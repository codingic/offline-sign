//! sign：本地离线签名服务。
//!
//! 仅监听回环地址（`127.0.0.1`），**无任何鉴权**——本服务只应在本机被信任的程序调用。
//!
//! 端点（与 acli 的统一信封结构一致）：
//! - `POST /v1/signtx`  body `{chaintype, txdatahex, fromaddress[, context]}`
//!   用 `fromaddress` 对应的私钥签名并组装可广播交易。
//! - `GET  /v1/chains`                       列出支持的链、所用曲线、公钥与本 keystore 的地址。
//! - `GET  /v1/keystore`                     列出 keystore 目录与两个文件的状态。
//!
//! ## `context` 字段：只有 BTC 需要
//!
//! BTC 是 UTXO 模型，每个输入各有一个 sighash；而 P2WPKH 的 sighash 走 BIP143，
//! 需要**该输入的金额**——金额不在交易字节里。所以 BTC 要把 SDK `build_transfer`
//! 下发的 `extra.submit_context` 原样放进 `context`。其余链传了会被拒绝（不静默忽略）。
//!
//! # 启动流程：先解锁，再监听
//!
//! 服务启动时先在终端问口令，用 Argon2id 解开 `~/.allchain-sign` 下的两个加密 keystore
//! 文件（secp256k1 / ed25519 各一），把两条私钥读进内存，然后才开端口。
//!
//! 顺序不能颠倒：先监听后解锁的话，中间那段窗口里 `signtx` 会以一个「没有密钥」的状态
//! 对外提供服务，调用方拿到的是「地址不存在」这种误导性错误，而不是「还没解锁」。
//!
//! # 安全模型
//!
//! - **磁盘**：只有加密文件（AES-256-GCM），私钥从不以明文落盘；
//! - **内存**：私钥常驻（服务就是靠它签名的），`Vault` 在 drop 时清零；
//! - **口令**：只用于启动时派生密钥，用完即弃，绝不写日志；
//! - **无法找回**：没有后门、没有助记词，口令忘了就是永久失去这两个私钥。

mod keys;
mod password;
mod sign;
mod store;
mod timing;
mod vault;

use std::path::PathBuf;
use std::sync::Arc;

// `Timer` 来自 `timing` 模块：handler 用它记录请求耗时，填进 `Envelope.took_ms`，
// `main.rs` 本身不再直接碰 `std::time::Instant`。
use crate::timing::Timer;

use axum::{
    Router,
    extract::{Json as JsonExtractor, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};

use allchain_core::{Envelope, ErrorCode, SdkError};
use store::{KeyStore, Scheme};
use vault::Vault;

/// 口令输错时的重试上限。
///
/// 给 3 次而不是无限重试：无限重试等于给本机任意进程一个「拿 keystore 文件试口令」的
/// 无限机会机；3 次足够覆盖真人的手指失误，又让自动暴破没有意义。
const MAX_PASSWORD_ATTEMPTS: usize = 3;

/// 进程内共享状态：内存密钥库 + 解锁后的两个私钥。
///
/// `Vault` 用 `Arc` 而非直接 `Clone`：它里面是**私钥**。实现 `Clone` 会让副本散落到
/// 每个请求的 handler 里，既增加暴露面也说不清「到底有几份」；
/// `Arc` 则明确表达「全进程只有一份，大家都只是借用」。
#[derive(Clone)]
struct AppState {
    store: KeyStore,
    vault: Arc<Vault>,
    /// keystore 目录。**必须存在状态里**：`/v1/keystore` 要如实报告路径，
    /// 若那里改用 `vault::default_dir()`，用户传了 `--keystore-dir` 时就会报出
    /// 一个「文件不存在」的错误路径，把人引去查根本没用到的目录。
    dir: Arc<std::path::PathBuf>,
}

/// CLI 参数。
#[derive(Parser)]
#[command(name = "sign", about = "本地离线签名服务：口令解锁 keystore + signtx")]
struct Cli {
    /// 监听地址；默认回环，不对外暴露（本服务无鉴权）。
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 7878)]
    port: u16,
    /// keystore 目录；默认 `~/.allchain-sign`。
    ///
    /// 建议保持默认：指定别处很容易在换目录启动时生成第二套密钥，
    /// 表现为「我明明有地址，怎么余额是 0」——因为那是另一把钥匙的另一套地址。
    #[arg(long)]
    keystore_dir: Option<PathBuf>,
}

/// `POST /v1/signtx` 请求体。
#[derive(Debug, Deserialize)]
struct SignBody {
    chaintype: String,
    /// **完整交易**序列化后的字节（hex，可带 0x 前缀）；各链格式见 `sign` 模块文档。
    ///
    /// 「完整」= 结构完整、只差签名：nonce / gas / fee / 接收方 / 金额 等字段都已填好，
    /// 由调用方（实际是 allchain SDK 的 `build_transfer`）产出。
    /// 本服务**不**接收单独的待签哈希，也不自己拼字段。
    txdatahex: String,
    /// 由 `/v1/chains` 给出的地址（签名所用私钥在内存中按此地址索引）。
    fromaddress: String,
    /// **仅 BTC 需要**：SDK `build_transfer` 下发的 `extra.submit_context`，原样回传。
    ///
    /// 为什么 BTC 非要它不可：P2WPKH 的 sighash 走 BIP143，
    /// 要把「这个输入值多少 satoshi」也混进哈希，而金额**不在交易字节里**。
    /// 少了它就算不出正确的 sighash——算出来的会是另一个值，
    /// 签名照样合法，只是签在了别的交易上，而这类错误在广播前毫无提示。
    context: Option<Value>,
}

/// 启动：先解锁 keystore，再起 HTTP 服务。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let dir = cli.keystore_dir.clone().unwrap_or_else(vault::default_dir);

    let state = unlock(&dir)?;

    // 预热：把所有链的地址先算出来塞进内存密钥库。
    // 好处是 `signtx` 只查一次 HashMap，且启动日志能一次列出全部地址。
    eprintln!();
    eprintln!("本 keystore 在各链上的地址：");
    populate(&state);

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/v1/chains", get(chains_handler))
        .route("/v1/keystore", get(keystore_handler))
        .route("/v1/signtx", post(signtx_handler))
        .with_state(state);

    let addr = format!("{}:{}", cli.host, cli.port);
    eprintln!();
    eprintln!("sign offline-signer listening on http://{addr}  (loopback only, no auth)");
    eprintln!("  POST /v1/signtx  body: {{chaintype, txdatahex, fromaddress[, context]}}");
    eprintln!("  GET  /v1/chains");
    eprintln!("  GET  /v1/keystore");
    eprintln!();

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// 解锁（或在首次运行时创建）keystore，返回共享状态。
///
/// 三种目录状态对应三种口令策略：
/// - `Empty`   → 要新口令，且要求二次确认（口令无法找回，防手滑）；
/// - `Partial` → 要原口令，解开已有的、补上缺的；
/// - `Complete`→ 要原口令，错了给最多 3 次重试。
fn unlock(dir: &std::path::Path) -> anyhow::Result<AppState> {
    use vault::DirState;

    let dir_state = vault::state(dir);
    std::fs::create_dir_all(dir)?;

    match dir_state {
        DirState::Empty => {
            eprintln!("首次运行：将在 {} 创建两个加密 keystore 文件。", dir.display());
            eprintln!("  - keystore-secp256k1.json   (eth / btc)");
            eprintln!("  - keystore-ed25519.json     (sol / near / apt / sui / ton / icp)");
            eprintln!();
            eprintln!("口令用于加密这两个文件，**无法找回**——丢失即永久失去私钥。");
            eprintln!();
        }
        // 只找到一个文件时必须**先警告再动手**：补齐的那条是一把全新私钥，
        // 与用户此前（可能已经收过款）的地址毫无关系。
        // 等事后才发现，钱已经打到一个没人控制的地址里了。
        DirState::Partial => {
            eprintln!("keystore 目录: {}", dir.display());
            eprintln!();
            eprintln!("⚠️  只找到一个 keystore 文件，缺失的那个将被新建。");
            eprintln!("   新建的是一把全新私钥，与以往任何一次启动的地址都不同。");
            eprintln!("   若这属于误删：现在中止，先从备份恢复文件再启动。");
            eprintln!();
        }
        // 两个都在：正常复用，不重建。
        DirState::Complete => {
            eprintln!("keystore 目录: {}", dir.display());
        }
    }

    // 三个分支都返回 `(vault, reports, 口令来源)`：来源要打进日志，
    // 因为它决定了运维该去哪儿找口令（终端 vs 环境变量），缺了这条排查会绕远路。
    let (vault, reports, source) = match dir_state {
        // 全新：问新口令，只问一次（失败就是参数问题，不是口令问题）。
        DirState::Empty => {
            let pw = password::prompt_new()?;
            let (v, r) = vault::open_or_fill(dir, std::str::from_utf8(pw.as_bytes())?)?;
            (v, r, pw.source())
        }
        // 已有文件：问原口令，口令错就重试（其他错误不重试）。
        DirState::Partial | DirState::Complete => {
            let mut attempt = 0usize;
            loop {
                let pw = password::prompt_existing()?;
                let source = pw.source();
                match vault::open_or_fill(dir, std::str::from_utf8(pw.as_bytes())?) {
                    Ok((v, r)) => break (v, r, source),
                    Err(e) if e.is_wrong_password() && attempt + 1 < MAX_PASSWORD_ATTEMPTS => {
                        attempt += 1;
                        eprintln!(
                            "  口令错误（第 {attempt}/{MAX_PASSWORD_ATTEMPTS} 次，还剩 {} 次）",
                            MAX_PASSWORD_ATTEMPTS - attempt
                        );
                        continue;
                    }
                    // `Corrupt` 与 IO 错误重试一万次也一样，直接抛给用户。
                    Err(e) => return Err(e.into()),
                }
            }
        }
    };
    print_unlock_report(&reports, source);

    Ok(AppState {
        store: KeyStore::new(),
        vault: Arc::new(vault),
        dir: Arc::new(dir.to_path_buf()),
    })
}

/// 把解锁结果打到启动日志（只说「新建/已解开」，绝不说私钥）。
fn print_unlock_report(reports: &[vault::Report], source: password::Source) {
    // 两个分支都要是 `String`：`&'static str` 与 `String` 混在一个 match 里会
    // 因类型不一致而编译失败，统一转成 `String` 最省事。
    let from: String = match source {
        password::Source::Tty => "终端输入".to_string(),
        password::Source::Env => format!("环境变量 {}", password::ENV_PASSWORD),
    };
    eprintln!("口令来源: {from}");
    for r in reports {
        let verb = if r.created { "已创建" } else { "已解锁" };
        eprintln!("  {verb}: {} ({})", r.path.display(), r.scheme.as_str());
    }

    // 补一句总结。两个分支各自回答用户心里那个疑问：
    //   - 全复用 → 「我的地址还是不是上次那些？」（这是绝大多数次启动的情形）
    //   - 有新建 → 「哪个是新钥匙？」（新钥匙意味着对应几条链的地址与以往不同）
    // 「已解锁」只是中性陈述，回答不了这两个问题。
    let created = reports.iter().filter(|r| r.created).count();
    match created {
        0 => eprintln!("  复用已有私钥，未重新生成：各链地址与上次启动一致。"),
        n => eprintln!(
            "  新建 {n} 个 / 复用 {} 个：新建的那条是全新私钥，\
             它对应链上的地址与以往任何一次启动都不同。",
            reports.len() - n
        ),
    }
}

/// 预热内存密钥库：为每条链派生地址并登记，顺带打到启动日志。
///
/// 逐条 `match` 而非整体 `?`：某条链派生失败只应让它自己不可用，
/// 不该拖垮整个服务——keystore 里的两条种子是好的，别的链照用。
fn populate(state: &AppState) {
    for chain in keys::CHAINS {
        let Some(scheme) = keys::scheme_for(chain) else {
            continue;
        };
        let seed = state.vault.seed_for(scheme);
        match keys::derive(chain, seed) {
            Ok(info) => {
                eprintln!("  {:<5} {}", chain, info.address);
                state.store.insert(&info.address, keys::to_stored(&info));
            }
            Err(e) => eprintln!("  {chain:<5} <派生失败: {e}>"),
        }
    }
}

/// 根路径：返回简短说明。
///
/// 走 `ok()` 而非直接 `Json(...)`：**所有**端点都必须包统一信封。
/// 之前这里返回裸 JSON，与 README 里「响应复用 `Envelope<T>`」的说法不一致，
/// 调用方得为不同端点写两套解析——这种不一致是最难发现的，因为每个端点单独看都对。
async fn root_handler() -> Response {
    ok(
        json!({
            "service": "sign offline-signer",
            "endpoints": ["POST /v1/signtx", "GET /v1/chains", "GET /v1/keystore"],
            "keys": "two persistent keys (secp256k1 + ed25519), encrypted at rest with a password",
            "warning": "loopback-only, no auth"
        }),
        &Timer::start(),
    )
}

/// `GET /v1/chains`：能力清单，并附上本 keystore 在各链上的**地址与公钥**。
async fn chains_handler(State(state): State<AppState>) -> Response {
    let timer = Timer::start();
    let chains: Vec<Value> = keys::CHAINS
        .iter()
        .filter_map(|c| {
            let scheme = keys::scheme_for(c)?;
            let seed = state.vault.seed_for(scheme);
            let info = keys::derive(c, seed).ok()?;
            Some(json!({
                "chain": c,
                "scheme": scheme.as_str(),
                "address": info.address,
                // BTC 的 `build_transfer` **必须**要公钥：P2WPKH 的见证里要显式携带它，
                // 而公钥无法从地址反推（地址是公钥的哈希）。
                // 这里给的是压缩公钥的十六进制，可直接原样传给 SDK。
                "public_key": info.public_key,
                "signed_tx_encoding": if *c == "sol" || *c == "sui" { "base64" } else { "hex" },
                // TON 与 BTC 与 ICP 都只出签名：TON 的完整 message 要钱包 code + state-init，
                // BTC 的交易要 submit_context + 签名数组，ICP 的 ingress 信封要 caller/method/arg——
                // 三者都由 SDK 组装。
                "assembles_full_tx": *c != "ton" && *c != "btc" && *c != "icp",
                // 调用方据此决定 `signtx` 要不要带 context，不必硬记「哪条链特殊」。
                "needs_context": *c == "btc",
            }))
        })
        .collect();
    ok(json!({ "chains": chains, "count": chains.len() }), &timer)
}

/// `GET /v1/keystore`：两个文件的路径与是否存在。
///
/// 只报**存在性**，不报任何内容、也不校验口令——它不会帮攻击者省掉 Argon2。
///
/// 不接 `State`：本端点只描述磁盘状态。能访问到它本身就说明服务已解锁
/// （端口是在解锁之后才开的）。
async fn keystore_handler(State(state): State<AppState>) -> Response {
    let timer = Timer::start();
    let dir = state.dir.as_path();
    let files: Vec<Value> = Scheme::ALL
        .iter()
        .map(|s| {
            let p = vault::path_for(dir, *s);
            json!({
                "scheme": s.as_str(),
                "path": p.display().to_string(),
                "exists": p.exists(),
            })
        })
        .collect();
    ok(
        json!({
            "dir": dir.display().to_string(),
            "files": files,
            "unlocked": true,
            "note": "口令无法找回；keystore 文件 + 口令 二者缺一即永久失去私钥"
        }),
        &timer,
    )
}

/// `POST /v1/signtx`：按地址取密钥，签名并组装交易。
async fn signtx_handler(
    State(state): State<AppState>,
    JsonExtractor(body): JsonExtractor<SignBody>,
) -> Response {
    let timer = Timer::start();
    if !keys::is_supported(&body.chaintype) {
        return err(
            ErrorCode::Unsupported,
            &format!(
                "不支持的链: {}（可选 eth / btc / sol / near / apt / sui / ton / icp）",
                body.chaintype
            ),
            &timer,
        );
    }
    // 注意这里**不做** hex 解码：各链函数收的就是 hex 字符串。
    // 解码失败时它们能说出「这段字节本该是什么」（例如 BTC 会说「需序列化的未签名交易」），
    // 比在这里统一解码后再往下传字节信息量大得多。
    let key = match state.store.get(&body.fromaddress) {
        Some(k) => k,
        None => {
            return err(
                ErrorCode::InvalidArgument,
                &format!(
                    "地址 {} 不属于本 keystore；请用 GET /v1/chains 查看本 keystore 在各链上的地址",
                    body.fromaddress
                ),
                &timer,
            )
        }
    };
    match sign::sign(&body.chaintype, &body.txdatahex, body.context.as_ref(), &key).await {
        Ok(r) => {
            let data = json!({
                "chain": body.chaintype,
                "from_address": body.fromaddress,
                "scheme": key.scheme.as_str(),
                "signature": r.signature,
                // 多签名链（BTC）的完整结果在这里；单签名链只有一项。
                "signatures": r.signatures,
                "signature_count": r.signatures.len(),
                "signed_tx": r.signed_tx,
                "encoding": r.encoding,
                "note": r.note,
            });
            ok(data, &timer)
        }
        // `sign::sign` 已经把错误归到了正确的 `ErrorCode`
        // （调用方参数错 → InvalidArgument / 400，能力不支持 → Unsupported / 501，
        // 真正的内部故障 → Internal / 500），这里直接透传，不再一刀切成 INTERNAL。
        Err(e) => err(e.code, &e.message, &timer),
    }
}

/// 成功信封 → (200, JSON)。
fn ok(data: Value, timer: &Timer) -> Response {
    let env: Envelope<Value> =
        Envelope::ok("sign", "offline", timer.elapsed_ms(), data);
    (StatusCode::OK, Json(env.to_value().unwrap_or(Value::Null))).into_response()
}

/// 失败信封 → (按错误码选状态码, JSON)。
fn err(code: ErrorCode, msg: &str, timer: &Timer) -> Response {
    let status = match code {
        ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::Unsupported => StatusCode::NOT_IMPLEMENTED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let env: Envelope<()> = Envelope::err(
        "sign",
        "offline",
        timer.elapsed_ms(),
        SdkError::new(code, msg.to_string()),
    );
    (status, Json(env.to_value().unwrap_or(Value::Null))).into_response()
}
