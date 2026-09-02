//! 各链「签名 + 组装完整可广播交易」的分派层。
//!
//! # 文件布局：一条链一个文件
//!
//! 本模块只放**跨链共用的东西**（结果类型 `SignedResult` 与按链分派的 [`sign`]），
//! 各链的实现分别在同目录下的独立文件里：
//!
//! | 文件 | 链 | 序列化 | `signed_tx` 编码 |
//! |---|---|---|---|
//! | `eth.rs`  | eth  | RLP    | hex |
//! | `btc.rs`  | btc  | bitcoin 字节格式 | —（只出签名） |
//! | `sol.rs`  | sol  | bincode| base64 |
//! | `near.rs` | near | Borsh  | hex |
//! | `apt.rs`  | apt  | BCS    | hex |
//! | `sui.rs`  | sui  | BCS    | base64 |
//! | `ton.rs`  | ton  | —（仅签名）| — |
//! | `icp.rs`  | icp  | —（仅签名）| — |
//!
//! 分文件的理由：每条链都拖着一大堆只在自己身上成立的 `use` 与编码约定，
//! 挤在一起时改一条链容易误伤另一条；分开后依赖关系一眼可见，
//! 也便于按链增删（接 BTC 就是新增一个 `btc.rs` + 分派表里加一行）。
//!
//! # 统一的输入契约（先讲清楚「收到的是什么」）
//!
//! `txdatahex` 恒为**完整交易序列化后的 hex 字符串**（可带 `0x` 前缀）。
//!
//! **为什么各链函数收的是 `&str` 而不是 `&[u8]`**：HTTP 请求体里的字段就叫
//! `txdatahex`，是个字符串。让每个 `sign_xxx` 直接收字符串、自己解码，
//! 它就能在解码失败时给出**这条链特有的**错误信息——BTC 会说
//! 「需序列化的未签名交易」，而不是一句对所有链都成立的「需 hex」。
//! 若在分派层统一解码后再往下传字节，这份信息就丢了。
//! 剥 `0x` 前缀与 `hex::decode` 的重复由 [`decode_txdata`] 承担，各链只补自己的那句话。
//!
//! 这里「完整」的含义必须讲准：这份字节是**结构完整、只差签名**的那笔交易——
//! nonce / gas / fee / 接收方 / 金额 / 指令等字段**都已填好并参与了序列化**，
//! 由调用方（实际就是 allchain SDK 的 `build_transfer`）产出。
//!
//! 两个容易搞错、必须排掉的误解：
//!
//! - **不是「单独一个待签哈希」**。收到的是交易本体，不是 `sha256(tx)` 之类的摘要。
//!   内部要不要先哈希，是各链自己的事（见各链文件说明），与输入形态无关。
//! - **不是「部分字段」**。本模块不拼字段、不补 nonce、不算 fee——交易必须是完整的，
//!   这里只做「签名 + 把签名装配回去」这两件事。
//!
//! # 唯一的例外：BTC 需要额外的 `context`
//!
//! BTC 是 UTXO 模型，每个输入各有一个 sighash；而 P2WPKH 的 sighash 走 BIP143，
//! 需要**该输入的金额**，金额却不在交易字节里。所以 BTC 除 `txdatahex` 之外，
//! 还要把 SDK `build_transfer` 下发的 `extra.submit_context` 原样传进来。
//! 详见 `btc.rs` 的模块文档。
//!
//! # `signtx` 的语义
//!
//! 本模块用内存里 `fromaddress` 对应的种子重建签名器，对这笔完整交易签名，
//! 再把签名装配回交易，返回 `{signature, signed_tx}`。
//! `signed_tx` 是该链可直接广播的编码。
//!
//! 各链「完整交易」的序列化格式（细节见对应文件）：
//! - eth ：RLP 编码的交易（typed / legacy 均可），对应 MetaMask 离线签名输入。
//! - sol ：bincode 编码的 `solana_transaction::Transaction`（`signatures[0]` 为占位空签名）。
//! - near：Borsh 编码的 `near_primitives::transaction::Transaction`。
//! - apt ：BCS 编码的 `aptos_sdk::transaction::types::RawTransaction`。
//! - sui ：BCS 编码的 `sui_sdk_types::Transaction`。
//! - ton ：external message 的完整序列化字节（本服务只出签名，不组装 message）。
//!   通用签名器只出 ed25519 签名，完整 external message 组装需钱包 code + state-init。
//! - icp ：ingress message / envelope 的完整序列化字节（本服务只出签名，不组装信封）。
//!   地址（self-authenticating principal）由公钥派生，见 `keys.rs`；完整请求组装需
//!   caller principal、method、arg，由调用方负责。

mod apt;
mod btc;
mod eth;
mod icp;
mod near;
mod sol;
mod sui;
mod ton;

use serde_json::Value;

// 复用 SDK core 的错误码/载体：让 sign 的 HTTP 响应与 SDK 的 `Envelope`
// 错误码体系一致（INVALID_ARGUMENT → 400、UNSUPPORTED → 501、INTERNAL → 500）。
use allchain_core::{ErrorCode, SdkError};

use crate::store::StoredKey;

/// 一次签名 + 组装的结果。
///
/// # 为什么可以 `derive(Debug)`
///
/// 这个结构体里只有签名、编码标签和说明文字，**没有任何密钥材料**，直接放进
/// `{:?}` 是安全的。对比 `store.rs` 里的 `Vault`：它持有 seed，必须手写 `Debug`
/// 把种子打码——那里一旦误用 `derive`，一行 `println!("{:?}", vault)` 就会把私钥
/// 泄进日志。判据不是「结构体有多大」，而是「里面有没有不能外泄的字节」。
#[derive(Debug)]
pub struct SignedResult {
    /// 原始签名（统一 `0x` + hex）。多签名链（BTC）取**第一个**。
    pub signature: String,
    /// 本次产出的**全部**签名，顺序与各链定义一致（BTC 为「按输入下标」）。
    ///
    /// 单签名链只有一项，与 `signature` 相同；保留两个字段是为了让调用方
    /// 既能统一遍历 `signatures`，又不必为单签名场景再多解一层。
    pub signatures: Vec<String>,
    /// 装配好的可广播交易；TON 与 BTC 为 `None`（见各链文件说明）。
    pub signed_tx: Option<String>,
    /// `signed_tx` 的编码：`"hex"` 或 `"base64"`。
    pub encoding: String,
    /// 附加说明（如 TON 的组装限制）。
    pub note: Option<String>,
}

/// 把 `0x` / `0X` 前缀剥掉（无前缀原样返回）。
///
/// # 语法要点
///
/// `or_else(闭包)` 是**惰性**的：已有 `0x` 时就不再试 `0X`，省一次比较。
/// 返回 `&str` 而不是 `String`——切片不拷贝，调用方只是想看一眼剩下的部分。
pub(crate) fn strip_0x(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        rest
    } else {
        s
    }
}

/// 把 `txdatahex` 解成字节。
///
/// # 参数 `what`
///
/// 「这段字节应该是什么」的人话描述，会进错误信息，例如 `"序列化的未签名交易"`。
/// 各链传自己的描述，解码失败时调用方看到的就不是一句放之四海皆准的「需 hex」，
/// 而是「BTC 交易解码失败（需序列化的未签名交易）」——能直接指引人去对
/// `build_transfer` 的产物。
///
/// # 语法要点
///
/// `trim()` 先去掉首尾空白：调用方常把 hex 嵌在多行 JSON 或 shell 变量里，
/// 带一个换行是很常见的。剥前缀**放在** trim 之后，否则 `" 0xab"` 会先剥失败。
pub(crate) fn decode_txdata(txdatahex: &str, what: &str) -> anyhow::Result<Vec<u8>> {
    let body = strip_0x(txdatahex.trim());
    hex::decode(body).map_err(|e| {
        anyhow::anyhow!(
            "{what} 的 hex 解码失败（需 hex 字符串，可带 0x 前缀，收到 {} 个字符）: {e}",
            body.len()
        )
    })
}

/// 入口：按链分派到具体实现。
///
/// # 参数 `txdatahex`
///
/// **hex 字符串**，不是字节。解码由各链自己完成（见模块头的说明），
/// 这样每条链都能给出自己的解码错误信息。
///
/// # 参数 `context`
///
/// 只有 **BTC** 需要它（BIP143 sighash 要输入金额，而金额不在交易字节里）。
/// 其余链传 `Some` 会被直接拒绝——**不静默忽略**：调用方以为传了上下文会有某种效果，
/// 而实际上它没参与计算，这种「看起来生效了」的错觉比报错更难排查。
///
/// # 语法要点
///
/// 这里各分支的调用形式不同：ETH 是 `async`，要 `.await`，其余是同步函数直接返回。
/// 同一个 `match` 的每个分支都产出 `anyhow::Result<SignedResult>`，类型一致，可以混写。
///
/// 另外注意分支里写的是 `eth::sign_eth(..)` 而不是 `sign_eth(..)`：
/// 子模块里的函数要先经过模块路径才能访问，就像 `std::fs::read` 那样。
pub async fn sign(
    chain: &str,
    txdatahex: &str,
    context: Option<&Value>,
    key: &StoredKey,
) -> Result<SignedResult, SdkError> {
    // BTC 单独走一条路：它是唯一需要上下文的链，也是唯一产出多个签名的链。
    // 与下面那个 `match` 分开写，是为了让「需要上下文」这件事只有一个判断点。
    if chain == "btc" {
        // `context` 缺失是调用方参数错：直接给 INVALID_ARGUMENT，别落到底层 anyhow。
        let ctx = match context {
            Some(c) => c,
            None => {
                return Err(SdkError::invalid_argument(
                    "BTC 签名必须传 context（build_transfer 下发的 extra.submit_context）：\
                     BIP143 的 sighash 需要每个输入的金额，而金额不在交易字节里",
                ))
            }
        };
        // 各链函数仍返回 `anyhow::Result`；在边界上用 sign 专属分类器把报错
        // 归到正确的错误码，而不是让 `?` 走 SDK 的 RPC 分类器（会把参数错判成 RpcError）。
        return btc::sign_btc(txdatahex, ctx, key).map_err(|e| sign_classify(&e.to_string()));
    }
    if context.is_some() {
        return Err(SdkError::invalid_argument(format!(
            "{chain} 不接受 context：只有 btc 需要它"
        )));
    }

    // 其余链都不需要 context。每个分支产出 `anyhow::Result<SignedResult>`，
    // 在 `match` 出口统一分类——这样 10 个链文件一个都不用动。
    match chain {
        "eth" => eth::sign_eth(txdatahex, key).await,
        "sol" => sol::sign_sol(txdatahex, key),
        "near" => near::sign_near(txdatahex, key),
        "apt" => apt::sign_apt(txdatahex, key),
        "sui" => sui::sign_sui(txdatahex, key),
        "ton" => ton::sign_ton(txdatahex, key),
        "icp" => icp::sign_icp(txdatahex, key),
        other => Err(anyhow::anyhow!(
            "不支持的链: {other}（可选 eth / btc / sol / near / apt / sui / ton / icp）"
        )),
    }
    .map_err(|e| sign_classify(&e.to_string()))
}

/// 把 sign 层产生的报错归到正确的 [`ErrorCode`]。
///
/// 为什么不在各链函数里就地标 code：那样要改 10 个文件、约 50 处错误点；
/// 而这里的报错文案**全是本 crate 自己写的**，关键词稳定可控，所以在分派边界
/// 用一份关键词表统一分类，改动极小、且不会随某条链新增错误而漏标。
///
/// 为什么不直接复用 SDK 的 `classify`：那张表是给「节点 RPC 返回」设计的，
/// 会把「公钥不一致」「不是同一笔交易」这类参数错判成 `RpcError`（可重试），
/// 而重试对参数错毫无意义。sign 的报错语义不同，需要自己的表。
fn sign_classify(msg: &str) -> SdkError {
    let lower = msg.to_ascii_lowercase();
    let code = if contains_any(&lower, &["不支持的链"]) {
        // 能力未接入，对应 HTTP 501；属于调用方选了不支持的链。
        ErrorCode::Unsupported
    } else if contains_any(
        &lower,
        &[
            "非法", "不一致", "不是同一笔交易", "不是合法", "十六进制", "解码失败",
            "解不出", "解析失败", "格式", "缺少第", "一一对应", "签名元数据",
            "必须传 context", "不接受 context", "公钥", "只支持", "种子不是合法", "脚本类型",
        ],
    ) {
        // 上述都指向「调用方传进来的参数/上下文有问题」→ 400。
        ErrorCode::InvalidArgument
    } else {
        // 兜底：keystore 损坏、意外 crypto 失败等真正的内部错误 → 500。
        ErrorCode::Internal
    };
    SdkError::new(code, msg)
}

/// 私有辅助：判断 `haystack` 是否含 `needles` 中任意一个（短路）。
fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Scheme;
    use serde_json::json;

    // 复用 eth.rs 里那条**真实主网向量**：它是唯一一条「只有 sign_eth 能消化」的输入，
    // 因此能把 `eth` 的路由与其它六条链区分开（详见下面第一条测试的说明）。
    use crate::sign::eth::SDK_UNSIGNED_TX_HEX;

    fn secp256k1_key() -> StoredKey {
        StoredKey { scheme: Scheme::Secp256k1, seed: [1u8; 32] }
    }

    fn ed25519_key() -> StoredKey {
        StoredKey { scheme: Scheme::Ed25519, seed: [6u8; 32] }
    }

    /// **`eth` 必须被路由到 `sign_eth`**，而不是某条 ed25519 链。
    ///
    /// # 这条测试在防什么
    ///
    /// 分派表是七行 `match`，写错一行（比如把 `"sol"` 接到 `near::sign_near`）
    /// 在类型上完全合法——两边都是 `anyhow::Result<SignedResult>`，编译器不会吭声。
    /// 而各链自己的测试都是**直接调** `sign_near` / `sign_sol` 的，
    /// 于是分派表错位在本地是全绿的，只有真实调用方会拿到一条解不开的错误。
    /// 这和 APT / NEAR 那两个缺陷是同一类：**没人测过「连线」本身**。
    ///
    /// # 为什么这个判据能证伪
    ///
    /// ETH 的签名是 **65 字节可恢复签名**（`r ‖ s ‖ v`），hex 后是 130 个字符；
    /// 其余六条链里有五条是 ed25519，签名恒为 64 字节 = 128 个字符。
    /// 所以「130 位」这个数字本身就排除了「被路由到任一 ed25519 链」——
    /// 若真路由错了，要么解码直接失败，要么产出 128 位。
    #[tokio::test]
    async fn eth_is_routed_to_the_secp256k1_path() {
        let out = sign("eth", SDK_UNSIGNED_TX_HEX, None, &secp256k1_key())
            .await
            .expect("真实向量走 eth 路由必须成功");

        assert_eq!(
            out.signature.len(),
            2 + 130,
            "ETH 应产出 65 字节可恢复签名（`0x` + 130 hex）；\
             128 位说明被误路由到了某条 ed25519 链，实际: {}",
            out.signature
        );
        // 再钉一次产出形态：裸 EIP-2718（详见 eth.rs 的说明）。
        let raw = out.signed_tx.expect("eth 应产出 signed_tx");
        assert!(
            raw.starts_with("0x02"),
            "分派到 eth 后产出的应是 EIP-1559 信封，实际: {raw}"
        );
    }

    /// **`ton` 必须被路由到「只出签名」那条路**。
    ///
    /// TON 是七条链里唯一「来者不拒」的：它不解析字节结构，对任何输入都签名。
    /// 这个特性正好用来证伪——若 `"ton"` 被接到任何别的链上，
    /// 两个任意字节是解不开的，会直接报错。
    #[tokio::test]
    async fn ton_is_routed_to_the_signature_only_path() {
        // `0x00ff` 不是一个合法交易，但 TON 不解析结构，照签不误。
        let out = sign("ton", "0x00ff", None, &ed25519_key())
            .await
            .expect("ton 对任意字节都应签名成功");

        assert!(
            out.signed_tx.is_none(),
            "ton 只出签名、不组装交易；出现 signed_tx 说明被路由到了别的链"
        );
        let note = out.note.expect("ton 应带说明");
        assert!(note.contains("钱包"), "说明应点明原因，实际: {note}");
        // ed25519 签名 = 64 字节 = 128 hex，与上面的 ETH 判据互为对照。
        assert_eq!(out.signature.len(), 2 + 128, "ton 应是 64 字节签名");
    }

    /// 其余各链**必须拒绝**任意字节——用来防止它们被误接到 `ton` 上。
    ///
    /// 反证的那一半：若 `"sol"` 被接到 `ton::sign_ton`，下面这条会由红转绿吗？
    /// 不会——它会**失败**（`expect` 通过变成 `is_err()` 不成立），正是我们要的。
    #[tokio::test]
    async fn the_structuring_chains_reject_arbitrary_bytes() {
        for chain in ["sol", "near", "apt", "sui"] {
            let err = sign(chain, "0x00ff", None, &ed25519_key())
                .await
                .expect_err("{chain} 不应接受两个任意字节");
            assert!(
                !err.to_string().is_empty(),
                "{chain} 的报错应带原因，便于调用方定位"
            );
        }
    }

    /// **`icp` 必须被路由到「只出签名」那条路**（与 `ton` 同类）。
    ///
    /// ICP 也是「来者不拒」的链：它不解析字节结构，对任何输入都签名。
    /// 这个特性正好用来证伪——若 `"icp"` 被接到任何别的链上，
    /// 两个任意字节是解不开的，会直接报错。
    #[tokio::test]
    async fn icp_is_routed_to_the_signature_only_path() {
        // `0x00ff` 不是一个合法 IC 消息，但 ICP 不解析结构，照签不误。
        let out = sign("icp", "0x00ff", None, &ed25519_key())
            .await
            .expect("icp 对任意字节都应签名成功");

        assert!(
            out.signed_tx.is_none(),
            "icp 只出签名、不组装信封；出现 signed_tx 说明被路由到了别的链"
        );
        let note = out.note.expect("icp 应带说明");
        assert!(note.contains("不组装"), "说明应点明原因，实际: {note}");
        // ed25519 签名 = 64 字节 = 128 hex，与上面的 TON 判据互为对照。
        assert_eq!(out.signature.len(), 2 + 128, "icp 应是 64 字节签名");
    }

    /// BTC 缺 `context` 必须报错，且错误信息要说清**为什么**需要它。
    ///
    /// 这条错误信息是给调用方看的：它要能让人直接去 `build_transfer` 的响应里
    /// 找 `extra.submit_context`，而不是对着「缺少参数」发呆。
    #[tokio::test]
    async fn btc_requires_a_context() {
        let err = sign("btc", "0x00", None, &secp256k1_key())
            .await
            .expect_err("btc 不传 context 必须被拒");
        let msg = err.to_string();
        assert!(msg.contains("context"), "应点名缺的是 context，实际: {msg}");
        assert!(
            msg.contains("金额"),
            "应说清为什么要 context（BIP143 sighash 需要输入金额），实际: {msg}"
        );
    }

    /// 非 BTC 链传了 `context` 必须被拒——**不静默忽略**。
    ///
    /// 静默忽略的坏处：调用方以为传了上下文会有某种效果，
    /// 实际上它没参与任何计算。这种「看起来生效了」的错觉比直接报错难排查得多。
    #[tokio::test]
    async fn non_btc_chains_reject_a_context() {
        let ctx = json!({ "network": "mainnet" });
        let err = sign("sol", "0x00", Some(&ctx), &ed25519_key())
            .await
            .expect_err("非 btc 链不接受 context");
        let msg = err.to_string();
        assert!(msg.contains("只有 btc"), "应点明只有 btc 需要它，实际: {msg}");
    }

    /// 未知链必须报错，且把可选项列全——调用方照着改就行。
    #[tokio::test]
    async fn an_unknown_chain_is_rejected() {
        let err = sign("ckb", "0x00", None, &secp256k1_key())
            .await
            .expect_err("未接入的链必须被拒");
        let msg = err.to_string();
        assert!(msg.contains("不支持的链"), "实际: {msg}");
        for c in ["eth", "btc", "sol", "near", "apt", "sui", "ton", "icp"] {
            assert!(msg.contains(c), "错误信息应列出可选链 {c}，实际: {msg}");
        }
    }

    /// **错误码**必须是 `Unsupported`（HTTP 501），而不是被一刀切成 `INTERNAL`。
    ///
    /// 只断言 message 不够——message 里本来就含「不支持的链」，但 HTTP 状态码
    /// 取决于 `code`。这条把「未知链 → UNSUPPORTED」这个分类契约钉死，
    /// 免得有人把 `sign::sign` 的兜底分类改回全 INTERNAL。
    #[tokio::test]
    async fn an_unknown_chain_is_rejected_with_the_unsupported_code() {
        let err = sign("ckb", "0x00", None, &secp256k1_key())
            .await
            .expect_err("未接入的链必须被拒");
        assert_eq!(
            err.code,
            ErrorCode::Unsupported,
            "未知链应 UNSUPPORTED，实际: {}",
            err.code.as_str()
        );
    }

    /// **错误码**必须是 `InvalidArgument`（HTTP 400），而不是 `INTERNAL`。
    ///
    /// 这正是这次修复要解决的事故：调用方参数错（缺 context / 多传 context）
    /// 之前全被标成 INTERNAL（500），调用方分不清「自己参数错了」还是
    /// 「签名器内部挂了」。两条都覆盖，证明分类器对 BTC / 非 BTC 都生效。
    #[tokio::test]
    async fn caller_parameter_errors_are_invalid_argument() {
        // BTC 缺 context：参数错。
        let err = sign("btc", "0x00", None, &secp256k1_key())
            .await
            .expect_err("btc 不传 context 必须被拒");
        assert_eq!(
            err.code,
            ErrorCode::InvalidArgument,
            "缺 context 应 INVALID_ARGUMENT，实际: {}",
            err.code.as_str()
        );

        // 非 BTC 链多传了 context：参数错。
        let ctx = json!({ "network": "mainnet" });
        let err = sign("sol", "0x00", Some(&ctx), &ed25519_key())
            .await
            .expect_err("非 btc 链不接受 context");
        assert_eq!(
            err.code,
            ErrorCode::InvalidArgument,
            "多传 context 应 INVALID_ARGUMENT，实际: {}",
            err.code.as_str()
        );
    }

    /// `strip_0x` 的三种输入形态：两种拼写的前缀 + 没有前缀。
    ///
    /// # 为什么连 `0X` 都要测
    ///
    /// 大写 `0X` 是合法的 hex 前缀写法（Solidity / Go 里都常见），
    /// 调用方从别处拷贝过来的字符串完全可能带它。只认小写会让这类输入
    /// 在 `hex::decode` 那里报一句「Invalid character 'X'」——
    /// 信息指向错误的位置，排查方向就跑偏了。
    #[test]
    fn strip_0x_handles_both_spellings_and_absence() {
        assert_eq!(strip_0x("0xab"), "ab");
        assert_eq!(strip_0x("0Xab"), "ab", "大写 0X 前缀也要认");
        assert_eq!(strip_0x("ab"), "ab", "无前缀应原样返回");
        // 只剥一层：`0x0xab` 是调用方写错了，这里不该无限剥下去把错误吞掉。
        assert_eq!(strip_0x("0x0xab"), "0xab");
        assert_eq!(strip_0x(""), "");
    }

    /// `decode_txdata` 的报错必须带上调用方传入的那句「这段字节本该是什么」。
    ///
    /// 这是当初把入参从 `&[u8]` 改成 `&str` 的**唯一理由**：
    /// 解码放在各链内部，各链才能给出自己的那句描述。
    /// 若哪天有人把解码收回分派层、统一成一句「需 hex」，这条会红。
    #[test]
    fn decode_txdata_names_the_expected_shape_in_its_error() {
        let err = decode_txdata("0xZZZZ", "SOL 完整交易（bincode Transaction）")
            .expect_err("非 hex 必须被拒");
        let msg = err.to_string();
        assert!(msg.contains("SOL 完整交易"), "报错应带上链的形状描述，实际: {msg}");
        assert!(msg.contains("hex"), "应说明需要的是 hex，实际: {msg}");
        assert!(
            msg.contains('4'),
            "应报出收到的字符数（此处 4 个），便于调用方自查，实际: {msg}"
        );
    }

    /// 三种被接受的写法必须等价：带 `0x`、带 `0X`、带首尾空白。
    #[test]
    fn decode_txdata_accepts_every_spelling_that_callers_actually_send() {
        let plain = decode_txdata("0011ff", "测试").expect("无前缀");
        assert_eq!(plain, vec![0x00, 0x11, 0xff]);

        for spelled in ["0x0011ff", "0X0011ff", "  0x0011ff  ", "0x0011ff\n"] {
            let got = decode_txdata(spelled, "测试")
                .unwrap_or_else(|e| panic!("{spelled:?} 应被接受，实际报错: {e}"));
            assert_eq!(got, plain, "{spelled:?} 应与无前缀写法等价");
        }

        // 前缀剥在 trim **之后**：`" 0xab"` 若先剥前缀会失败（前面有空格）。
        // 这条断言把「顺序即正确性」钉住——两个操作交换一下就会红。
        assert!(decode_txdata(" 0x0011ff", "测试").is_ok());
    }

    /// 奇数长度必须被拒，而不是被 `hex::decode` 之后静默截断。
    #[test]
    fn an_odd_length_hex_string_is_rejected() {
        let err = decode_txdata("0xabc", "测试").expect_err("奇数长度 hex 非法");
        assert!(!err.to_string().is_empty());
    }
}
