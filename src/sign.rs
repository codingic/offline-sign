//! 各链「签名 + 组装完整可广播交易」的分派层。
//!
//! # 文件布局：一条链一个文件
//!
//! 本模块只放**跨链共用的东西**（结果类型 `SignedResult` 与按链分派的 [`sign`]），
//! 各链的实现分别在同目录下的独立文件里：
//!
//! | 文件 | 链 | 序列化 | `signedtxdatahex` 编码 |
//! |---|---|---|---|
//! | `eth.rs`  | eth  | RLP    | hex |
//! | `btc.rs`  | btc  | bitcoin 字节格式 | 完整 segwit 交易 hex（带 witness） |
//! | `sol.rs`  | sol  | bincode| base64 |
//! | `near.rs` | near | Borsh  | hex |
//! | `apt.rs`  | apt  | BCS    | hex |
//! | `sui.rs`  | sui  | BCS    | base64 |
//! | `ton.rs`  | ton  | external message（签名前拼）| 完整 external message hex |
//! | `icp.rs`  | icp  | ingress message（签名前拼）| 签名前缀 hex（须包进 CBOR envelope）|
//!
//! 分文件的理由：每条链都拖着一大堆只在自己身上成立的 `use` 与编码约定，
//! 挤在一起时改一条链容易误伤另一条；分开后依赖关系一眼可见，
//! 也便于按链增删（接 BTC 就是新增一个 `btc.rs` + 分派表里加一行）。
//!
//! # 统一的输入契约（先讲清楚「收到的是什么」）
//!
//! `unsignedtxdatahex` 恒为**完整交易序列化后的 hex 字符串**（可带 `0x` 前缀）。
//!
//! **为什么各链函数收的是 `&str` 而不是 `&[u8]`**：HTTP 请求体里的字段就叫
//! `unsignedtxdatahex`，是个字符串。让每个 `sign_xxx` 直接收字符串、自己解码，
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
//! 需要**该输入的金额**，金额却不在交易字节里。所以 BTC 除 `unsignedtxdatahex` 之外，
//! 还要把 SDK `build_transfer` 下发的 `extra.submit_context` 原样传进来。
//! 详见 `btc.rs` 的模块文档。
//!
//! # `signtx` 的语义
//!
//! 本模块用内存里 `fromaddress` 对应的种子重建签名器，对这笔完整交易签名，
//! 再把签名装配回交易，返回 `{signature, signedtxdatahex}`。
//! `signedtxdatahex` 是该链可直接广播的编码。
//!
//! 各链「完整交易」的序列化格式（细节见对应文件）：
//! - eth ：RLP 编码的交易（typed / legacy 均可），对应 MetaMask 离线签名输入。
//! - sol ：bincode 编码的 `solana_transaction::Transaction`（`signatures[0]` 为占位空签名）。
//! - near：Borsh 编码的 `near_primitives::transaction::Transaction`。
//! - apt ：BCS 编码的 `aptos_sdk::transaction::types::RawTransaction`。
//! - sui ：BCS 编码的 `sui_sdk_types::Transaction`。
//! - ton ：external message 的完整序列化字节；本服务把 64 字节签名前拼到消息前，
//!   返回可直接广播的完整 external message（钱包 code + state-init 须由调用方提供）。
//! - icp ：ingress message / envelope 的完整序列化字节；本服务把 64 字节签名前拼到字节前，
//!   返回 `signedtxdatahex`（签名前缀字节）。IC 真正可广播的是 CBOR envelope，调用方须把
//!   此 `signature` 填进 `envelope.sender_sig` 后广播。地址（self-authenticating principal）
//!   由公钥派生，见 `keys.rs`。

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
    /// 装配好的可广播交易；TON 为完整 external message，ICP 为签名前缀字节（须包进 CBOR envelope，见各链文件说明）。
    pub signedtxdatahex: Option<String>,
    /// 该交易在链上的哈希（txid / tx hash）。
    ///
    /// 只有** BTC 与 ETH **能在这里算出：
    /// - BTC：`tx.compute_txid()`（double-SHA256 反序，即区块浏览器里看到的 txid）；
    /// - ETH：`keccak256(signedtxdatahex 字节)`（节点对 `eth_sendRawTransaction` 入参哈希即得）。
    ///
    /// 其余链在「只拿原始字节、不做链结构解析」的前提下**算不出**：
    /// NEAR 需要出块时的 block hash；TON / ICP 需要解析 cell / CBOR envelope；
    /// SOL / APT / SUI 的哈希依赖各自的链结构（SOL 的 txid 即签名本身，见各链 `note`）。
    /// 这些链统一返回 `None`，由调用方在拿到结构后再算或在广播后向节点查询。
    pub txhash: Option<String>,
    /// `signedtxdatahex` 的编码：`"hex"` 或 `"base64"`。
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

/// 把 `unsignedtxdatahex` 解成字节。
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
pub(crate) fn decode_txdata(unsignedtxdatahex: &str, what: &str) -> anyhow::Result<Vec<u8>> {
    let body = strip_0x(unsignedtxdatahex.trim());
    hex::decode(body).map_err(|e| {
        anyhow::anyhow!(
            "{what} 的 hex 解码失败（需 hex 字符串，可带 0x 前缀，收到 {} 个字符）: {e}",
            body.len()
        )
    })
}

/// 入口：按链分派到具体实现。
///
/// # 参数 `unsignedtxdatahex`
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
    unsignedtxdatahex: &str,
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
        return btc::sign_btc(unsignedtxdatahex, ctx, key).map_err(|e| sign_classify(&e.to_string()));
    }
    if context.is_some() {
        return Err(SdkError::invalid_argument(format!(
            "{chain} 不接受 context：只有 btc 需要它"
        )));
    }

    // 其余链都不需要 context。每个分支产出 `anyhow::Result<SignedResult>`，
    // 在 `match` 出口统一分类——这样 10 个链文件一个都不用动。
    match chain {
        "eth" => eth::sign_eth(unsignedtxdatahex, key).await,
        "sol" => sol::sign_sol(unsignedtxdatahex, key),
        "near" => near::sign_near(unsignedtxdatahex, key),
        "apt" => apt::sign_apt(unsignedtxdatahex, key),
        "sui" => sui::sign_sui(unsignedtxdatahex, key),
        "ton" => ton::sign_ton(unsignedtxdatahex, key),
        "icp" => icp::sign_icp(unsignedtxdatahex, key),
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
            "解不出", "解析失败", "格式", "没有输入", "见证", "缺少第", "一一对应",
            "签名元数据", "必须传 context", "不接受 context", "公钥", "只支持",
            "种子不是合法", "脚本类型",
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

#[cfg(test)] mod tests;
