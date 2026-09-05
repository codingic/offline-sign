//! TON：做 ed25519 签名并**装配**完整 external message。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 装配规则（与「所有链收 unsigned 返 signed」统一契约一致）
//!
//! TON 的真实地址由**钱包合约的 code + state-init** 共同决定，仅凭公钥算不出来；
//! 而 external message 又必须带上 state-init（首次部署时）。通用离线签名器既不知道
//! 钱包版本（v3 / v4 / highload），也不知道该不该带 init——所以**装配所需的全部信息
//! 必须由调用方放进 `unsignedtxdatahex`**：它必须是「只差签名前缀」的消息本体。
//! 签名器只做一件事：把 64 字节 ed25519 签名**前拼**到消息字节前，得到可广播消息。
//! 这样签名器不必去猜钱包结构，又满足了「返回完整 signedtxdatahex」的统一契约。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`unsignedtxdatahex` —— hex 字符串（可带 `0x`），解码后是 external message 的
//!   **完整序列化字节**——是「结构完整、只差签名」的交易本体，**不是**单独的待签哈希或摘要。
//! - **输出**：`signature` = `0x` + 64 字节 ed25519 签名 hex；`signedtxdatahex` = `0x` +
//!   64 字节签名前拼消息字节（即装配好的完整 external message）。

use ed25519_dalek::{Signer, SigningKey};

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// TON 签名：对给定字节做 ed25519 签名，并把签名**前拼**回消息，返回完整 external message。
///
/// # 领域要点
///
/// 这里**不校验**输入是不是合法的 TON 消息：本函数只保证「用这把私钥对这段字节
/// 签出了有效签名，并把签名装配成可广播消息」。判断该签什么，是调用方（钱包层）的责任。
///
/// # 装配规则
///
/// TON 的 external message 结构是 `signature(64 字节) || message_body`，所以签名后把
/// 64 字节签名**前拼**到消息字节前即得完整消息。钱包版本（v3 / v4 / highload）与是否带
/// state-init 都由调用方决定，签名器不参与——它只负责「签名 + 前拼」。
///
/// # 一个需要留意的口径
///
/// 本函数直接对**收到的完整字节**签名，内部**不额外做 sha256**。
/// 这是刻意的：与其余各链保持同一口径——签传入的完整交易字节，
/// 而不是由签名服务替调用方决定「该签原文还是签哈希」。
///
/// 若某个上游场景约定的是「签 body 的哈希」（TON 钱包常见做法），
/// 应由调用方在构造 `unsignedtxdatahex` 时就传入哈希后的字节，或明确要求本函数加一步哈希；
/// **不要**默默在这里加，否则其余各链的口径就不一致了。
pub fn sign_ton(unsignedtxdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。TON 是唯一不解析字节结构的链（只做裸签名 + 前拼），
    // 但解码仍要在本函数内完成：调用方给的是字符串，解码失败得由这里说清楚。
    let txdata = decode_txdata(unsignedtxdatahex, "TON external message（完整序列化字节）")?;

    let sk = SigningKey::from_bytes(&key.seed);
    let sig = sk.sign(&txdata);
    let sig_bytes = sig.to_bytes();
    // 单签名链：见 `eth.rs` 里同名的说明。
    let sig_hex = format!("0x{}", hex::encode(sig_bytes));

    // 装配：TON 的 external message 结构就是 `signature(64) || message_body`，
    // 所以把 64 字节签名**前拼**到消息字节前，即得可广播的完整 external message。
    // 钱包 code / state-init 必须由调用方在 `unsignedtxdatahex` 里放好——签名器不猜钱包版本。
    let mut assembled = Vec::with_capacity(sig_bytes.len() + txdata.len());
    assembled.extend_from_slice(&sig_bytes);
    assembled.extend_from_slice(&txdata);

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signedtxdatahex: Some(format!("0x{}", hex::encode(&assembled))),
        txhash: None,
        encoding: "hex".to_string(),
        note: Some(
            "TON 已把 64 字节 ed25519 签名前拼到消息前，signedtxdatahex 即完整 external message（可直接广播）。\
             钱包 code / state-init 须由调用方放进 unsignedtxdatahex。\
             TON 的 txid 需解析 cell 树，本服务只做裸签名前拼，故不返回 txhash".to_string(),
        ),
    })
}

#[cfg(test)] mod tests;
