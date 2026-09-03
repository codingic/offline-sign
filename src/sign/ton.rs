//! TON：仅做 ed25519 签名，**不组装** external message。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 为什么 TON 是六条链里的例外
//!
//! TON 的真实地址由**钱包合约的 code + state-init** 共同决定，仅凭公钥算不出来；
//! 而一笔可广播的 external message 又必须带上 state-init（首次部署时）。
//! 通用离线签名器既不知道用户用的是哪个钱包版本（v3 / v4 / highload），
//! 也不知道该不该带 init，因此这里**刻意只返回签名**，`signed_tx` 恒为 `None`。
//! 强行在这里拼 message 会产出「能广播但打到错误地址」的交易，那比不做更危险。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`txdatahex` —— hex 字符串（可带 `0x`），解码后是 external message 的
//!   **完整序列化字节**——与其余各链口径一致，是「结构完整、只差签名」的交易本体，
//!   **不是**单独的待签哈希或摘要。
//! - **输出**：`signature` = `0x` + 64 字节 ed25519 签名 hex；`signed_tx` = `None`。

use ed25519_dalek::{Signer, SigningKey};

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// TON 签名：对给定字节做 ed25519 签名，不做任何交易组装。
///
/// # 领域要点
///
/// 这里**不校验**输入是不是合法的 TON 消息：本函数只保证「用这把私钥对这段字节
/// 签出了有效签名」。判断该签什么，是调用方（钱包层）的责任。
///
/// # 一个需要留意的口径
///
/// 本函数直接对**收到的完整字节**签名，内部**不额外做 sha256**。
/// 这是刻意的：与其余各链保持同一口径——签传入的完整交易字节，
/// 而不是由签名服务替调用方决定「该签原文还是签哈希」。
///
/// 若某个上游场景约定的是「签 body 的哈希」（TON 钱包常见做法），
/// 应由调用方在构造 `txdatahex` 时就传入哈希后的字节，或明确要求本函数加一步哈希；
/// **不要**默默在这里加，否则其余五条链的口径就不一致了。
pub fn sign_ton(txdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。TON 是唯一不解析字节结构的链（只做裸签名），
    // 但解码仍要在本函数内完成：调用方给的是字符串，解码失败得由这里说清楚。
    let txdata = decode_txdata(txdatahex, "TON external message（完整序列化字节）")?;

    let sk = SigningKey::from_bytes(&key.seed);
    let sig = sk.sign(&txdata);
    // 单签名链：见 `eth.rs` 里同名的说明。
    let sig_hex = format!("0x{}", hex::encode(sig.to_bytes()));

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signed_tx: None,
        encoding: "hex".to_string(),
        note: Some(
            "TON 仅返回 ed25519 签名；完整 external message 组装需钱包 code + state-init，通用签名器不负责"
                .to_string(),
        ),
    })
}

#[cfg(test)] mod tests;
