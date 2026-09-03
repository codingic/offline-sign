//! ICP（Internet Computer）：仅做 ed25519 签名，**不组装**信封 / 请求。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 为什么 ICP 是「只签名」链（与 TON 同类）
//!
//! ICP 的可签名输入是一段 **CBOR 编码的 request / envelope**（含 caller principal、
//! ingress expiry、method name、arg 等），这段字节由调用方（agent / SDK 的
//! `build_transfer` 或上层钱包逻辑）负责拼装——离线签名器并不知道用户要调哪个
//! canister、哪个 method、arg 是什么。因此这里**刻意只返回签名**，`signed_tx` 恒为 `None`。
//!
//! 强行在这里拼 envelope 会产出「能广播但 caller / method / arg 全错」的请求，
//! 那比不做更危险（资金可能打到错误的 canister / 方法）。
//!
//! # 地址在哪算
//!
//! ICP 的「地址」即 **self-authenticating principal**，由公钥派生（与签名无关），
//! 因此放在 `keys.rs::ed25519_info` 里算（`icp_principal_text`），不在这里。
//! 本文件只负责「用这把私钥对这段字节签出有效 ed25519 签名」。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`txdatahex` —— hex 字符串（可带 `0x`），解码后是待签的**完整字节**
//!   （IC 的 ingress message 本体 / envelope 序列化结果），与其余各链口径一致。
//! - **输出**：`signature` = `0x` + 64 字节 ed25519 签名 hex；`signed_tx` = `None`。

use ed25519_dalek::{Signer, SigningKey};

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// ICP 签名：对给定字节做 ed25519 签名，不做任何交易组装。
///
/// # 领域要点
///
/// 这里**不校验**输入是不是合法的 IC 消息：本函数只保证「用这把私钥对这段字节
/// 签出了有效签名」。判断该签什么，是调用方（agent / 钱包层）的责任。
///
/// # 一个需要留意的口径
///
/// 本函数直接对**收到的完整字节**签名，内部**不额外做 hash**。
/// 这是刻意的：与其余各链保持同一口径——签传入的完整交易字节，
/// 而不是由签名服务替调用方决定「该签原文还是签哈希」。
///
/// ICP 的「待签字节」已由调用方在拼装 envelope 时带上 intent / domain 分隔符，
/// 签名服务**不应**再二次哈希，否则节点验的是另一段字节，签名永远被拒。
pub fn sign_icp(txdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。ICP 是唯一不解析字节结构的链（只做裸签名），
    // 但解码仍要在本函数内完成：调用方给的是字符串，解码失败得由这里说清楚。
    let txdata = decode_txdata(txdatahex, "ICP ingress message（完整序列化字节）")?;

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
            "ICP 仅返回 ed25519 签名；完整 ingress message / envelope 组装需 caller principal、\
             method、arg，由调用方负责，通用签名器不组装"
                .to_string(),
        ),
    })
}

#[cfg(test)] mod tests;
