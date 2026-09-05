//! ICP（Internet Computer）：做 ed25519 签名，并**按统一契约**返回 `signedtxdatahex`。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 装配规则（与「所有链收 unsigned 返 signed」统一契约一致）
//!
//! 与 TON 同类：本服务**不解析也不纠正** IC 的 envelope 结构（caller principal、
//! method、arg 都不在这里拼），只做「用这把私钥对传入字节签出 ed25519 签名，
//! 再把 64 字节签名前拼到字节前」这件事——和 TON 口径完全一致。
//!
//! 因此 `signedtxdatahex` = `0x` + 64 字节签名前拼「待签字节」。
//!
//! 必须点明一点：IC 真正可广播的是 CBOR envelope（`content` + `sender_pubkey` + `sender_sig`），
//! 而不是「签名 ‖ 原文」的扁平字节。所以本服务返回的 `signedtxdatahex` 只是签名前缀字节，
//! 调用方（agent / 钱包层）须自行把 signature 填进 envelope 的 sender_sig 字段后再广播。
//! 通用签名器不解析 envelope 内部、不去猜 caller / method / arg，避免拼出能广播但打到错误 canister 的请求。
//!
//! # 地址在哪算
//!
//! ICP 的「地址」即 **self-authenticating principal**，由公钥派生（与签名无关），
//! 因此放在 `keys.rs::ed25519_info` 里算（`icp_principal_text`），不在这里。
//! 本文件只负责「用这把私钥对这段字节签出有效 ed25519 签名并前拼」。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`unsignedtxdatahex` —— hex 字符串（可带 `0x`），解码后是待签的**完整字节**
//!   （IC 的 ingress message 本体 / envelope 序列化结果），与其余各链口径一致。
//! - **输出**：`signature` = `0x` + 64 字节 ed25519 签名 hex；`signedtxdatahex` = `0x` +
//!   64 字节签名前拼待签字节（调用方须据此组装 CBOR envelope，不能直接广播这段扁平字节）。

use ed25519_dalek::{Signer, SigningKey};

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// ICP 签名：对给定字节做 ed25519 签名，并把签名**前拼**回字节，返回 `signedtxdatahex`。
///
/// # 领域要点
///
/// 这里**不校验**输入是不是合法的 IC 消息：本函数只保证「用这把私钥对这段字节
/// 签出了有效签名，并按 TON 口径前拼」。判断该签什么，是调用方（agent / 钱包层）的责任。
///
/// # 一个需要留意的口径
///
/// 本函数直接对**收到的完整字节**签名，内部**不额外做 hash**。
/// 这是刻意的：与其余各链保持同一口径——签传入的完整交易字节，
/// 而不是由签名服务替调用方决定「该签原文还是签哈希」。
///
/// ICP 的「待签字节」若由调用方在拼装 envelope 时已带上 intent / domain 分隔符
/// （即 `hash(domain || content)` 的预哈希），签名服务**不应**再二次哈希，
/// 否则节点验的是另一段字节，签名永远被拒。
pub fn sign_icp(unsignedtxdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。ICP 不解析字节结构（只做裸签名 + 前拼），
    // 但解码仍要在本函数内完成：调用方给的是字符串，解码失败得由这里说清楚。
    let txdata = decode_txdata(unsignedtxdatahex, "ICP ingress message（完整序列化字节）")?;

    let sk = SigningKey::from_bytes(&key.seed);
    let sig = sk.sign(&txdata);
    let sig_bytes = sig.to_bytes();
    // 单签名链：见 `eth.rs` 里同名的说明。
    let sig_hex = format!("0x{}", hex::encode(sig_bytes));

    // 装配（与 TON 同口径）：把 64 字节签名前拼到字节前，返回 signedtxdatahex。
    // 注意：IC 真正可广播的是 CBOR envelope，扁平「签名 ‖ 原文」不是合法 envelope，
    // 调用方须把 `signature` 填进 envelope.sender_sig 字段后广播。
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
            "ICP 已返回签名前缀字节（0x + 64字节签名 ‖ 待签字节）。IC 真正可广播的是 CBOR envelope，\
             调用方须把 signature 填进 envelope.sender_sig 后广播；通用签名器不解析 envelope 结构。\
             ICP 的 request id 需由调用方包进 CBOR envelope 后按 IC 规则取，故不返回 txhash".to_string(),
        ),
    })
}

#[cfg(test)] mod tests;
