//! APT（Aptos）：ed25519 签名 + BCS 交易重组（输出 hex）。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`txdatahex` —— hex 字符串（可带 `0x`），解码后是**完整交易**的
//!   BCS 编码，即 `aptos_sdk::transaction::types::RawTransaction`
//!   （Aptos 里未签名交易就叫 RawTransaction，它本身就是结构完整的交易体）。
//! - **输出**：`signed_tx` = hex 的 BCS `SignedTransaction`，可直接 `submit`。
//!
//! # 与 SUI 的对比（两个最容易被写反的邻居）
//!
//! APT 与 SUI 都用 ed25519 + BCS，但**待签字节的构造完全不同**：
//! - APT：直接签 `BCS(RawTransaction)`，没有前缀；
//! - SUI：签 `intent(3 字节) ‖ BCS(Transaction)`，intent 在前。
//!
//! 两者混用不会报错，只会产出一条节点永远拒绝的交易——属于「静默失败」，
//! 所以分文件、各自写清契约，比挤在一起靠注释区分更安全。

use aptos_sdk::crypto::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use aptos_sdk::transaction::authenticator::TransactionAuthenticator;
use aptos_sdk::transaction::types::{RawTransaction, SignedTransaction};

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// APT 签名：对 RawTransaction 签名，BCS 组装 SignedTransaction（hex）。
///
/// # 领域要点
///
/// Aptos 的 `SignedTransaction` = `RawTransaction` + `TransactionAuthenticator`。
/// authenticator 要同时带上**公钥与签名**，因为节点只有交易本身，
/// 并不知道签名者是谁（Aptos 的账户地址是 `sha3-256(公钥 ‖ 0x00)`，
/// 只有拿到公钥才能反推出该用哪个账户的序列号与余额）。
pub fn sign_apt(txdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。各链自己解码，报错时才能说清「这段字节本该是什么」。
    let txdata = decode_txdata(txdatahex, "APT 完整交易（BCS RawTransaction）")?;

    let sk = Ed25519PrivateKey::from_bytes(&key.seed)
        .map_err(|e| anyhow::anyhow!("APT 私钥重建失败: {e}"))?;
    let raw: RawTransaction = bcs::from_bytes(&txdata)
        .map_err(|e| anyhow::anyhow!("APT 交易解码失败（需 BCS RawTransaction）: {e}"))?;

    // ⚠️ **待签字节不是 `BCS(RawTransaction)`**，而是
    //   `sha3_256("APTOS::RawTransaction")` ‖ `BCS(RawTransaction)`
    //
    // 前面那 32 字节是 Aptos 的**域分离盐**（domain separation salt）。
    // 直接签裸 BCS 时：签名在数学上完全合法、本地验签也能过，
    // 但节点会判定「签的不是这笔交易」而拒绝——不报错、不上链，属于最难排查的一类失败。
    //
    // 所以这里**不自己拼**，而是直接调官方 `signing_message()`：
    // 期望值/算法来自官方实现，才算对拍；自己拼一遍等于自证，官方哪天改了口径也发现不了。
    // 底部测试 `signature_verifies_against_the_official_signing_message` 用同一个官方函数
    // 当判据把这条钉死了（并配了反证：盐确实改变了待签字节）。
    let raw_bytes = raw
        .signing_message()
        .map_err(|e| anyhow::anyhow!("APT signing_message 计算失败: {e}"))?;
    // aptos-crypto 的 `sign` 直接返回签名（非 Result）。
    let signature: Ed25519Signature = sk.sign(&raw_bytes);
    let public_key: Ed25519PublicKey = sk.public_key();

    // SignedTransaction 由 RawTransaction + TransactionAuthenticator 组成；
    // authenticator 的 ed25519 构造接收 (公钥字节, 签名字节)。
    let authenticator = TransactionAuthenticator::ed25519(
        public_key.to_bytes().to_vec(),
        signature.to_bytes().to_vec(),
    );
    let signed = SignedTransaction::new(raw, authenticator);
    let out = bcs::to_bytes(&signed)
        .map_err(|e| anyhow::anyhow!("APT 交易重组失败: {e}"))?;

    // 单签名链：见 `eth.rs` 里同名的说明。
    let sig_hex = format!("0x{}", hex::encode(signature.to_bytes()));

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signed_tx: Some(format!("0x{}", hex::encode(out))),
        encoding: "hex".to_string(),
        note: None,
    })
}

#[cfg(test)] mod tests;
