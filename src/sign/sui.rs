//! SUI：ed25519 签名 + BCS 交易重组（输出 base64）。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`unsignedtxdatahex` —— hex 字符串（可带 `0x`），解码后是**完整交易**的
//!   BCS 编码，即 `sui_sdk_types::Transaction`（结构完整、只差签名）。
//! - **输出**：`signedtxdatahex` = base64 的 BCS `SignedTransaction`，
//!   可直接 `sui_executeTransactionBlock`。
//!
//! # 本链最容易踩的坑：intent 前缀
//!
//! Sui 不是直接签交易字节，而是签 `intent(3 字节) ‖ BCS(Transaction)`。
//! 少算这 3 个字节，签名在数学上完全合法，但节点会判定「签的不是这笔交易」
//! 而拒绝——不报错、不上链，属于最难排查的一类失败。
//! 与之对照，APT 没有这个前缀，详见 [`crate::sign::apt`] 的模块文档。

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sui_sdk_types::{
    Intent, IntentAppId, IntentScope, IntentVersion, SignatureScheme, SignedTransaction,
    Transaction, UserSignature,
};

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// SUI 签名：按官方约定签 intent 前缀 ‖ BCS(Transaction)，封装为 UserSignature（base64）。
///
/// # 领域要点
///
/// `UserSignature` 的字节布局是 `flag(1) ‖ signature(64) ‖ pubkey(32)`，
/// 公钥**跟在签名后面**而不是放在别处；`flag = 0x00` 代表 ed25519 方案。
/// 这个 97 字节的结构就是 Sui 节点认定「谁签的」的依据。
pub fn sign_sui(unsignedtxdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。各链自己解码，报错时才能说清「这段字节本该是什么」。
    let txdata = decode_txdata(unsignedtxdatahex, "SUI 完整交易（BCS Transaction）")?;

    let sk = SigningKey::from_bytes(&key.seed);
    let vk = VerifyingKey::from(&sk);

    let raw: Transaction = bcs::from_bytes(&txdata)
        .map_err(|e| anyhow::anyhow!("SUI 交易解码失败（需 BCS Transaction）: {e}"))?;
    let raw_bytes = bcs::to_bytes(&raw)
        .map_err(|e| anyhow::anyhow!("SUI Transaction 序列化失败: {e}"))?;

    // Sui 签名域 = intent(3 字节) ‖ 交易 BCS 字节。
    let intent = Intent::new(IntentScope::TransactionData, IntentVersion::V0, IntentAppId::Sui)
        .to_bytes()
        .to_vec();

    // 语法：`let mut msg = intent;` 把 Vec 的所有权移过来（intent 是上面刚创建的临时值），
    // 接着 `extend_from_slice` 就地追加。若写成 `let mut msg = &intent;` 就只能得到
    // 不可变/可变的**引用**，没法追加——这里需要的是拥有所有权的 Vec。
    let mut msg = intent;
    msg.extend_from_slice(&raw_bytes);

    // 语法：ed25519-dalek 的 `sign` 来自 `Signer` trait，必须 `use ed25519_dalek::Signer`
    // 才能调用；它返回 `Signature` 值（不是 Result），因为纯 ed25519 签名不会失败。
    let sig = sk.sign(&msg);
    let sig_bytes = sig.to_bytes();
    let pub_bytes = vk.to_bytes();

    // UserSignature = flag(0x00) ‖ sig(64) ‖ pubkey(32)。
    let mut full = vec![SignatureScheme::Ed25519 as u8];
    full.extend_from_slice(&sig_bytes);
    full.extend_from_slice(&pub_bytes);
    let user_sig = UserSignature::from_bytes(&full)
        .map_err(|e| anyhow::anyhow!("SUI UserSignature 封装失败: {e}"))?;

    // `SignedTransaction` 字段公开，直接构造（transaction + signatures）。
    let signed = SignedTransaction {
        transaction: raw,
        signatures: vec![user_sig],
    };
    let out = bcs::to_bytes(&signed)
        .map_err(|e| anyhow::anyhow!("SUI 交易重组失败: {e}"))?;

    // 单签名链：见 `eth.rs` 里同名的说明。
    let sig_hex = format!("0x{}", hex::encode(sig_bytes));

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signedtxdatahex: Some(base64::engine::general_purpose::STANDARD.encode(&out)),
        txhash: None,
        encoding: "base64".to_string(),
        note: Some(
            "SUI 的 tx digest 为 BLAKE2b-256(BCS(SignedTransaction))；本服务只返回 BCS 字节，\
             调用方可对自身解 BCS 后按 Sui 规则取 digest，故不另返 txhash".to_string(),
        ),
    })
}

#[cfg(test)] mod tests;
