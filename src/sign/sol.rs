//! SOL：ed25519 签名 + bincode 交易重组（输出 base64）。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`unsignedtxdatahex` —— hex 字符串（可带 `0x`），解码后是**完整交易**
//!   （`solana_transaction::Transaction`）的 **bincode** 字节，
//!   其中 `signatures[0]` 是占位空签名（Solana 的惯例：签名槽先留好位置再填）。
//! - **输出**：`signedtxdatahex` = base64 的 bincode 字节，可直接 `sendTransaction`。
//!
//! # 本链最容易踩的坑：待签字节到底是哪个
//!
//! 见 [`sign_sol`] 中关于 `Message::serialize()` 的说明——它和
//! `bincode::serialize(&tx.message)` 逐字节相同，但**不能**因此就去签 bincode
//! 编码：这里取 `serialize()` 是因为它是官方 `try_partial_sign` 内部用的那一个，
//! 意图更明确，且不依赖 serde feature。底部的测试把这个等价性钉死了。

use base64::Engine;
use solana_keypair::keypair_from_seed;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// SOL 签名：由种子重建 Keypair，对 message 签名并填回 `signatures[0]`。
///
/// # 领域要点
///
/// Solana 的 Keypair 直接由 32 字节 ed25519 **种子**重建（不是「私钥字节」，
/// ed25519 的种子就是私钥）。这与 `keys::random_seed` 生成时用的表示一致，
/// 所以从 keystore 解开的种子能原样还原出同一个 Keypair。
pub fn sign_sol(unsignedtxdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。各链自己解码，报错时才能说清「这段字节本该是什么」。
    let txdata = decode_txdata(unsignedtxdatahex, "SOL 完整交易（bincode Transaction）")?;

    // 由 32 字节种子直接重建 Keypair（与生成时一致：seed 即 ed25519 种子）。
    let kp = keypair_from_seed(&key.seed)
        .map_err(|e| anyhow::anyhow!("SOL Keypair 重建失败: {e}"))?;

    let mut tx: Transaction = bincode::deserialize(&txdata)
        .map_err(|e| anyhow::anyhow!("SOL 交易解码失败（需 bincode Transaction）: {e}"))?;

    if tx.signatures.is_empty() {
        return Err(anyhow::anyhow!("SOL 交易缺少签名槽（signatures[0] 应为占位签名）"));
    }

    // 待签字节 = `Message::serialize()`，即 Solana 的**线格式**。
    //
    // 一个反直觉的事实（底部测试 `bincode_matches_official_wire_format` 已钉死）：
    // 它与 `bincode::serialize(&tx.message)` **逐字节相同**——
    // 因为 `Message` 里所有向量字段都套了 `ShortVec`，而 `ShortVec` 的 serde 实现
    // 就是照着线格式写的（长度用 compact-u16，不用 bincode 默认的 u64）。
    //
    // 既然两者等价，这里仍取 `serialize()`：它是官方 `Transaction::try_partial_sign`
    // 内部（`message_data()`）用的那一个，意图更明确，且不依赖 serde feature。
    let msg_bytes = tx.message.serialize();

    // 语法：`Signer` trait 必须在作用域内，`kp.sign_message(..)` 才能解析到它的方法；
    // 这就是文件顶部 `use solana_signer::Signer;` 的用途——即便 `kp` 本身不是我们定义的类型。
    let sig = kp.sign_message(&msg_bytes);
    tx.signatures[0] = sig;

    let out = bincode::serialize(&tx)
        .map_err(|e| anyhow::anyhow!("SOL 交易重组失败: {e}"))?;
    // 单签名链：见 `eth.rs` 里同名的说明。
    let sig_hex = format!("0x{}", hex::encode(sig.as_ref()));

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signedtxdatahex: Some(base64::engine::general_purpose::STANDARD.encode(&out)),
        txhash: None,
        encoding: "base64".to_string(),
        note: Some(
            "SOL 的链上 txid 即本交易唯一的 ed25519 签名（见 signatures[0]），\
             与本服务的签名口径一致，故不另返 txhash；调用方可直接用 signatures[0] 作 txid 查询".to_string(),
        ),
    })
}

#[cfg(test)] mod tests;
