//! NEAR：ed25519 签名 + Borsh 交易重组（输出 hex）。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`txdatahex` —— hex 字符串（可带 `0x`），解码后是**完整交易**的
//!   Borsh 编码，即 `near_primitives::transaction::Transaction`（结构完整、只差签名）。
//! - **输出**：`signed_tx` = hex 的 Borsh `SignedTransaction`，可直接 `broadcast_tx_commit`。
//!
//! # 本链最容易踩的坑：密钥的字节表示
//!
//! NEAR 的 `ED25519SecretKey` 内部存的是 **64 字节 keypair**（种子 32 + 公钥 32），
//! 不是 32 字节种子。所以从 keystore 拿到种子后，必须先用 dalek 的
//! `to_keypair_bytes()` 展开成 64 字节，再喂给 NEAR——直接塞 32 字节会编译不过，
//! 而如果有人「想办法」只取前 32 字节，签出来的交易会被节点静默拒绝
//! （不报错，只是永远不上链）。

use borsh::BorshDeserialize;
use ed25519_dalek::SigningKey;
use near_crypto::{ED25519SecretKey, SecretKey, Signature};
use near_primitives::transaction::{SignedTransaction, Transaction};

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// NEAR 签名：对交易的 **sha256(Borsh) 哈希**签名，Borsh 组装 SignedTransaction。
///
/// # 领域要点
///
/// NEAR 的待签字节是 `sha256(borsh(Transaction))` 这个 32 字节**哈希**，
/// 而不是交易自身的 Borsh 字节——这与 SOL 那种「先算 message 再签」是两种不同口径，
/// 也和 BTC 的 sighash、SUI 的 intent 前缀各不相同。
/// 判据是节点自己的校验（`near-primitives` 的 `ValidatedTransaction::new`），
/// 底部测试把这一行原样搬过来当判据了。
pub fn sign_near(txdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。各链自己解码，报错时才能说清「这段字节本该是什么」。
    let txdata = decode_txdata(txdatahex, "NEAR 完整交易（Borsh 编码）")?;

    // NEAR SecretKey 内部是 64 字节 keypair（种子 32 + 公钥 32），由种子重建。
    let sk_dalek = SigningKey::from_bytes(&key.seed);
    let kp_bytes = sk_dalek.to_keypair_bytes();
    let secret = SecretKey::ED25519(ED25519SecretKey(kp_bytes));

    let tx: Transaction = BorshDeserialize::try_from_slice(&txdata)
        .map_err(|e| anyhow::anyhow!("NEAR 交易解码失败（需 Borsh Transaction）: {e}"))?;

    // ⚠️ **待签字节不是 `borsh(tx)`**，而是 `sha256(borsh(tx))` 那个 32 字节哈希。
    //
    // 判据来自节点自己的代码（`near-primitives-0.37.3/src/transaction.rs:291`，
    // `ValidatedTransaction::new` 内部）：
    //   `signed_tx.signature.verify(signed_tx.get_hash().as_ref(), …)`
    // 而 `get_hash()` = `sha256(borsh(transaction))`。
    //
    // 签裸 borsh 字节时：签名在数学上完全合法、本地也能验过，
    // 但节点只会回一个 `InvalidSignature`，不告诉你签错了对象——
    // 属于「本地全绿、只有广播时才失败」那类最贵的缺陷。
    //
    // `get_hash_and_size()` 一次给出 (哈希, 序列化长度)，这里只要前者。
    // 语法：解构元组时 `_size` 的下划线前缀表示「这个绑定有意不用」，
    // 否则 clippy 会报 `unused_variables`。
    let (digest, _size) = tx.get_hash_and_size();
    let signature: Signature = secret.sign(&digest.0);
    let signed = SignedTransaction::new(signature.clone(), tx);
    let out = borsh::to_vec(&signed)
        .map_err(|e| anyhow::anyhow!("NEAR 交易重组失败: {e}"))?;

    // 取原始 ed25519 签名字节（64 字节）作为响应签名。
    //
    // 语法：`match &signature` 借用的是**引用**，所以下面的 `s` 是 `&ED25519Signature`，
    // 不会把 signature 移动走——后面若还要用它就不至于编译失败。
    // 这里用了 `&signature` 其实也是为了与 `_ =>` 分支的 `borsh::to_vec(&signature)` 共存。
    let sig_bytes = match &signature {
        Signature::ED25519(s) => s.to_bytes().to_vec(),
        _ => borsh::to_vec(&signature).unwrap_or_default(),
    };

    // 单签名链：见 `eth.rs` 里同名的说明。
    let sig_hex = format!("0x{}", hex::encode(&sig_bytes));

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signed_tx: Some(format!("0x{}", hex::encode(out))),
        encoding: "hex".to_string(),
        note: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Scheme;
    use near_primitives::hash::CryptoHash;
    use near_primitives::transaction::{Action, TransactionV0, TransferAction};
    use near_primitives::types::Balance;

    fn fixture_key() -> StoredKey {
        StoredKey {
            scheme: Scheme::Ed25519,
            seed: [9u8; 32],
        }
    }

    /// 一条确定性构造的 NEAR 交易；`public_key` 必须与签名用的钥匙一致，
    /// 因为节点是拿**交易里声明的公钥**去验签的。
    fn fixture_tx(key: &StoredKey) -> Transaction {
        let sk_dalek = SigningKey::from_bytes(&key.seed);
        let secret = SecretKey::ED25519(ED25519SecretKey(sk_dalek.to_keypair_bytes()));
        Transaction::V0(TransactionV0 {
            signer_id: "alice.near".parse().expect("合法 AccountId"),
            public_key: secret.public_key(),
            nonce: 1,
            receiver_id: "bob.near".parse().expect("合法 AccountId"),
            block_hash: CryptoHash([0xab; 32]),
            actions: vec![Action::Transfer(TransferAction {
                deposit: Balance::from_yoctonear(1),
            })],
        })
    }

    /// **端到端产出**：`signed_tx` 必须能过**节点自己的验签**。
    ///
    /// # 这条测试抓到过一个真实缺陷
    ///
    /// NEAR 的待签字节**不是** `borsh(tx)`，而是 `sha256(borsh(tx))` —— 那个 32 字节哈希。
    /// 判据直接取自节点代码 `near-primitives-0.37.3/src/transaction.rs:291`：
    ///
    /// ```ignore
    /// signed_tx.signature.verify(signed_tx.get_hash().as_ref(), signed_tx.transaction.public_key())
    /// ```
    ///
    /// 签错对象时（签了裸 borsh 字节），签名在数学上完全合法、本地也验得过，
    /// 但节点回一个 `InvalidSignature` 就完事了——不告诉你签错了什么。
    #[test]
    fn signed_tx_passes_the_nodes_own_signature_check() {
        let key = fixture_key();
        let tx = fixture_tx(&key);
        let txdatahex = hex::encode(borsh::to_vec(&tx).expect("NEAR 交易应可 Borsh 序列化"));

        let out = sign_near(&txdatahex, &key).expect("合法的 NEAR 交易应能签名");
        let raw = out.signed_tx.expect("NEAR 必须产出 signed_tx");
        let bytes = hex::decode(raw.strip_prefix("0x").expect("出参应带 0x"))
            .expect("signed_tx 应是合法 hex");
        let signed: SignedTransaction =
            BorshDeserialize::try_from_slice(&bytes).expect("产出应能解回 SignedTransaction");

        // ↓ 这一行与 `ValidatedTransaction::new` 里的校验逐字对应。
        let hash = signed.get_hash();
        assert!(
            signed
                .signature
                .verify(&hash.0, signed.transaction.public_key()),
            "sign_near 的签名必须能过节点自己的验签（签的是 sha256(borsh(tx))，不是 borsh(tx)）"
        );
    }

    /// **反证**：上面那条不能是空的——哈希确实不等于裸 borsh 字节。
    ///
    /// 若 `get_hash()` 恰好等于 `borsh(tx)`（比如哪天 NEAR 改了口径），
    /// 前一条测试会退化成恒真，所以这里把「两者不同」也钉住。
    #[test]
    fn the_signing_digest_is_not_the_raw_borsh_bytes() {
        let key = fixture_key();
        let tx = fixture_tx(&key);
        let bare = borsh::to_vec(&tx).expect("应可 Borsh 序列化");

        let signed = SignedTransaction::new(
            near_crypto::Signature::empty(near_crypto::KeyType::ED25519),
            tx,
        );
        let digest = signed.get_hash();

        assert_ne!(
            bare.as_slice(),
            digest.0.as_slice(),
            "待签摘要必须是 sha256 后的 32 字节，不能等于裸 borsh 字节"
        );
        assert_eq!(digest.0.len(), 32, "sha256 的摘要应恰好 32 字节");
        assert_ne!(
            digest.0, [0u8; 32],
            "摘要不应为全零（说明哈希确实算了，不是默认值）"
        );
    }

    /// 非 Borsh 的垃圾输入必须报错，且错误信息点名 NEAR。
    #[test]
    fn garbage_txdata_is_rejected() {
        let key = fixture_key();
        // 合法 hex，但不是 Borsh Transaction。
        let err = sign_near(&"ab".repeat(32), &key).unwrap_err();
        assert!(
            err.to_string().contains("NEAR"),
            "错误信息应带链名以便定位，实际: {err}"
        );
    }
}
