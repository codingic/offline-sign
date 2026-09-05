// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
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

    /// **端到端产出**：`signedtxdatahex` 必须能过**节点自己的验签**。
    ///
    /// # 这条测试抓到过一个真实缺陷
    ///
    /// NEAR 的待签字节**不是** `borsh(tx)`，而是 `sha256(borsh(tx))` —— 那个 32 字节哈希。
    /// 判据直接取自节点代码 `near-primitives-0.37.3/src/transaction.rs:291`：
    ///
    /// ```ignore
    /// signedtxdatahex.signature.verify(signedtxdatahex.get_hash().as_ref(), signedtxdatahex.transaction.public_key())
    /// ```
    ///
    /// 签错对象时（签了裸 borsh 字节），签名在数学上完全合法、本地也验得过，
    /// 但节点回一个 `InvalidSignature` 就完事了——不告诉你签错了什么。
    #[test]
    fn signedtxdatahex_passes_the_nodes_own_signature_check() {
        let key = fixture_key();
        let tx = fixture_tx(&key);
        let txdatahex = hex::encode(borsh::to_vec(&tx).expect("NEAR 交易应可 Borsh 序列化"));

        let out = sign_near(&txdatahex, &key).expect("合法的 NEAR 交易应能签名");
        let raw = out.signedtxdatahex.expect("NEAR 必须产出 signedtxdatahex");
        let bytes = hex::decode(raw.strip_prefix("0x").expect("出参应带 0x"))
            .expect("signedtxdatahex 应是合法 hex");
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
