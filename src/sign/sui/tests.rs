// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
    use super::*;
    use crate::store::Scheme;
    use ed25519_dalek::Signature as DalekSignature;
    // `Verifier` 是**验签**方法所在的 trait（与签名的 `Signer` 分开）。
    // 用它验签意味着判据走的是 dalek 自己的实现，而不是 solana / sui 的封装。
    use ed25519_dalek::Verifier;
    use sui_sdk_types::{
        Address, GasPayment, ProgrammableTransaction, TransactionExpiration, TransactionKind,
    };

    fn fixture_key() -> StoredKey {
        StoredKey {
            scheme: Scheme::Ed25519,
            seed: [3u8; 32],
        }
    }

    /// 一条最小但结构完整的 PTB 交易（空输入、空指令）。
    ///
    /// 字段值固定而非随机，是为了让下面的字节级断言可复现。
    fn fixture_tx() -> Transaction {
        let sender = Address::from_bytes([0x11; 32]).expect("32 字节应是合法地址");
        Transaction {
            kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                inputs: vec![],
                commands: vec![],
            }),
            sender,
            gas_payment: GasPayment {
                objects: vec![],
                owner: sender,
                price: 1_000,
                budget: 2_000_000,
            },
            expiration: TransactionExpiration::None,
        }
    }

    /// Sui 的签名域前缀：`IntentScope::TransactionData` / `IntentVersion::V0` /
    /// `IntentAppId::Sui` 三个枚举的判别值**都是 0**（读 sui-sdk-types 源码确认）。
    fn intent_bytes() -> [u8; 3] {
        Intent::new(IntentScope::TransactionData, IntentVersion::V0, IntentAppId::Sui).to_bytes()
    }

    /// **端到端产出**：签名必须验得过 `intent ‖ BCS(Transaction)`。
    ///
    /// Sui 与 Aptos 的差别就在这 3 个字节，两者混用不会报错，
    /// 只会产出一条节点永远拒绝的交易。这条测试把「前缀在，且签的是它」钉死。
    #[test]
    fn signature_verifies_against_the_intent_prefixed_message() {
        let tx = fixture_tx();
        let bcs = bcs::to_bytes(&tx).expect("Transaction 应可 BCS 序列化");
        let key = fixture_key();

        let out = sign_sui(&hex::encode(&bcs), &key).expect("合法 SUI 交易应能签名");

        // 判据：intent(3) ‖ BCS(tx)。
        let mut expected = intent_bytes().to_vec();
        expected.extend_from_slice(&bcs);

        let sig_hex = out.signature.strip_prefix("0x").expect("出参应带 0x");
        let sig: [u8; 64] = hex::decode(sig_hex)
            .expect("签名应是合法 hex")
            .try_into()
            .expect("ed25519 签名应是 64 字节");

        let sk = SigningKey::from_bytes(&key.seed);
        let vk = VerifyingKey::from(&sk);
        assert!(
            vk.verify(&expected, &DalekSignature::from_bytes(&sig)).is_ok(),
            "sign_sui 的签名必须验得过 intent ‖ BCS(tx)；\
             验不过说明漏了 intent 前缀或签错了对象"
        );
    }

    /// **反证**：intent 前缀确实存在，且省掉它就验不过。
    ///
    /// 没有这条，上面的断言可能在「intent 恰好是空字节」时恒真。
    #[test]
    fn dropping_the_intent_prefix_breaks_verification() {
        assert_eq!(
            intent_bytes(),
            [0, 0, 0],
            "TransactionData=0 / V0=0 / Sui=0 —— 三个判别值都是 0，\
             若哪天官方改了枚举顺序，这里会红"
        );
        assert_eq!(intent_bytes().len(), 3, "intent 应恰好 3 字节");

        let tx = fixture_tx();
        let bcs = bcs::to_bytes(&tx).expect("应可 BCS 序列化");
        let key = fixture_key();
        let out = sign_sui(&hex::encode(&bcs), &key).expect("应能签名");

        let sig_hex = out.signature.strip_prefix("0x").unwrap();
        let sig: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();
        let sk = SigningKey::from_bytes(&key.seed);
        let vk = VerifyingKey::from(&sk);

        assert!(
            vk.verify(&bcs, &DalekSignature::from_bytes(&sig)).is_err(),
            "用**不带** intent 的裸 BCS 字节验签必须失败——\
             否则说明 intent 前缀根本没起作用，前一条测试是空的"
        );
    }

    /// `signed_tx` 里的 `UserSignature` 必须是 `flag ‖ sig(64) ‖ pubkey(32)` = 97 字节。
    ///
    /// 这个布局一旦错位（比如把公钥放前面），节点就认不出签名者是谁。
    #[test]
    fn user_signature_is_flag_then_signature_then_pubkey() {
        use base64::Engine as _;

        let tx = fixture_tx();
        let bcs = bcs::to_bytes(&tx).expect("应可 BCS 序列化");
        let key = fixture_key();
        let out = sign_sui(&hex::encode(&bcs), &key).expect("应能签名");

        let raw = out.signed_tx.expect("SUI 必须产出 signed_tx");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw)
            .expect("signed_tx 应是合法 base64");
        let signed: SignedTransaction =
            bcs::from_bytes(&bytes).expect("产出应能解回 SignedTransaction");

        let user_sig = signed
            .signatures
            .first()
            .expect("应恰好一个签名")
            .to_bytes();
        assert_eq!(user_sig.len(), 97, "flag(1) ‖ sig(64) ‖ pubkey(32) = 97 字节");
        assert_eq!(user_sig[0], SignatureScheme::Ed25519 as u8, "flag 应为 0x00（ed25519）");

        let sk = SigningKey::from_bytes(&key.seed);
        assert_eq!(
            &user_sig[1..65],
            &out.signature.strip_prefix("0x").map(|h| hex::decode(h).unwrap()).unwrap()[..],
            "签名段应与返回的 signature 字段一致"
        );
        assert_eq!(
            &user_sig[65..97],
            VerifyingKey::from(&sk).to_bytes().as_slice(),
            "公钥段应跟在签名**后面**，且属于本 keystore"
        );
    }

    /// 非 BCS 的垃圾输入必须报错，且错误信息点名 SUI。
    #[test]
    fn garbage_txdata_is_rejected() {
        let err = sign_sui(&"ab".repeat(32), &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("SUI"),
            "错误信息应带链名以便定位，实际: {err}"
        );
    }
