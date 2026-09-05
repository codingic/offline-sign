// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
    use super::*;
    use crate::store::Scheme;
    use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};

    fn fixture_key() -> StoredKey {
        StoredKey {
            scheme: Scheme::Ed25519,
            seed: [6u8; 32],
        }
    }

    /// **端到端口径**：签的就是**收到的原始字节**，中间**不额外做 sha256**。
    ///
    /// 这条契约很容易被「好心」改坏：TON 钱包常见做法是签 body 的哈希，
    /// 于是后来者可能顺手在这里加一步 `sha256`。加了以后签名仍然完全合法，
    /// 但**节点验的是原文**，于是永远拒绝——本地却一片绿。
    ///
    /// 判据用 dalek 验「原文」，而不是用本实现自己算的东西对照。
    #[test]
    fn signs_the_raw_bytes_without_an_extra_hash() {
        let key = fixture_key();
        // 用一段能看出「没被哈希」的形态：不是 32 字节，长度也不是哈希输出长度。
        let body: Vec<u8> = b"ton external message body".to_vec();
        let txdatahex = hex::encode(&body);

        let out = sign_ton(&txdatahex, &key).expect("合法 hex 应能签名");

        let sig_hex = out.signature.strip_prefix("0x").expect("出参应带 0x");
        let sig: [u8; 64] = hex::decode(sig_hex)
            .expect("签名应是合法 hex")
            .try_into()
            .expect("ed25519 签名应是 64 字节");

        let sk = SigningKey::from_bytes(&key.seed);
        let vk = VerifyingKey::from(&sk);
        assert!(
            vk.verify(&body, &DalekSignature::from_bytes(&sig)).is_ok(),
            "签名必须验得过**原始字节**；验不过说明内部多加了一步哈希，\
             那会导致节点验签失败（节点验的是原文）"
        );

        // 反证：签名必须**严格绑定**在这段字节上。
        // 没有这条，上面的 `verify` 有可能因为实现上的意外（比如验的是空消息）而恒真。
        let mut tampered = body.clone();
        tampered[0] ^= 0x01;
        assert!(
            vk.verify(&tampered, &DalekSignature::from_bytes(&sig))
                .is_err(),
            "改动任意一个字节后必须验签失败——否则说明签名没有真正绑定到原文"
        );
    }

    /// TON 现在**装配**完整 external message：`signedtxdatahex` = 0x + (64字节签名 ‖ 消息字节)。
    #[test]
    fn assembles_complete_external_message() {
        let key = fixture_key();
        // 消息本体（不含签名）：前 64 字节位置由签名占用。
        let body: Vec<u8> = b"ton external message body".to_vec();
        let out = sign_ton(&hex::encode(&body), &key).expect("合法 hex 应能签名");

        let signed = out
            .signedtxdatahex
            .expect("TON 现在应返回装配好的 external message");
        let bytes = hex::decode(signed.strip_prefix("0x").expect("应带 0x"))
            .expect("signedtxdatahex 应是合法 hex");

        // 长度 = 64（签名）+ 消息本体长度。
        assert_eq!(
            bytes.len(),
            64 + body.len(),
            "signedtxdatahex 应是「64字节签名 ‖ 消息」，长度对不上"
        );
        // 前 64 字节必须能独立验过「原始消息」——证明签的就是这段字节、且前拼顺序正确。
        let sk = SigningKey::from_bytes(&key.seed);
        let vk = VerifyingKey::from(&sk);
        let sig_slice: [u8; 64] = bytes[..64].try_into().expect("前 64 字节应为签名");
        assert!(
            vk.verify(&body, &DalekSignature::from_bytes(&sig_slice)).is_ok(),
            "前 64 字节必须是验得过消息本体的 ed25519 签名"
        );
        // 尾部必须是原消息字节（前拼，不是后拼）。
        assert_eq!(&bytes[64..], &body[..], "签名应前拼到消息前，尾部须是原始消息");
        // 说明应点明已返回完整 external message。
        let note = out.note.expect("TON 应给出说明");
        assert!(note.contains("external message"), "说明应点明返回完整 external message，实际: {note}");
    }

    /// 非 hex 输入必须报错，且错误信息点名 TON。
    #[test]
    fn non_hex_txdata_is_rejected() {
        let err = sign_ton("0xZZZZ", &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("TON"),
            "错误信息应带链名以便定位，实际: {err}"
        );
    }
