// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
    // `use super::*` 把父模块的**私有**绑定也带进来（子模块天然可见父模块的私有项），
    // 于是 `sign_sol` / `StoredKey` / 以及文件顶部的 `use solana_signer::Signer`
    // 都能直接用——否则得在测试里重复一遍 `use solana_signer::Signer`。
    use super::*;

    /// `bincode::serialize(&Message)` 与官方线格式 `Message::serialize()` **逐字节相同**。
    ///
    /// 这条测试记录的是一个**反直觉**的事实，值得写成断言而不是注释：
    /// 按 serde 的常规行为，向量长度会用 bincode 默认的 u64 前缀，
    /// 于是与 Solana 的线格式（compact-u16）本该不同。
    /// 但 `Message` 的所有向量字段都套了 `ShortVec`，而 `ShortVec` 的 serde 实现
    /// 是**专门照着线格式写的**——所以两种编码恰好一致。
    ///
    /// 为什么值得测：我曾据此断定「签 bincode 编码是错的」并动手改代码，
    /// 结果测试直接打脸——两种编码完全相同，原实现本来就是对的。
    /// 把这类「看着该不同、其实相同」的结论固化成断言，
    /// 能防止后来者（包括未来的我）再犯同样的错误。
    #[test]
    fn bincode_matches_official_wire_format() {
        use solana_message::Message;
        use solana_pubkey::Pubkey;
        use solana_system_interface::instruction::transfer;

        // 用**确定性**公钥而不是 `new_unique()`：这样下面的字节级断言才有固定期望值，
        // 不会因为随机地址偶发踩中边界（比如首字节恰好为 0）而 flaky。
        let from = Pubkey::new_from_array([0x11; 32]);
        let to = Pubkey::new_from_array([0x22; 32]);
        let message = Message::new(&[transfer(&from, &to, 1_000)], Some(&from));

        let wire = message.serialize();
        let bin = bincode::serialize(&message).expect("Message 应可 bincode 序列化");

        assert_eq!(
            wire, bin,
            "ShortVec 的 serde 实现应使 bincode 编码与官方线格式一致；\
             若不一致，说明待签字节的口径已改变，必须同步修改 sign_sol"
        );

        // 钉住线格式的开头，防止长度前缀悄悄退化成 bincode 默认的 u64：
        //   wire[0..3] = header（1 个必需签名 / 0 个只读签名 / 1 个只读非签名）
        //   wire[3]    = account_keys 的 compact-u16 长度 = 3
        //   wire[4..36]= 第一个账户（fee payer = from）的 32 字节公钥
        // 若长度前缀变成 u64，wire[3] 仍是 3（小端首字节），但 wire[4..12] 会是全零，
        // 与这里期望的 0x11 重复 32 字节冲突——于是断言会红。
        assert_eq!(&wire[..3], &[1, 0, 1]);
        assert_eq!(wire[3], 3);
        assert_eq!(&wire[4..36], &[0x11; 32]);
    }

    /// **端到端**：走真正的 `sign_sol`，产出必须能被**独立实现**验签。
    ///
    /// 与上面两条的分工：那两条测的是「字节串怎么来的」与「官方路径能不能签」，
    /// 这一条测的是**本模块的函数本身**——此前 `sign_sol` 没有任何直接覆盖，
    /// 于是「填错签名槽」「签错字节」这类缺陷在本地是全绿的。
    #[test]
    fn sign_sol_fills_slot_zero_and_verifies() {
        use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
        use solana_keypair::keypair_from_seed;
        use solana_message::Message;
        use solana_pubkey::Pubkey;
        use solana_system_interface::instruction::transfer;

        let key = StoredKey {
            scheme: crate::store::Scheme::Ed25519,
            seed: [5u8; 32],
        };
        let kp = keypair_from_seed(&key.seed).expect("种子应可重建 Keypair");
        let from = kp.pubkey();
        let to = Pubkey::new_from_array([0x22; 32]);

        // `new_unsigned` 会把签名槽先填成默认（全零）签名——正是调用方该给的形态。
        let tx = solana_transaction::Transaction::new_unsigned(Message::new(
            &[transfer(&from, &to, 1_000)],
            Some(&from),
        ));
        let txdatahex = hex::encode(bincode::serialize(&tx).expect("应可 bincode 序列化"));

        let out = sign_sol(&txdatahex, &key).expect("合法 SOL 交易应能签名");

        // 待签字节是官方线格式 `Message::serialize()`（与 bincode 等价，见上一条测试）。
        let expected_message = tx.message.serialize();
        let sig_hex = out.signature.strip_prefix("0x").expect("出参应带 0x");
        let sig: [u8; 64] = hex::decode(sig_hex)
            .expect("签名应是合法 hex")
            .try_into()
            .expect("ed25519 签名应是 64 字节");

        let vk =
            VerifyingKey::from_bytes(from.as_array()).expect("SOL 地址就是 ed25519 公钥本身");
        assert!(
            vk.verify(&expected_message, &DalekSignature::from_bytes(&sig))
                .is_ok(),
            "sign_sol 的签名必须验得过 Message::serialize()；验不过说明签错了字节"
        );

        // 产出：base64 的 bincode Transaction，且签名确实落在槽 0。
        use base64::Engine as _;
        let raw = out.signed_tx.expect("SOL 必须产出 signed_tx");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw)
            .expect("signed_tx 应是合法 base64");
        let signed: solana_transaction::Transaction =
            bincode::deserialize(&bytes).expect("产出应能解回 Transaction");
        assert_eq!(
            signed.signatures[0].as_ref(),
            &sig[..],
            "签名应填进 signatures[0]（SOL 是单签名链）"
        );
        assert_eq!(
            signed.message.serialize(),
            expected_message,
            "重组不应改动 message 本身——改了就签的不是同一笔交易"
        );
    }

    /// 交易缺签名槽时必须报错，而不是 panic。
    #[test]
    fn a_transaction_without_a_signature_slot_is_rejected() {
        use solana_keypair::keypair_from_seed;
        use solana_message::Message;
        use solana_pubkey::Pubkey;
        use solana_system_interface::instruction::transfer;

        let key = StoredKey {
            scheme: crate::store::Scheme::Ed25519,
            seed: [5u8; 32],
        };
        let kp = keypair_from_seed(&key.seed).expect("种子应可重建 Keypair");
        let tx = solana_transaction::Transaction::new_unsigned(Message::new(
            &[transfer(&kp.pubkey(), &Pubkey::new_from_array([0x22; 32]), 1_000)],
            Some(&kp.pubkey()),
        ));
        // 手工清掉签名槽：模拟「调用方给了没有占位签名的交易」。
        let mut empty = tx;
        empty.signatures.clear();
        let txdatahex = hex::encode(bincode::serialize(&empty).expect("应可序列化"));

        let err = sign_sol(&txdatahex, &key).unwrap_err();
        assert!(
            err.to_string().contains("签名槽"),
            "应明确报「缺少签名槽」，实际: {err}"
        );
    }

    /// 端到端：对待签字节签名后，用**公钥验签**必须通过。
    ///
    /// 与上一条的分工不同：上一条证明「我们选的字节串是什么」，
    /// 这一条证明「对这个字节串签出来的签名是有效签名」。
    /// ed25519 对任何字节都能签名，所以「签名成功」本身没有意义——
    /// 只有验签通过才说明签名方确实持有对应私钥。
    #[test]
    fn solana_signature_verifies_against_public_key() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use solana_keypair::keypair_from_seed;
        use solana_message::Message;
        use solana_pubkey::Pubkey;
        use solana_signer::Signer as _;
        use solana_system_interface::instruction::transfer;

        // 与 `keys.rs` 生成逻辑一致：32 字节种子即 ed25519 私钥种子。
        let seed: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let kp = keypair_from_seed(&seed).expect("种子应可重建 Keypair");

        let from = kp.pubkey();
        let to = Pubkey::new_unique();
        let message = Message::new(&[transfer(&from, &to, 1_000)], Some(&from));
        let payload = message.serialize();

        // 走与 `sign_sol` 完全相同的路径：官方 Signer trait 的 `sign_message`。
        let sig = kp.sign_message(&payload);
        // 用**另一条独立实现**（ed25519-dalek）验签，避免用 solana 自己验自己。
        let dalek_sig = Signature::from_bytes(&sig.as_ref().try_into().expect("签名应为 64 字节"));
        let vk = VerifyingKey::from_bytes(kp.pubkey().as_array()).expect("公钥应为 32 字节");
        assert!(
            vk.verify(&payload, &dalek_sig).is_ok(),
            "官方路径签出的 ed25519 签名应能通过独立验签"
        );
    }
