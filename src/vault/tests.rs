// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
    use super::*;

    // ——— 外部真值 ———
    //
    // 下面所有 `TV_*` 常量都由 /tmp/gen_vectors.py 用**独立实现**算出：
    //   - AES-256-GCM : Python `cryptography`（OpenSSL 后端）
    //   - Argon2id    : Python `argon2-cffi`（官方 C 参考实现 libargon2 的绑定）
    //   - blake2b     : Python `hashlib`
    //
    // 为什么不用本实现自己算的值当期望：**自证无效**。实现算错时测试会跟着错，
    // 永远绿。只有与不含共享代码的第三方实现对上，才说明兼容性是真的。
    // （实际发生过：我凭记忆写的 GCM 向量是错的，正是这一步抓出来的。）

    /// 全零 32 字节密钥。
    const TV_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    /// 全零 12 字节 nonce。
    const TV_NONCE: &str = "AAAAAAAAAAAAAAAA";
    /// OpenSSL 对 `key/nonce/AAD + 32 个 0x11` 的输出（含尾部 16 字节 tag）。
    const TV_CIPHERTEXT: &str = "37ZRLFxxen8WX9TCq+KMCWNxEtsmtztlwLPkn2QXJJ8axEZj13ts5rGCPo0rM5zD";
    /// 固定盐（`00 01 02 … 0f`），只为让向量可复现；真实文件用随机盐。
    const TV_SALT: &str = "AAECAwQFBgcICQoLDA0ODw==";
    /// libargon2 对 `PW + TV_SALT + (m=19456, t=2, p=1, len=64)` 的输出。
    const TV_MASTER: &str = "c948a1912c7c128e9156e3a94722a5366e6c62f33a082f77f46eb57bc1bad034420feff9f780f2b13b889f7a6dcf263da5a4310898aa51ff4de932e6a0adcd11";
    /// `blake2b_256("allchain-sign-verifier" ‖ mac_key)`，其中 mac_key = master[32..]。
    const TV_VERIFIER: &str = "VwGsYYfs63nDBLAIcnQ4pe+ngNJD4aJqiCtVO9BXJeo=";
    const TV_PLAINTEXT: [u8; 32] = [0x11u8; 32];

    /// 一段口令，仅测试用（与 /tmp/gen_vectors.py 里的一致）。
    const PW: &str = "correct horse battery staple";

    /// 打开一个临时目录（测试专用，进程退出后由 OS 清理）。
    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sign-vault-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// 第一轮：目录为空。
    #[test]
    fn empty_dir_then_creating_both_files_yields_complete_state() {
        let d = tmpdir("empty");
        assert_eq!(state(&d), DirState::Empty);

        let (vault, reports) = open_or_fill(&d, PW).unwrap();
        assert_eq!(state(&d), DirState::Complete);
        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|r| r.created), "首次应两个都新建");

        // 两条种子必须不同（否则说明两条曲线共用了同一份随机数）。
        assert_ne!(
            vault.seed_for(Scheme::Secp256k1),
            vault.seed_for(Scheme::Ed25519)
        );
        fs::remove_dir_all(&d).unwrap();
    }

    /// 核心正确性：**幂等**。同口令二次打开必须解出同一批种子。
    ///
    /// 这条测试守的是「重新生成即丢币」这条底线。
    #[test]
    fn reopening_with_the_same_password_returns_the_same_seeds() {
        let d = tmpdir("idempotent");
        let (first, _) = open_or_fill(&d, PW).unwrap();
        let secp1 = *first.seed_for(Scheme::Secp256k1);
        let ed1 = *first.seed_for(Scheme::Ed25519);
        drop(first);

        let (second, reports) = open_or_fill(&d, PW).unwrap();
        assert_eq!(*second.seed_for(Scheme::Secp256k1), secp1, "secp256k1 种子变了");
        assert_eq!(*second.seed_for(Scheme::Ed25519), ed1, "ed25519 种子变了");
        assert!(reports.iter().all(|r| !r.created), "第二次不应再新建");
        fs::remove_dir_all(&d).unwrap();
    }

    /// 二次打开时，两个 keystore 文件必须**一字不动**。
    ///
    /// 领域说明：这是上面那条幂等测试的补强，两者抓的缺陷不同。
    /// 幂等测试比的是**种子**，而「解开成功后又重新加密写一遍盘」这个变异体
    /// 种子完全不变、那条测试照样绿——但文件其实被换掉了。
    /// 换掉文件的后果比看起来的严重：新密文出自一次全新的加密，
    /// 若那次加密的参数与当前口令有任何偏差（或写盘中途失败留下截断文件），
    /// 用户就永久失去私钥，且现象是「昨天还好好的，今天打不开了」。
    ///
    /// 为什么字节级比对能抓住它：keystore 的 salt 与 nonce 每次加密都随机，
    /// 只要真的走过一次「生成新私钥并写盘」，字节**必然**改变。
    /// 换句话说，「字节不变」等价于「一次加密都没发生过」。
    #[test]
    fn reopening_rewrites_nothing_on_disk() {
        let d = tmpdir("no-rewrite");
        let (first, _) = open_or_fill(&d, PW).unwrap();
        drop(first);

        // `.collect()` 而非留着迭代器：下面要拿它和「之后」比对，
        // 迭代器是惰性的，留着它会在比对时才去读第二次的文件。
        let before: Vec<Vec<u8>> = Scheme::ALL
            .iter()
            .map(|s| fs::read(path_for(&d, *s)).unwrap())
            .collect();

        let (second, reports) = open_or_fill(&d, PW).unwrap();
        drop(second);
        assert!(reports.iter().all(|r| !r.created), "第二次不应再新建");

        for (i, scheme) in Scheme::ALL.iter().enumerate() {
            let name = scheme.as_str();
            let after = fs::read(path_for(&d, *scheme)).unwrap();
            assert_eq!(
                after, before[i],
                "{name}: 二次打开后文件字节变了（说明重新加密写过盘）"
            );
        }
        fs::remove_dir_all(&d).unwrap();
    }

    /// 口令错必须报 `WrongPassword`，且**绝不能**顺手重新生成（否则等于静默换密钥）。
    #[test]
    fn wrong_password_is_reported_and_does_not_recreate_keys() {
        let d = tmpdir("wrongpw");
        let (vault, _) = open_or_fill(&d, PW).unwrap();
        let secp_before = *vault.seed_for(Scheme::Secp256k1);
        let ciphertext_before = fs::read_to_string(path_for(&d, Scheme::Secp256k1)).unwrap();
        drop(vault);

        let err = open_or_fill(&d, "not-the-password").unwrap_err();
        assert!(err.is_wrong_password(), "期望 WrongPassword，实际: {err}");

        // 文件一字未动——若被覆盖，用户再试对口令也拿不回原密钥。
        assert_eq!(
            fs::read_to_string(path_for(&d, Scheme::Secp256k1)).unwrap(),
            ciphertext_before,
            "口令错不应改动 keystore 文件"
        );
        // 用对口令仍能取回原种子。
        let (again, _) = open_or_fill(&d, PW).unwrap();
        assert_eq!(*again.seed_for(Scheme::Secp256k1), secp_before);
        fs::remove_dir_all(&d).unwrap();
    }

    /// 篡改密文 → 报 `Corrupt`，**不是** `WrongPassword`。
    ///
    /// 这正是分两层校验的唯一目的：两种失败的处置方式相反，报错不能混。
    #[test]
    fn tampered_ciphertext_is_reported_as_corrupt_not_wrong_password() {
        let d = tmpdir("tamper-ct");
        open_or_fill(&d, PW).unwrap();

        let path = path_for(&d, Scheme::Ed25519);
        let mut file: KeystoreFile = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        // 翻转密文第一个字节。verifier 不绑定密文，故校验值仍会通过，
        // 倒在第二道 GCM 认证上——正是期望的分层行为。
        let mut ct = base64_decode(&file.ciphertext, "ciphertext").unwrap();
        ct[0] ^= 0x01;
        file.ciphertext = base64_encode(&ct);
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();

        let err = open_or_fill(&d, PW).unwrap_err();
        assert!(
            matches!(err, VaultError::Corrupt(_)),
            "期望 Corrupt，实际: {err}"
        );
        assert!(!err.is_wrong_password(), "损坏绝不能被当成口令错");
        fs::remove_dir_all(&d).unwrap();
    }

    /// 改盐 → verifier 不匹配 → 报 `WrongPassword`（模块文档「已知边界」里记过的行为）。
    ///
    /// 把「我们接受什么」钉死，将来若有人想加完整性字段，这条测试会提醒他改语义。
    #[test]
    fn tampered_salt_reports_wrong_password() {
        let d = tmpdir("tamper-salt");
        open_or_fill(&d, PW).unwrap();

        let path = path_for(&d, Scheme::Secp256k1);
        let mut file: KeystoreFile = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let mut salt = base64_decode(&file.kdf.salt, "salt").unwrap();
        salt[0] ^= 0x01;
        file.kdf.salt = base64_encode(&salt);
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();

        let err = open_or_fill(&d, PW).unwrap_err();
        assert!(err.is_wrong_password(), "期望 WrongPassword，实际: {err}");
        fs::remove_dir_all(&d).unwrap();
    }

    /// AAD 绑定：把文件里的 `scheme` 改掉，解密必须失败。
    ///
    /// 没有这条绑定，改 scheme 会**解密成功**，然后 32 字节种子被按错误曲线解释，
    /// 表现为「能签名但节点永远拒绝」——比直接失败难查得多。
    #[test]
    fn aad_binds_the_scheme_field() {
        let d = tmpdir("aad");
        open_or_fill(&d, PW).unwrap();

        let path = path_for(&d, Scheme::Ed25519);
        let body = fs::read_to_string(&path).unwrap();
        let mut file: KeystoreFile = serde_json::from_str(&body).unwrap();

        // 直接改字段：scheme 变成 secp256k1，AAD 随之改变 → GCM 认证失败。
        file.scheme = Scheme::Secp256k1;
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();

        let err = decrypt_seed(PW, &file).unwrap_err();
        assert!(
            matches!(err, VaultError::Corrupt(_)),
            "改了 scheme 必须解密失败，实际: {err}"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    /// 两个文件必须用**不同的盐**——共用盐等于放弃域分离。
    #[test]
    fn the_two_files_use_different_salts_and_nonces() {
        let d = tmpdir("distinct");
        open_or_fill(&d, PW).unwrap();
        let a: KeystoreFile =
            serde_json::from_str(&fs::read_to_string(path_for(&d, Scheme::Secp256k1)).unwrap()).unwrap();
        let b: KeystoreFile =
            serde_json::from_str(&fs::read_to_string(path_for(&d, Scheme::Ed25519)).unwrap()).unwrap();
        assert_ne!(a.kdf.salt, b.kdf.salt, "两个文件共用了盐");
        assert_ne!(a.cipher.nonce, b.cipher.nonce, "两个文件共用了 nonce");
        fs::remove_dir_all(&d).unwrap();
    }

    /// 磁盘上绝不出现种子明文（hex 形式）。
    #[test]
    fn the_seed_never_appears_in_plaintext_on_disk() {
        let d = tmpdir("plaintext");
        let (vault, _) = open_or_fill(&d, PW).unwrap();
        let secp = *vault.seed_for(Scheme::Secp256k1);
        let ed = *vault.seed_for(Scheme::Ed25519);
        for scheme in Scheme::ALL {
            let body = fs::read_to_string(path_for(&d, scheme)).unwrap();
            let hexes = [hex::encode(secp), hex::encode(ed)];
            for h in hexes {
                assert!(!body.contains(&h), "{:?} 文件里出现了种子明文", scheme);
            }
        }
        fs::remove_dir_all(&d).unwrap();
    }

    /// keystore 文件权限应为 0600（Unix）。
    #[test]
    #[cfg(unix)]
    fn keystore_files_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("perms");
        open_or_fill(&d, PW).unwrap();
        for scheme in Scheme::ALL {
            let meta = fs::metadata(path_for(&d, scheme)).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{:?} 权限是 {mode:o}，应为 600", scheme);
        }
        fs::remove_dir_all(&d).unwrap();
    }

    /// 部分缺失（只删一个文件）→ 状态为 Partial，再用同口令打开会**只补那一个**，
    /// 另一个保持原值。这是从备份只恢复了一半时的真实场景。
    #[test]
    fn a_missing_file_is_refilled_while_the_other_survives() {
        let d = tmpdir("partial");
        let (first, _) = open_or_fill(&d, PW).unwrap();
        let secp_before = *first.seed_for(Scheme::Secp256k1);
        drop(first);

        fs::remove_file(path_for(&d, Scheme::Ed25519)).unwrap();
        assert_eq!(state(&d), DirState::Partial);

        let (vault, reports) = open_or_fill(&d, PW).unwrap();
        assert_eq!(*vault.seed_for(Scheme::Secp256k1), secp_before, "原有的被改了");
        let created: Vec<_> = reports.iter().filter(|r| r.created).map(|r| r.scheme).collect();
        assert_eq!(created, vec![Scheme::Ed25519], "应只补 ed25519 那一个");
        fs::remove_dir_all(&d).unwrap();
    }

    /// 版本/算法名不认识 → `Other`（连口令都不该去试）。
    #[test]
    fn unknown_version_or_algorithm_is_rejected_before_touching_the_password() {
        let d = tmpdir("version");
        open_or_fill(&d, PW).unwrap();
        let path = path_for(&d, Scheme::Secp256k1);
        let mut file: KeystoreFile = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

        file.version = 999;
        assert!(matches!(
            decrypt_seed(PW, &file).unwrap_err(),
            VaultError::Other(_)
        ));

        file.version = KEYSTORE_VERSION;
        file.kdf.name = "pbkdf2".to_string();
        assert!(matches!(
            decrypt_seed(PW, &file).unwrap_err(),
            VaultError::Other(_)
        ));

        file.kdf.name = "argon2id".to_string();
        file.cipher.name = "chacha20-poly1305".to_string();
        assert!(matches!(
            decrypt_seed(PW, &file).unwrap_err(),
            VaultError::Other(_)
        ));
        fs::remove_dir_all(&d).unwrap();
    }

    /// 文件名与内容里的 scheme 不符 → 报错，不猜。
    #[test]
    fn scheme_in_a_file_must_match_its_file_name() {
        let d = tmpdir("mismatch");
        open_or_fill(&d, PW).unwrap();
        // 把 ed25519 的内容抄到 secp256k1 的路径上（只改路径、不改内容）。
        let src = fs::read_to_string(path_for(&d, Scheme::Ed25519)).unwrap();
        fs::write(path_for(&d, Scheme::Secp256k1), src).unwrap();

        let err = open_or_fill(&d, PW).unwrap_err();
        assert!(
            matches!(err, VaultError::Corrupt(_)),
            "scheme 与文件名不符应报 Corrupt，实际: {err}"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    /// `Debug` 输出不能带私钥——日志和崩溃回溯都走这条路。
    #[test]
    fn debug_output_never_leaks_the_seeds() {
        let d = tmpdir("debug");
        let (vault, _) = open_or_fill(&d, PW).unwrap();
        let out = format!("{:?}", vault);
        assert!(!out.contains(&hex::encode(*vault.seed_for(Scheme::Secp256k1))));
        assert!(!out.contains(&hex::encode(*vault.seed_for(Scheme::Ed25519))));
        assert!(out.contains("32 bytes"), "Debug 应保留长度信息: {out}");
        fs::remove_dir_all(&d).unwrap();
    }

    /// secp256k1 种子必须是**合法标量**（能构造出 SigningKey）。
    ///
    /// 这是把「不能赌 2^-128」变成可执行断言：生成路径用的是 `SigningKey::random`，
    /// 它保证落在 `[1, n-1]`；这里反过来验证存下来的种子确实能被接受。
    #[test]
    fn generated_secp256k1_seed_is_a_valid_scalar() {
        let d = tmpdir("scalar");
        let (vault, _) = open_or_fill(&d, PW).unwrap();
        let seed = vault.seed_for(Scheme::Secp256k1);
        // `from_slice` 对全零、≥ 阶的值都会报错。
        assert!(
            k256::ecdsa::SigningKey::from_slice(seed).is_ok(),
            "生成的 secp256k1 种子不是合法私钥"
        );
        // 顺带确认它真能签名、且签名能验过，而不是仅仅「能被解析」。
        // `Signer` 必须标注签名类型：`SigningKey` 同时实现了
        // `Signer<Signature>` 和 `Signer<(Signature, RecoveryId)>` 等多个 impl，
        // 不写类型会撞 E0283——这不是啰嗦，是 trait 设计上就要求调用方选一种。
        use k256::ecdsa::{Signature, signature::{Signer as _, Verifier as _}};
        let sk = k256::ecdsa::SigningKey::from_slice(seed).unwrap();
        let vk = sk.verifying_key();
        let sig: Signature = sk.sign(b"probe");
        assert!(vk.verify(b"probe", &sig).is_ok(), "签出的签名验不过");
        fs::remove_dir_all(&d).unwrap();
    }

    /// ed25519 种子同样能被官方构造接受，且签出的签名能验过。
    #[test]
    fn generated_ed25519_seed_is_usable() {
        use ed25519_dalek::{Signer, Verifier};
        let d = tmpdir("ed25519");
        let (vault, _) = open_or_fill(&d, PW).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(vault.seed_for(Scheme::Ed25519));
        let vk = sk.verifying_key();
        let sig = sk.sign(b"probe");
        assert!(vk.verify(b"probe", &sig).is_ok());
        fs::remove_dir_all(&d).unwrap();
    }

    /// 不同口令 → 不同主密钥（否则口令形同虚设）。
    #[test]
    fn different_passwords_produce_different_keys() {
        let d = tmpdir("twopw");
        let (a, _) = open_or_fill(&d, "password-a").unwrap();
        let sa = *a.seed_for(Scheme::Secp256k1);
        drop(a);
        fs::remove_dir_all(&d).unwrap();

        let d2 = tmpdir("twopw2");
        let (b, _) = open_or_fill(&d2, "password-b").unwrap();
        assert_ne!(*b.seed_for(Scheme::Secp256k1), sa);
        fs::remove_dir_all(&d2).unwrap();
    }

    /// 空口令与超短口令：本层不设政策（由 CLI 提示层管），但必须不崩、能正常往返。
    ///
    /// 把「不设政策」写明，避免后人以为是漏了校验。
    #[test]
    fn an_empty_password_still_round_trips() {
        let d = tmpdir("emptypw");
        let (vault, _) = open_or_fill(&d, "").unwrap();
        let seed = *vault.seed_for(Scheme::Secp256k1);
        drop(vault);
        let (again, _) = open_or_fill(&d, "").unwrap();
        assert_eq!(*again.seed_for(Scheme::Secp256k1), seed);

        // 非空口令打不开空口令建的文件——证明空口令也真的参与了派生。
        assert!(open_or_fill(&d, "x").unwrap_err().is_wrong_password());
        fs::remove_dir_all(&d).unwrap();
    }

    /// base64 解码失败要带上字段名。
    #[test]
    fn base64_errors_name_the_field() {
        let e = base64_decode("!!!not-base64!!!", "verifier").unwrap_err();
        assert!(e.to_string().contains("verifier"), "错误信息应指出字段: {e}");
    }

    /// 校验值长度不等时返回 false（而非 panic 或越界）。
    #[test]
    fn verifier_comparison_tolerates_length_mismatch() {
        assert!(!verifier_matches(&[1u8; 32], &[1u8; 31]));
        assert!(verifier_matches(&[7u8; 32], &[7u8; 32]));
        assert!(!verifier_matches(&[7u8; 32], &[8u8; 32]));
    }

    // ——— 外部真值 2：AES-256-GCM 与 Python cryptography 对拍 ———

    /// 用固定 key/nonce/AAD 加密固定明文，与 OpenSSL 产出逐字节比对。
    ///
    /// 一条测试同时钉住三件事：密文构造、tag 追加在尾部（48 = 32 明文 + 16 tag）、
    /// AAD 的传入方式。任一项与主流实现脱钩都会变红。
    #[test]
    fn aes_gcm_matches_an_independent_implementation() {
        // 不用 `Key::from_slice`（generic-array 0.14 已废弃），改用 `From<[u8; 32]>`：
        // 定长数组进、定长数组出，长度不符在编译期/转换期就暴露，不靠运行时切片。
        let key_bytes: [u8; 32] = base64_decode(TV_KEY, "key").unwrap().try_into().unwrap();
        let key = Key::<Aes256Gcm>::from(key_bytes);
        let nonce_bytes: [u8; NONCE_LEN] =
            base64_decode(TV_NONCE, "nonce").unwrap().try_into().unwrap();
        let nonce = Nonce::from(nonce_bytes);
        let aad = aad(KEYSTORE_VERSION, Scheme::Secp256k1);

        let cipher = Aes256Gcm::new(&key);
        let ct = cipher
            .encrypt(&nonce, Payload { msg: &TV_PLAINTEXT, aad: &aad })
            .unwrap();

        assert_eq!(base64_encode(&ct), TV_CIPHERTEXT, "与 OpenSSL 的输出不一致");
        assert_eq!(ct.len(), 48, "应为 32 字节密文 + 16 字节 tag");

        // 反解：确认向量不是「单向碰巧对上」。
        let pt = cipher
            .decrypt(&nonce, Payload { msg: &ct, aad: &aad })
            .unwrap();
        assert_eq!(pt, TV_PLAINTEXT.to_vec());

        // AAD 改动必须解密失败。少了这条，上面的比对可能只是碰巧——
        // 它证明 AAD 真的参与了认证，而不是被忽略后仍算出同一密文。
        let mut other = aad.clone();
        other.push(b'x');
        assert!(
            cipher
                .decrypt(&nonce, Payload { msg: &ct, aad: &other })
                .is_err(),
            "AAD 改动后仍能解密，说明 AAD 没生效"
        );
    }

    /// Argon2id 与官方 C 参考实现（libargon2）对拍。
    ///
    /// 这条同时钉住算法变体（id 而非 i/d）、版本（0x13）、m/t/p 的单位
    /// （m_cost 是 **KiB** 不是字节——写错会差 1024 倍且照样能跑），以及输出长度。
    #[test]
    fn argon2id_matches_the_official_reference_implementation() {
        let params = KdfParams {
            name: "argon2id".to_string(),
            salt: TV_SALT.to_string(),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
            output_len: MASTER_LEN as u32,
        };
        let master = derive_master(PW.as_bytes(), &params).unwrap();
        assert_eq!(hex::encode(master.as_slice()), TV_MASTER);
    }

    /// 校验值与 Python `hashlib.blake2b` 对拍：钉住前缀字符串与 mac_key 的切片位置。
    ///
    /// `mac_key = master[32..64]` 这一刀切错位置（比如写成 `master[..32]`）
    /// 不会报错，只会让校验值恒不匹配——表现为「永远提示口令错」。
    #[test]
    fn verifier_matches_an_independent_implementation() {
        let master = hex::decode(TV_MASTER).unwrap();
        assert_eq!(master.len(), MASTER_LEN);
        let mac_key = &master[32..];
        assert_eq!(base64_encode(&verifier_for(mac_key).unwrap()), TV_VERIFIER);
    }

    /// 校验值**不依赖密文**（模块文档第 2 点的可执行断言）。
    ///
    /// 若有人为了「更安全」把密文也喂进 verifier，这条会红——
    /// 因为那样做之后，密文损坏会被误报成口令错，白分的两层又合回一层。
    #[test]
    fn the_verifier_does_not_depend_on_the_ciphertext() {
        let master = hex::decode(TV_MASTER).unwrap();
        let v1 = verifier_for(&master[32..]).unwrap();

        // 密文怎么变都不影响校验值：用一个全新的密文再算一次。
        let file = encrypt_seed(PW, Scheme::Ed25519, &[9u8; SEED_LEN]).unwrap();
        let master2 = derive_master(PW.as_bytes(), &file.kdf).unwrap();
        let _ = &file.ciphertext; // 密文参与了文件，但不参与校验值
        let v2 = verifier_for(&master2[32..]).unwrap();

        // 两个文件的盐不同 → 校验值本就不同；这里要验证的是**计算不含密文**：
        // 同一份 master 下，改密文前后 verifier 必须一字不变。
        let mut tampered = file.clone();
        let mut ct = base64_decode(&tampered.ciphertext, "ciphertext").unwrap();
        ct[0] ^= 0xff;
        tampered.ciphertext = base64_encode(&ct);
        let master3 = derive_master(PW.as_bytes(), &tampered.kdf).unwrap();
        let v3 = verifier_for(&master3[32..]).unwrap();

        assert_eq!(
            base64_encode(&v2),
            base64_encode(&v3),
            "改了密文校验值却变了 —— 会把「文件损坏」误报成「口令错」"
        );
        // v1 用固定盐，与随机盐的 v2 不同，这条只是确认盐确实生效。
        assert_ne!(base64_encode(&v1), base64_encode(&v2));
    }
