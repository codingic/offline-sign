// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
    use super::*;

    use crate::store::KeyStore;
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

    /// 明确延后的链（应返回 false）。
    const DEFERRED: &[&str] = &["ckb", "fil", "ar", "xxx"];

    // —— 外部真值：`aptos init` 的真实输出 ——
    //
    // 一条 ed25519 私钥，以及由它派生的公钥与四条链的地址。
    // 公钥与 Aptos 地址直接取自官方 CLI 的 `public_key` / `account` 字段；
    // Sui 地址、Sol / NEAR 的 base58 由 Python 独立算得。
    // 详见 `ed25519_addresses_match_a_real_world_vector` 的文档。
    const VECTOR_SEED: &str = "b7d58a41ffb3fb0cbfb813624c40fd7c5dad993865e809aec7697c0a02061d11";
    const VECTOR_PUBKEY: &str = "f02b2e4600d68eca9565026b1e9ad528df287a20fe63d98adc5690284e9649d5";
    const VECTOR_APTOS: &str = "9cc107ca00ed1f08c33ebe2ce1d39b213b755e300c608827e0aa7b3d16c6e78f";
    const VECTOR_SUI: &str = "0x52a34a4797797d9cb33aa49e383288030936fe34649ec8c1b6e981ed7c1bd1cd";
    const VECTOR_SOL: &str = "HAX38bnfz9P7pAbYFgK4o9YLjmYqispBM7M5fDVnDj4G";
    // ICP：上面的 VECTOR_PUBKEY 对应的 self-authenticating principal（独立 Python 复算）。
    const ICP_VECTOR_PRINCIPAL: &str =
        "zaxbn-zrxsg-ovn4s-rqhg2-f2l2q-hafze-olq6l-kzlk3-xh2iq-ajg5y-zqe";

    // 两条**独立算出**的 principal 文本（Python stdlib 复算，不依赖本 crate）：
    // 用来证明 SHA-224(DER) ‖ 0x02 的整条派生链路与 IC 官方一致。
    const ICP_PUBKEY_ZERO_PRINCIPAL: &str =
        "ukev2-6iweo-izmyj-rdxlb-jun6n-nef5z-gk2lp-fuzke-7ghpu-jecqq-iae";
    const ICP_PUBKEY_RFC8032_TV1_PRINCIPAL: &str =
        "e73il-iz5tp-nkgt7-idxyw-ngkah-47bpv-qdase-pzde6-g6vwc-a3eql-jae";

    #[test]
    fn is_supported_matrix() {
        for c in CHAINS {
            assert!(is_supported(c), "期望支持 {c}");
        }
        for c in DEFERRED {
            assert!(!is_supported(c), "期望延后 {c}");
        }
    }

    #[test]
    fn scheme_for_matches_the_two_curves() {
        for c in ["eth", "btc"] {
            assert_eq!(scheme_for(c), Some(Scheme::Secp256k1), "{c}");
        }
        for c in ["sol", "near", "apt", "sui", "ton", "icp"] {
            assert_eq!(scheme_for(c), Some(Scheme::Ed25519), "{c}");
        }
        assert_eq!(scheme_for("ckb"), None);
    }

    #[test]
    fn derive_rejects_unsupported() {
        assert!(derive("ckb", &[1u8; 32]).is_err());
        assert!(derive("not-a-chain", &[1u8; 32]).is_err());
    }

    /// **确定性**：同一种子必须永远派生出同一地址。
    ///
    /// 这条是持久 keystore 成立的前提——每次启动都变的话，上次给出去的地址就失联了。
    #[test]
    fn derivation_is_deterministic() {
        let seed = [7u8; 32];
        for chain in CHAINS {
            let a = derive(chain, &seed).unwrap();
            let b = derive(chain, &seed).unwrap();
            assert_eq!(a.address, b.address, "{chain}: 同种子两次派生地址不同");
            assert_eq!(a.private_key, b.private_key, "{chain}: private_key 不同");
            assert_eq!(a.public_key, b.public_key, "{chain}: public_key 不同");
        }
    }

    /// 不同种子 → 不同地址（否则说明种子压根没参与派生）。
    #[test]
    fn different_seeds_yield_different_addresses() {
        for chain in CHAINS {
            let a = derive(chain, &[1u8; 32]).unwrap();
            let b = derive(chain, &[2u8; 32]).unwrap();
            assert_ne!(a.address, b.address, "{chain}: 不同种子却同地址");
        }
    }

    #[test]
    fn random_seed_produces_valid_keys_every_time() {
        // 抽 20 次，确保 `random_seed` 不会偶发产出非法标量。
        for _ in 0..20 {
            let s = random_seed(Scheme::Secp256k1);
            assert!(k256::ecdsa::SigningKey::from_slice(&s).is_ok());
            let e = random_seed(Scheme::Ed25519);
            let sk = SigningKey::from_bytes(&e);
            let sig = sk.sign(b"probe");
            assert!(sk.verifying_key().verify(b"probe", &sig).is_ok());
        }
    }

    #[test]
    fn derive_store_roundtrip_all_chains() {
        let store = KeyStore::new();
        let seed = [3u8; 32];
        for chain in CHAINS {
            let ki = derive(chain, &seed).unwrap();
            assert!(ki.private_key.starts_with("0x"));
            assert_eq!(ki.private_key.len(), 66, "{chain}: private_key 应为 0x+64hex");
            assert!(!ki.address.is_empty(), "{chain}: 地址不得为空");

            let stored = to_stored(&ki);
            store.insert(&ki.address, stored);
            let got = store.get(&ki.address).expect("应能从密钥库取回");
            assert_eq!(got.seed, ki.seed, "{chain}: 取回的种子不一致");
            assert_eq!(got.scheme, ki.scheme, "{chain}: 取回的算法族不一致");
        }
        // eth 与 btc 共用 secp256k1 那条种子，但派生规则不同（keccak256 vs hash160+
        // bech32），地址不会互撞，也不会与 ed25519 系撞上，故共 CHAINS.len() 条。
        assert_eq!(store.len(), CHAINS.len());
    }

    #[test]
    fn eth_address_format() {
        // 用一条固定种子，保证断言可复现。
        let ki = derive("eth", &[1u8; 32]).unwrap();
        assert!(ki.address.starts_with("0x"));
        assert_eq!(ki.address.len(), 42);
        assert!(ki.address[2..].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ki.address[2..].chars().all(|c| !c.is_ascii_uppercase()));
        assert_eq!(ki.scheme, Scheme::Secp256k1);
    }

    /// ETH 地址与**已知正确结果**对拍：私钥 1 对应的地址是公开常量。
    ///
    /// secp256k1 私钥 = 1 的公钥/地址是教科书级常量，属于外部真值，
    /// 能同时钉住：种子解释方式、非压缩公钥去掉 0x04、keccak256 取后 20 字节。
    /// 期望值来自 Ethereum 常见示例（privkey 0x01 的地址）。
    #[test]
    fn eth_address_matches_a_well_known_constant() {
        let mut seed = [0u8; 32];
        seed[31] = 1; // 大端表示的私钥 1
        let ki = derive("eth", &seed).unwrap();
        // 私钥 1 的公钥：
        // 04 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        //    483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        assert_eq!(
            ki.public_key,
            "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            "公钥与 secp256k1 生成元不符"
        );
        // 对应地址（小写，无 EIP-55 校验和）。
        assert_eq!(
            ki.address, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
            "私钥 1 的地址不符"
        );
    }

    // —— BTC 外部真值 ——
    //
    // 由 /tmp 下的独立 Python 脚本算出（`cryptography` 做 secp256k1 点乘、
    // `hashlib.sha256` + `ripemd160` 做 hash160、手写的 Base58Check 与 BIP173
    // bech32 编码），**不含**本 crate 与 Rust `bitcoin` crate 的任何一行代码。
    //
    // 为什么必须外部对拍而非「两条链地址不同」这类弱断言：地址算错的后果是
    // 资金打到无人控制的地址，不报错、只丢钱，本地所有自校验都会通过。
    /// 私钥 1 的**压缩**公钥（33 字节）。
    const BTC_VECTOR_PUBKEY_1: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// 私钥 1 的主网 **P2WPKH** 地址——本服务暴露的就是这一类。
    const BTC_VECTOR_P2WPKH_1: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    /// 私钥 1 的主网 P2PKH 地址（仅作对照，本服务不签发这类地址）。
    const BTC_VECTOR_P2PKH_1: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    /// 种子 `0x11 * 32` 的压缩公钥。
    const BTC_VECTOR_PUBKEY_11: &str =
        "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    /// 种子 `0x11 * 32` 的主网 P2WPKH 地址。
    const BTC_VECTOR_P2WPKH_11: &str = "bc1ql3e9pgs3mmwuwrh95fecme0s0qtn2880lsvsd5";

    /// BTC 地址与 Python 独立实现逐字符对拍（两个不同种子，防止「碰巧对上」）。
    ///
    /// 一条测试同时钉住四件事：种子解释方式、**压缩**公钥（33 字节而非 65）、
    /// `hash160 = ripemd160(sha256(pubkey))`、以及 bech32 的 hrp `bc` 与 witness v0。
    /// 任一项与主流实现脱钩都会变红。
    #[test]
    fn btc_addresses_match_an_independent_implementation() {
        let mut seed_one = [0u8; 32];
        seed_one[31] = 1;

        let one = derive("btc", &seed_one).unwrap();
        assert_eq!(
            one.public_key,
            format!("0x{BTC_VECTOR_PUBKEY_1}"),
            "btc: 压缩公钥与独立实现不符"
        );
        assert_eq!(one.address, BTC_VECTOR_P2WPKH_1, "btc: P2WPKH 地址不符");
        assert_eq!(one.scheme, Scheme::Secp256k1);

        // 第二个种子：确认不是「只有私钥 1 这一条碰巧对上」。
        let eleven = derive("btc", &[0x11u8; 32]).unwrap();
        assert_eq!(
            eleven.public_key,
            format!("0x{BTC_VECTOR_PUBKEY_11}"),
            "btc: 第二种子的压缩公钥不符"
        );
        assert_eq!(eleven.address, BTC_VECTOR_P2WPKH_11, "btc: 第二种子地址不符");

        // P2PKH 对照：同一个 hash160 走 base58check 是另一串地址。
        //
        // 这条不是凑数——bech32 的 hrp `bc` 与 base58 的版本字节 `0x00` 是
        // **两条独立**的编码路径，两条都对上才能排除「某一侧碰巧一致」。
        // 它同时钉住了 hash160 本身正确、以及派生确实用的是主网。
        let compressed =
            CompressedPublicKey::from_slice(&hex::decode(BTC_VECTOR_PUBKEY_1).unwrap()).unwrap();
        assert_eq!(
            Address::p2pkh(compressed.pubkey_hash(), Network::Bitcoin).to_string(),
            BTC_VECTOR_P2PKH_1,
            "btc: 同一 hash160 的 P2PKH 地址不符（说明 hash160 或网络不对）"
        );
        assert_ne!(
            BTC_VECTOR_P2PKH_1, BTC_VECTOR_P2WPKH_1,
            "两类地址必须不同，否则上面那条对照就是空的"
        );
    }

    /// BTC 地址格式：主网原生隔离见证（`bc1q` 开头，42 字符）。
    ///
    /// 这里刻意**不**断言字符集：bech32 只允许小写且禁用 `1/b/i/o`，
    /// 与其自己写规则，不如交给上面的真值对拍去钉。
    #[test]
    fn btc_address_format() {
        let ki = derive("btc", &[1u8; 32]).unwrap();
        assert!(ki.address.starts_with("bc1q"), "地址应为 P2WPKH: {}", ki.address);
        assert_eq!(ki.address.len(), 42, "P2WPKH 地址固定 42 字符");
        // 压缩公钥：`0x` + 66 个 hex 字符（33 字节）。
        assert_eq!(ki.public_key.len(), 68, "public_key 应为 0x+66hex");
        assert_eq!(ki.scheme, Scheme::Secp256k1);
    }

    /// **反证**：BTC 与 ETH 共用同一把 secp256k1 私钥，但地址与公钥编码都必须不同。
    ///
    /// 没有这条，上面两条可能在「BTC 直接复用了 ETH 的派生逻辑」的情况下恒真——
    /// 那正是最容易犯的错：两条链都是 secp256k1，抄一遍就能跑，只是地址全错。
    #[test]
    fn btc_and_eth_share_the_seed_but_not_the_address_or_encoding() {
        let seed = [5u8; 32];
        let btc = derive("btc", &seed).unwrap();
        let eth = derive("eth", &seed).unwrap();

        // 同一把私钥 —— 种子必然相同。
        assert_eq!(btc.seed, eth.seed);
        // 但地址不同（keccak256 取后 20 字节 vs hash160 + bech32）。
        assert_ne!(btc.address, eth.address, "btc 与 eth 地址不应相同");
        // 公钥长度也不同：BTC 用压缩（33 字节），ETH 用非压缩（65 字节）。
        assert_ne!(
            btc.public_key.len(),
            eth.public_key.len(),
            "BTC 应为压缩公钥、ETH 为非压缩，长度必须不同"
        );
        // P2WPKH 与 P2PKH 是两套地址，本服务只出 P2WPKH
        // （P2PKH 是 2017 年前的遗留类型，走另一套 sighash 算法）。
        assert!(
            !btc.address.starts_with('1'),
            "不应输出 P2PKH 地址: {}",
            btc.address
        );
    }

    #[test]
    fn ed25519_seed_keypair_is_real_and_verifiable() {
        let seed = [9u8; 32];
        for chain in ["sol", "near", "apt", "sui", "ton", "icp"] {
            let ki = derive(chain, &seed).unwrap();
            assert_eq!(ki.scheme, Scheme::Ed25519);

            let sk = SigningKey::from_bytes(&ki.seed);
            let vk = VerifyingKey::from(&sk);
            let sig = sk.sign(b"allchain-offline-signer-self-check");
            assert!(vk.verify(b"allchain-offline-signer-self-check", &sig).is_ok());

            if chain != "sol" {
                let pk_hex = ki.public_key.trim_start_matches("0x");
                let pk_bytes = hex::decode(pk_hex).expect("public_key 应为 hex");
                assert_eq!(pk_bytes, vk.to_bytes().to_vec(), "{chain}: public_key 与种子公钥不一致");
            }
        }
    }

    /// **ed25519 四链地址与真实世界向量对拍**（私钥 → 公钥 → 各链地址）。
    ///
    /// 数据来源：`aptos init` 实际跑出来的输出（私钥 / 公钥 / 账户地址三元组），
    /// 再用 Python（`cryptography` + `hashlib` + `base58`）独立复算确认过一遍。
    /// 属于外部真值，不依赖本实现的任何一行代码。
    ///
    /// 为什么必须用它而不是「两个地址不相等」那种弱断言：后者在**两个都算错**时依然通过。
    /// 实测确实如此——变异测试里「Aptos 丢掉 0x00 后缀」「Sui 把标志字节挪到后面」
    /// 这两个变异体在弱断言下存活了，只有真值对拍才抓得住。
    /// 地址算错的后果是资金打到无人控制的地址，不报错、只丢钱。
    ///
    /// 顺带钉住那个最容易写反的坑：Aptos 是 `sha3_256(公钥 ‖ 0x00)`，
    /// Sui 是 `blake2b_256(0x00 ‖ 公钥)`——**哈希不同，标志字节的位置也相反**。
    #[test]
    fn ed25519_addresses_match_a_real_world_vector() {
        let seed: [u8; 32] = hex::decode(VECTOR_SEED)
            .expect("向量种子应为 hex")
            .try_into()
            .expect("向量种子应为 32 字节");

        // 公钥：与 Aptos CLI 输出的 `public_key` 字段一致。
        let pubkey = format!("0x{VECTOR_PUBKEY}");
        for chain in ["apt", "sui", "ton", "icp"] {
            assert_eq!(
                derive(chain, &seed).unwrap().public_key,
                pubkey,
                "{chain}: 公钥与真实向量不符"
            );
        }

        assert_eq!(
            derive("apt", &seed).unwrap().address,
            format!("0x{}", VECTOR_APTOS.trim_start_matches("0x")),
            "apt: 地址与 Aptos CLI 的 account 字段不符"
        );
        assert_eq!(
            derive("sui", &seed).unwrap().address,
            VECTOR_SUI,
            "sui: 地址不符"
        );
        // ICP：地址即 self-authenticating principal，同样来自独立 Python 复算（见 ICP_VECTOR_PRINCIPAL）。
        assert_eq!(
            derive("icp", &seed).unwrap().address,
            ICP_VECTOR_PRINCIPAL,
            "icp: principal 与独立实现不符（SHA-224(DER) ‖ 0x02 + CRC32 + base32）"
        );

        // SOL 与 NEAR 共用 base58 编码，只是 NEAR 多了 `ed25519:` 前缀。
        assert_eq!(derive("sol", &seed).unwrap().address, VECTOR_SOL, "sol: 地址不符");
        assert_eq!(
            derive("near", &seed).unwrap().address,
            format!("ed25519:{VECTOR_SOL}"),
            "near: 隐式账户地址不符"
        );
        assert_eq!(
            derive("sol", &seed).unwrap().public_key,
            VECTOR_SOL,
            "sol: 公钥展示用 base58"
        );

        // 两个地址必须不同（同一公钥、不同哈希 + 不同标志位置）。
        assert_ne!(
            derive("apt", &seed).unwrap().address,
            derive("sui", &seed).unwrap().address
        );
    }

    /// 非法 secp256k1 种子（全零）必须报错，不能默默产出废钥。
    #[test]
    fn an_invalid_secp256k1_seed_is_rejected() {
        assert!(derive("eth", &[0u8; 32]).is_err(), "全零不是合法 secp256k1 私钥");
        // 全 ff 大于曲线阶，同样非法。
        assert!(derive("eth", &[0xffu8; 32]).is_err(), "≥ 阶的标量非法");
    }

    #[test]
    fn scheme_assignment() {
        assert_eq!(derive("eth", &[1u8; 32]).unwrap().scheme, Scheme::Secp256k1);
        for chain in ["sol", "near", "apt", "sui", "ton", "icp"] {
            assert_eq!(derive(chain, &[1u8; 32]).unwrap().scheme, Scheme::Ed25519);
        }
    }

    /// **ICP principal 文本编码对照 IC 官方 `ic_principal` 的三个外部向量**。
    ///
    /// 这三个向量是 IC 规范里的「已知真值」，与 SHA-224 / DER / 0x02 都无关，
    /// 纯粹钉死**文本编码**这一步：`base32(CRC32(blob) ‖ blob)` + 每 5 字符插 `-`。
    /// 任意一处算错（CRC 多项式、base32 字母表、是否补填充、分隔符位置），这条都会红。
    ///
    /// - `""` → 管理 canister `aaaaa-aa`
    /// - `[0x04]` → 匿名 principal `2vxsx-fae`
    /// - 测试 blob → `2chl6-4hpzw-vqaaa-aaaaa-c`
    #[test]
    fn icp_principal_encoding_matches_spec() {
        assert_eq!(principal_to_text(&[]), "aaaaa-aa", "管理 canister 编码不符");
        assert_eq!(principal_to_text(&[0x04]), "2vxsx-fae", "匿名 principal 编码不符");
        assert_eq!(
            principal_to_text(&[0xef, 0xcd, 0xab, 0, 0, 0, 0, 0, 1]),
            "2chl6-4hpzw-vqaaa-aaaaa-c",
            "IC 测试 blob 编码不符"
        );
    }

    /// **ICP self-authenticating principal 对照独立实现（Python stdlib 复算）**。
    ///
    /// 这条把完整的派生链路——`DER(pubkey)`（RFC 8410 SPKI）→ `SHA-224` → `‖ 0x02`
    /// → `CRC32 + base32 + 分隔符`——一次性钉死。期望值由 Python 的 `hashlib.sha224`
    /// + `zlib.crc32` + `base64.b32encode` 独立算得，**不依赖本 crate 的任何一行**，
    ///   排除「自己算自己对照」的恒真风险。
    ///
    /// 两个公钥分别取「全零」与「RFC 8032 测试向量 1 的公钥」，防止只碰巧对一个。
    #[test]
    fn icp_principal_matches_independent_implementation() {
        let zero = [0u8; 32];
        assert_eq!(
            icp_principal_text(&zero),
            ICP_PUBKEY_ZERO_PRINCIPAL,
            "全零公钥的 principal 与独立实现不符"
        );
        let rfc = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .expect("RFC8032 测试向量公钥应为 hex");
        let rfc: [u8; 32] = rfc.try_into().expect("应为 32 字节");
        assert_eq!(
            icp_principal_text(&rfc),
            ICP_PUBKEY_RFC8032_TV1_PRINCIPAL,
            "RFC8032 测试向量公钥的 principal 与独立实现不符"
        );
    }

    /// `derive("icp", seed)` 产出的 principal 必须满足 IC 文本格式自洽：
    /// 反解 base32 得到的 blob，其 CRC32 必须等于前缀的 4 字节校验和。
    /// 这样即便将来挪动某段编码，也能立刻抓到「principal 文本无法被 IC 解析」的坏改动。
    #[test]
    fn icp_address_is_self_consistent_principal_text() {
        let seed = [3u8; 32];
        let addr = derive("icp", &seed).unwrap().address;
        // 去掉分隔符并大写，走标准 RFC4648 base32 解码。
        let compact: String = addr.chars().filter(|c| *c != '-').map(|c| c.to_ascii_uppercase()).collect();
        let bytes = base32_decode(compact.as_bytes()).expect("principal 必须是合法 base32");
        assert!(bytes.len() > 4, "principal 文本过短");
        let (crc, blob) = bytes.split_at(4);
        let expected = crc32fast::hash(blob).to_be_bytes();
        assert_eq!(crc, &expected[..], "principal 的 CRC32 校验和与 blob 不匹配");
    }
