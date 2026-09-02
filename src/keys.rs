//! 密钥派生与地址计算。
//!
//! # 定位的变化（重要）
//!
//! 早期版本里 `generate(chain)` 每次调用都现生成一把新私钥——那是**错的**：
//! 用户拿到的地址是一次性的，转进去的资产再也无法控制。
//! 现在私钥来自 `vault` 模块在启动时用口令解开的两条持久种子（secp256k1 / ed25519 各一），
//! 本模块只负责「**给定种子，算出这条链的地址**」这一个纯函数式职责。
//!
//! 保留 `generate()` 仅作随机种子发生器（内部用），对外入口是 [`derive`]。
//!
//! # 为什么「两条种子覆盖全部链」
//!
//! 地址是公钥的派生物，同一把私钥在不同链上派生出的地址天然不同，互不冲突：
//!
//! | 曲线 | 覆盖的链 | 地址规则 |
//! |---|---|---|
//! | secp256k1 | eth | `keccak256(非压缩公钥[1:])[12:]` |
//! | secp256k1 | btc | `bech32(hash160(压缩公钥))`（P2WPKH，主网 `bc1q…`） |
//! | ed25519 | sol | base58(公钥) |
//! | ed25519 | near | `ed25519:<base58(公钥)>`（隐式账户） |
//! | ed25519 | apt | `sha3-256(公钥 ‖ 0x00)` |
//! | ed25519 | sui | `blake2b-256(0x00 ‖ 公钥)` |
//! | ed25519 | ton | 原始公钥十六进制（真实地址需钱包合约，见下） |
//! | ed25519 | icp | self-authenticating principal（见下） |
//!
//! TON 是唯一例外：它的地址由**钱包合约的 code + state-init** 共同决定，
//! 仅凭公钥算不出来，故返回公钥本身供上层对照。
//! ICP 则能由公钥算出一个真实地址——self-authenticating principal，
//! 见 [`icp_principal_text`] 的说明与正确性对拍。

use bitcoin::{Address, CompressedPublicKey, Network};
use rand::rngs::OsRng;
use sha2::{Digest, Sha224};

use crate::store::{Scheme, StoredKey};

/// 一次密钥派生的完整结果。
///
/// 注意：`private_key` 是 32 字节种子的 `0x` 十六进制，全链统一；
/// `public_key` 对各链给出最自然的展示（hex / base58）；`address` 是该链原生地址字符串。
///
/// `chain` / `private_key` / `public_key` 三个字段当前只被**测试套件**断言
/// （`_match_a_real_world_vector`、`eth_address_matches_a_well_known_constant` 等），
/// 生产 HTTP 路径在移除 `getprikey` 后不再返回它们，故非 `--tests` 构建会触发 dead_code。
/// 保留它们以维持「派生正确性」的钉死测试，不删。
#[allow(dead_code)]
pub struct KeyInfo {
    pub chain: String,
    pub scheme: Scheme,
    /// 原生地址（作为 `signtx` 的 fromaddress 使用，启动预热时已登记进内存密钥库）。
    pub address: String,
    /// `0x` + 32 字节种子十六进制。
    pub private_key: String,
    /// 公钥（hex 或 base58，随链）。
    pub public_key: String,
    /// 32 字节种子，交给密钥库存放。
    pub seed: [u8; 32],
}

/// 该链是否被本签名器支持（用于尽早返回 Unsupported，而非在签名时才报错）。
pub fn is_supported(chain: &str) -> bool {
    matches!(chain, "eth" | "btc" | "sol" | "near" | "apt" | "sui" | "ton" | "icp")
}

/// 该链对应的曲线族。
pub fn scheme_for(chain: &str) -> Option<Scheme> {
    match chain {
        // ETH 与 BTC 共用同一把 secp256k1 私钥，只是派生规则不同
        // （keccak256 取后 20 字节 vs hash160 + bech32），地址天然互不冲突。
        "eth" | "btc" => Some(Scheme::Secp256k1),
        "sol" | "near" | "apt" | "sui" | "ton" | "icp" => Some(Scheme::Ed25519),
        _ => None,
    }
}

/// 本服务支持的全部链。遍历顺序即启动时预热的顺序。
///
/// `btc` 紧随 `eth`：两条链共用 secp256k1 那条种子，放在一起打印时
/// 「哪把钥匙管哪几条链」一眼可见。
pub const CHAINS: [&str; 8] = ["eth", "btc", "sol", "near", "apt", "sui", "ton", "icp"];

/// **对外主入口**：给定一条种子，算出该链的地址与展示信息。
///
/// 按链名分派到对应曲线。**不校验种子与曲线的匹配关系**——调用方（`main`）
/// 是按 `scheme_for(chain)` 取种子的，传错属于编程错误，不是运行时错误。
pub fn derive(chain: &str, seed: &[u8; 32]) -> anyhow::Result<KeyInfo> {
    match chain {
        "eth" => secp256k1_info(chain, seed),
        "btc" => btc_info(chain, seed),
        "sol" | "near" | "apt" | "sui" | "ton" | "icp" => ed25519_info(chain, seed),
        other => Err(anyhow::anyhow!(
            "不支持的链: {other}（可选 eth / btc / sol / near / apt / sui / ton / icp）"
        )),
    }
}

/// 随机生成一条链的新种子（**仅用于首次创建 keystore**）。
///
/// secp256k1 不能直接取 32 随机字节：标量必须落在 `[1, n-1]`，全零或 ≥ 阶都是非法私钥。
/// 概率约 2^-128，但真撞上就是「能存进 keystore 却永远签不了名」，不能赌——
/// 交给 `SigningKey::random`，它内部重抽到合法为止。
pub fn random_seed(scheme: Scheme) -> [u8; 32] {
    match scheme {
        Scheme::Secp256k1 => k256::ecdsa::SigningKey::random(&mut OsRng).to_bytes().into(),
        Scheme::Ed25519 => ed25519_dalek::SigningKey::generate(&mut OsRng).to_bytes(),
    }
}

/// ETH：由 secp256k1 种子算出公钥与 keccak256 地址。
fn secp256k1_info(chain: &str, seed: &[u8; 32]) -> anyhow::Result<KeyInfo> {
    use k256::ecdsa::{SigningKey, VerifyingKey};

    // `SigningKey::from_slice` 会校验标量合法性（非零、小于阶），
    // 所以从磁盘解开的种子若被改坏，这里会报错而不是默默产出废签名。
    let sk = SigningKey::from_slice(seed)
        .map_err(|e| anyhow::anyhow!("secp256k1 种子不是合法私钥: {e}"))?;
    let vk = VerifyingKey::from(&sk);
    // 非压缩公钥：0x04 ‖ X(32) ‖ Y(32)，共 65 字节。
    let pub_bytes = vk.to_encoded_point(false).as_bytes().to_vec();

    // ETH 地址 = keccak256(公钥[1:])[12:]；注意**去掉 0x04 前缀**再哈希。
    let hash = alloy::primitives::keccak256(&pub_bytes[1..]);
    let address = format!("0x{}", hex::encode(&hash[12..]));

    Ok(KeyInfo {
        chain: chain.to_string(),
        scheme: Scheme::Secp256k1,
        address,
        private_key: format!("0x{}", hex::encode(seed)),
        public_key: format!("0x{}", hex::encode(pub_bytes)),
        seed: *seed,
    })
}

/// BTC：由 secp256k1 种子算出**压缩**公钥与主网 P2WPKH 地址（`bc1q…`）。
///
/// # 领域说明：为什么必须是压缩公钥
///
/// BTC 的隔离见证地址与见证字段都以**压缩**公钥（33 字节 `02/03 ‖ X`）为基础，
/// 未压缩公钥（65 字节）派生出的是**另一套**地址。SDK 侧 `build_transfer` 也只收
/// 压缩公钥（`chain/btc/src/tx.rs::parse_public_key` 会拒绝 65 字节），
/// 所以两侧必须对齐——否则「sign 报出去的地址」与「SDK 能花到的地址」是两套，
/// 钱会打进没人控制的地址，且不报错。
///
/// # 领域说明：为什么固定主网
///
/// 地址编码里含网络前缀（`bc` / `tb`），换网络就是另一套地址。
/// 本服务与 SDK 一致默认主网，且刻意不引入网络参数：多一个参数就多一种
/// 「换个目录/换个参数启动 → 拿到第二套地址」的可能，其表现是
/// 「我明明有地址，怎么余额是 0」——排查成本远高于收益。
fn btc_info(chain: &str, seed: &[u8; 32]) -> anyhow::Result<KeyInfo> {
    use k256::ecdsa::{SigningKey, VerifyingKey};

    // 与 ETH 同一把种子，同样要校验标量合法性。
    let sk = SigningKey::from_slice(seed)
        .map_err(|e| anyhow::anyhow!("secp256k1 种子不是合法私钥: {e}"))?;
    let vk = VerifyingKey::from(&sk);
    // `to_encoded_point(true)` 的 `true` 表示**压缩**：产出 33 字节（`02/03` + X），
    // 而不是 ETH 那条路径用的 65 字节（`04` + X + Y）。
    let pub_bytes = vk.to_encoded_point(true).as_bytes().to_vec();

    // `from_slice` 会同时校验长度（33）与「点在曲线上」。
    let compressed = CompressedPublicKey::from_slice(&pub_bytes)
        .map_err(|e| anyhow::anyhow!("BTC 压缩公钥构造失败: {e}"))?;
    let address = Address::p2wpkh(&compressed, Network::Bitcoin).to_string();

    Ok(KeyInfo {
        chain: chain.to_string(),
        scheme: Scheme::Secp256k1,
        address,
        private_key: format!("0x{}", hex::encode(seed)),
        // 公钥展示为**压缩**格式，与 SDK `build_transfer` 要求的 `public_key` 入参
        // 逐字节一致，调用方可直接把 `/v1/chains` 里这个值原样传过去。
        public_key: format!("0x{}", hex::encode(pub_bytes)),
        seed: *seed,
    })
}

/// SOL / NEAR / APT / SUI / TON：由 ed25519 种子算出公钥与各自地址。
fn ed25519_info(chain: &str, seed: &[u8; 32]) -> anyhow::Result<KeyInfo> {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    // ed25519 种子的合法域就是「任意 32 字节」本身，无需范围校验。
    let sk = SigningKey::from_bytes(seed);
    let vk = VerifyingKey::from(&sk);
    let pub_bytes = vk.to_bytes(); // 32 字节 ed25519 公钥

    let address = match chain {
        "sol" => {
            // Solana 地址即 ed25519 公钥的 base58。
            solana_pubkey::Pubkey::from(pub_bytes).to_string()
        }
        "near" => {
            // NEAR 隐式账户地址 = `ed25519:<base58(公钥)>`。
            let pk = near_crypto::PublicKey::ED25519(
                near_crypto::ED25519PublicKey::try_from(pub_bytes.as_slice())
                    .map_err(|e| anyhow::anyhow!("NEAR 公钥构造失败: {e}"))?,
            );
            pk.to_string()
        }
        "apt" => {
            // Aptos 地址 = sha3-256(公钥 ‖ 0x00)。末尾那个 0x00 是单签方案标志，
            // 漏掉它算出的地址与原钥不对应——资金会打到无人控制的地址。
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(pub_bytes);
            h.update([0x00u8]);
            format!("0x{}", hex::encode(h.finalize()))
        }
        "sui" => {
            // Sui 地址 = blake2b-256(方案标志 0x00 ‖ 公钥)；标志在**前面**，与 Aptos 相反。
            use blake2::{Blake2bVar, digest::{Update, VariableOutput}};
            let mut h = Blake2bVar::new(32)
                .map_err(|e| anyhow::anyhow!("SUI 哈希初始化失败: {e}"))?;
            h.update(&[0x00u8]);
            h.update(&pub_bytes);
            let mut out = [0u8; 32];
            h.finalize_variable(&mut out)
                .map_err(|e| anyhow::anyhow!("SUI 地址派生失败: {e}"))?;
            format!("0x{}", hex::encode(out))
        }
        "ton" => {
            // TON 真实地址需钱包合约；此处返回原始公钥十六进制供上层对照。
            format!("0x{}", hex::encode(pub_bytes))
        }
        "icp" => {
            // ICP self-authenticating principal：由公钥派生的真实地址（见 icp_principal_text）。
            icp_principal_text(&pub_bytes)
        }
        _ => unreachable!("调用方已按 scheme_for 分派"),
    };

    // 公钥展示：SOL 用 base58，其余用 hex。
    let public_key = match chain {
        "sol" => solana_pubkey::Pubkey::from(pub_bytes).to_string(),
        _ => format!("0x{}", hex::encode(pub_bytes)),
    };

    Ok(KeyInfo {
        chain: chain.to_string(),
        scheme: Scheme::Ed25519,
        address,
        private_key: format!("0x{}", hex::encode(seed)),
        public_key,
        seed: *seed,
    })
}

/// ICP self-authenticating principal 派生。
///
/// # 为什么这是 ICP 的「地址」
///
/// ICP 没有「公钥即地址」的简单位置；一个 ed25519 公钥对应的**真实身份**是
/// self-authenticating principal——它的字节布局为 `SHA-224(DER(pubkey)) ‖ 0x02`
/// （29 字节），文本形式再叠一层 `base32(CRC32(blob) ‖ blob)`。
/// 这段文字就是 `/v1/chains` 里 icp 的 `address`，也是调用方在 IC 上看到的那串
/// `xxxx-xxxx-...`。
///
/// # 为什么哈希的是 DER 而非裸公钥
///
/// 这是 IC 规范（与 `ic_agent` / `ic-principal` 一致）钉死的口径：principal 绑定的
/// 是 **DER 编码的 SubjectPublicKeyInfo**（RFC 8410，前缀 `302a300506032b6570032100`），
/// 不是裸 32 字节。裸公钥哈希会得到**另一串** principal——本地一切正常，
/// 但节点认的是 DER 那串，于是「地址」与「身份」脱钩，签名/请求被拒。
///
/// # 正确性对拍
///
/// 文本编码（CRC32 + base32 + 分隔符）逐字符对照 IC 官方 `ic_principal` crate 的
/// 三个外部向量（`""` → `aaaaa-aa`、`[0x04]` → `2vxsx-fae`、测试 blob →
/// `2chl6-4hpzw-vqaaa-aaaaa-c`），见 `icp_principal_encoding_matches_spec`；
/// SHA-224(DER) + `0x02` 末端则对照 `icp_principal_matches_independent_implementation`
/// （独立 Python 算出的 principal 文本）。
fn icp_principal_text(pubkey: &[u8; 32]) -> String {
    // RFC 8410 SPKI DER 前缀：SEQUENCE { AlgorithmIdentifier(ed25519 OID 1.3.101.112)
    // BIT STRING(0 未用位) }，无 NULL 参数。与 `openssl pkey -pubout -outform DER` 的
    // 前 12 字节逐字节一致。
    let mut der = [0u8; 44];
    der[..12].copy_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    der[12..].copy_from_slice(pubkey);

    // SHA-224 摘要（28 字节）。IC 用 SHA-224 而非 SHA-256，是规范规定。
    let digest = Sha224::digest(der);
    // blob = SHA-224(DER) ‖ 0x02（SELF_AUTHENTICATING_TAG），共 29 字节。
    let mut blob = [0u8; 29];
    blob[..28].copy_from_slice(&digest[..]);
    blob[28] = 0x02;
    principal_to_text(&blob)
}

/// 把 principal 的**内部字节**（blob）编码成 IC 文本形式。
///
/// 算法（与官方 `ic_principal` crate 逐字节一致）：
/// 1. `checksum = CRC32(blob)`（标准 CRC-32 / IEEE，4 字节大端）；
/// 2. `bytes = checksum ‖ blob`；
/// 3. `base32` 编码（RFC 4648 小写字母表，**无填充**）；
/// 4. 每 5 个字符插入一个 `-`（末尾不插）。
///
/// # 为什么要自己写 base32 而不引第三方 crate
///
/// 这段编码是 IC 身份正确性的唯一来源——算错一个字符，principal 就指向另一个身份，
/// 资金/请求会落到错误的地方且不报错。正因如此，它必须能被本 crate 的测试
/// **独立对拍**（见 `icp_principal_encoding_matches_spec`）。手写 30 行的 RFC 4648
/// 比引一个黑盒 crate 更可控，也更容易被审计。
fn principal_to_text(blob: &[u8]) -> String {
    // CRC32：标准 IEEE 多项式（与 `crc32fast`、Python `zlib.crc32` 一致）。
    let checksum = crc32fast::hash(blob).to_be_bytes();
    let mut bytes = Vec::with_capacity(4 + blob.len());
    bytes.extend_from_slice(&checksum);
    bytes.extend_from_slice(blob);

    let b32 = base32_encode(&bytes);
    // 每 5 个字符插一个 `-`：例如 53 字符 → `xxxxx-xxxxx-...-xxxxx-xxx`。
    let mut out = String::with_capacity(b32.len() + b32.len() / 5);
    for (i, c) in b32.chars().enumerate() {
        if i > 0 && i % 5 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// RFC 4648 base32 编码（小写字母表 `a–z2–7`，**无 `=` 填充**）。
///
/// # 语法要点
///
/// base32 把每 5 个字节（40 bit）切成 8 个 5-bit 符号。我们用一个 `u32` 位缓冲
/// 累积字节：每吃进一字节就 `buffer << 8`，凑够 ≥ 5 bit 就吐一个符号；
/// 最后不足 5 bit 的残余位在左侧补 0 凑成一个符号（与 RFC 4648 的「隐含零」规则一致）。
/// `u32` 足够装下缓冲：每轮最多 4（残余）+ 8（新字节）= 12 bit < 32。
fn base32_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(input.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        // 残余位左移补零到 5 bit 宽，再取一符号。
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// `base32_encode` 的逆运算（RFC 4648 小写字母表，无 `=` 填充）。
///
/// 仅用于测试里的「principal 文本 → blob」自洽校验（见
/// `icp_address_is_self_consistent_principal_text`），生产路径用不到解码。
///
/// # 语法要点
///
/// 与编码对称：每吃进一个 5-bit 符号就 `buffer << 5`，凑够 ≥ 8 bit 吐一个字节，
/// 并在吐完后把 `buffer` 按 `bits` 位掩码清零高字节（否则 `buffer` 会随迭代溢出 `u32`
/// 而腐化）。残余不足 8 bit 的尾部直接丢弃——校验 CRC 用不到它。
#[cfg(test)]
fn base32_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input {
        let v = match c {
            b'a'..=b'z' => (c - b'a') as u32,
            b'A'..=b'Z' => (c - b'A') as u32,
            b'2'..=b'7' => (c - b'2' + 26) as u32,
            _ => return None,
        };
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }
    Some(out)
}

/// 把 [`KeyInfo`] 转成可存入 [`KeyStore`] 的记录。
pub fn to_stored(key: &KeyInfo) -> StoredKey {
    StoredKey {
        scheme: key.scheme,
        seed: key.seed,
    }
}

#[cfg(test)]
mod tests {
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
    /// 私钥 1 的主网 P2WPKH 地址（BIP173 官方示例用的正是这个 hash160）。
    const BTC_VECTOR_P2WPKH_1: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    /// 私钥 1 的主网 P2PKH 地址（仅作对照，本服务不使用）。
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
        // P2WPKH 与 P2PKH 是两套地址，本服务只出 P2WPKH。
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
}
