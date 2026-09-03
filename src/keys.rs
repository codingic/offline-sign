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

#[cfg(test)] mod tests;
