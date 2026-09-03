//! 加密 keystore：一个口令 → 两个加密文件（secp256k1 / ed25519）。
//!
//! # 为什么这么设计
//!
//! ## 1. 一个曲线族一个文件，全服务只有两个私钥
//!
//! 地址是**公钥的派生物**，同一把私钥在不同链上派生出的地址天然不同：
//! - secp256k1 那条 → eth（`keccak256(pk)[12:]`）、btc（hash160）、ckb（blake160）…
//! - ed25519 那条   → sol（base58(pk)）、near、apt、sui、ton…
//!
//! 所以不需要为每条链各存一份种子，两个就够了。反过来，如果每次签名都现生成一把新私钥，
//! 用户拿到的就是一次性的、转完账就没法再控制该地址的密钥——这正是本服务改用
//! 「启动时由口令解开两个持久 keystore、预热全部地址」的原因。
//!
//! ## 2. 口令只存在于内存，且用完即清零
//!
//! 磁盘上只留：盐、nonce、密文、校验值。没有口令既无法还原私钥，也**无法判断**
//! 口令是否正确——所以额外存一个 `verifier`，把两种失败分开：
//!
//! | 现象 | 判定 | 正确处置 |
//! |---|---|---|
//! | `verifier` 不匹配 | 口令错 | 重试 |
//! | `verifier` 匹配、GCM 认证失败 | 文件被改坏 | 恢复备份，重试无意义 |
//!
//! 两者混为一谈的代价是不对称的：若把「文件损坏」报成「口令错」，用户会一直试口令；
//! 若把「口令错」报成「文件损坏」，用户可能直接删掉其实是好的备份。
//!
//! `verifier` 只由「口令 + 盐 + KDF 参数」派生的 mac_key 算出，**刻意不绑定密文**——
//! 一旦绑定密文，密文被改坏就会表现为 verifier 不匹配，又被误判成口令错，白分一层。
//!
//! ## 3. 两个文件各用独立随机盐
//!
//! 同一口令派生出**不同**的加密密钥，这叫域分离：即使某文件的密文侧出现故障（或将来
//! 换参数时算错），另一个文件的密钥不受牵连。共用一个盐则一处出错两处全毁。
//!
//! ## 4. AEAD 的 AAD 绑定元数据
//!
//! `version` 与 `scheme` 作为附加认证数据参与认证。否则攻击者把文件的
//! `"scheme": "ed25519"` 改成 `"secp256k1"` 会让解密**照常成功**，于是 32 字节种子被
//! 按错误曲线解释——不会报错，只会签出永远无效的签名，极难排查。
//!
//! ## 5. 参数选择
//!
//! Argon2id 取 OWASP 建议的 `m=19MiB, t=2, p=1`（约 50–100ms）。
//! 选 `id` 而非纯 `i`：纯 `i` 抗 GPU 弱（低内存可并行），纯 `d` 抗侧信道弱；
//! `id` 第一遍按 `i` 走、其余按 `d` 走，两头的短板都补上。
//!
//! # 已知边界
//!
//! - **改盐会让文件表现为「口令错」**。盐是参与派生的，篡改变 salt 与猜错口令在
//!   verifier 上不可区分。本工具不打算防「能写你磁盘的攻击者」——那个层级下
//!   攻击者可以直接把整个文件换掉，加什么完整性字段都拦不住。
//! - **口令无法找回**。没有后门、没有助记词，忘了就是永久失去私钥。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2bVar, digest::{Update, VariableOutput}};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::store::Scheme;

/// 磁盘格式版本号。改格式就 +1，旧版本继续按旧分支读（当前只有 v1，故直接拒）。
const KEYSTORE_VERSION: u32 = 1;

/// Argon2 盐长度（字节）。16 字节对 KDF 足够——盐只需**唯一**，无需保密。
const SALT_LEN: usize = 16;
/// AES-GCM nonce 长度（字节）。GCM 标准长度即 12。
const NONCE_LEN: usize = 12;
/// 主密钥长度（字节）：前 32 作加密密钥，后 32 作校验密钥。
const MASTER_LEN: usize = 64;
/// 校验值长度（字节）。
const VERIFIER_LEN: usize = 32;
/// 私钥种子长度（字节）。两种曲线的原始私钥都是 32 字节。
pub const SEED_LEN: usize = 32;

/// Argon2id 内存开销，单位 KiB。19 * 1024 KiB = 19 MiB。
const ARGON2_M_COST: u32 = 19 * 1024;
/// Argon2id 迭代次数。
const ARGON2_T_COST: u32 = 2;
/// Argon2id 并行度。
const ARGON2_P_COST: u32 = 1;

/// 域分离用的字符串前缀：改了就等于换一套格式，旧文件全部失效（这是有意为之的开关）。
const AAD_PREFIX: &str = "allchain-sign-keystore";
/// 校验值前缀，与 AAD、KDF 的输入区分开，避免不同用途的哈希撞车。
const VERIFIER_PREFIX: &str = "allchain-sign-verifier";

// ---------------------------------------------------------------------------
// 错误类型
// ---------------------------------------------------------------------------

/// 打开 keystore 的失败原因。
///
/// 三种必须分开：处置方式完全相反（重试 / 恢复备份 / 修路径），
/// 靠字符串匹配去区分迟早出错，所以做成类型。
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// `verifier` 不匹配：口令错。**重试即可**，文件本身是好的。
    #[error("口令错误")]
    WrongPassword,
    /// `verifier` 通过但 GCM 认证失败：文件被篡改或截断。**重试无意义**，应恢复备份。
    #[error("keystore 文件已损坏或被篡改：{0}")]
    Corrupt(String),
    /// 文件读不出来或字段缺失：连口令都没机会校验。
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl VaultError {
    /// 是否属于「值得让用户再试一次口令」的失败。
    ///
    /// 只有口令错值得重试；损坏与 IO 错误重试一万次也一样。
    pub fn is_wrong_password(&self) -> bool {
        matches!(self, VaultError::WrongPassword)
    }
}

// ---------------------------------------------------------------------------
// 磁盘格式
// ---------------------------------------------------------------------------

/// 磁盘上的一个 keystore 文件（明文 JSON，**不含私钥**）。
///
/// 全部敏感字节都在 `ciphertext` 里；其余字段都是解密所必需的公开参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreFile {
    /// 格式版本，同时绑定进 AAD（见模块文档第 4 点）。
    pub version: u32,
    /// 曲线族，同时绑定进 AAD。防止「解密成功但按错误曲线解释种子」。
    pub scheme: Scheme,
    /// 口令派生参数。
    pub kdf: KdfParams,
    /// 对称加密参数。
    pub cipher: CipherParams,
    /// base64(verifier)：只依赖「口令 + 盐 + KDF 参数」，用于区分口令错与文件损坏。
    pub verifier: String,
    /// base64(密文 ‖ GCM tag)。aes-gcm 的 `encrypt` 会把 16 字节 tag 追加在密文尾部。
    pub ciphertext: String,
}

/// Argon2id 参数。全部落盘——**没有这些就没法从同一口令重算出同一密钥**。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub name: String,
    /// base64(随机盐)。
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// 输出长度（字节）。
    pub output_len: u32,
}

/// AES-256-GCM 参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub name: String,
    /// base64(随机 nonce)。
    pub nonce: String,
}

// ---------------------------------------------------------------------------
// 路径
// ---------------------------------------------------------------------------

/// keystore 目录默认值：`~/.allchain-sign`。
///
/// 放家目录而非当前工作目录：放在 cwd 里会随「在哪儿敲命令」漂移，
/// 同一用户换目录启动就会莫名其妙地生成第二套密钥。
pub fn default_dir() -> PathBuf {
    home_dir().join(".allchain-sign")
}

/// 家目录。`$HOME` 缺失时回落到当前目录（容器 / 极简环境下不至于直接崩）。
fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// 单个 keystore 文件的路径。
pub fn path_for(dir: &Path, scheme: Scheme) -> PathBuf {
    dir.join(format!("keystore-{}.json", scheme.as_str()))
}

// ---------------------------------------------------------------------------
// 目录状态
// ---------------------------------------------------------------------------

/// keystore 目录当前处于哪种状态。决定启动时是「要新口令」还是「要旧口令」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirState {
    /// 两个文件都不存在：全新初始化，需要设口令（并要求二次确认）。
    Empty,
    /// 只有一个：补齐缺失的那个，沿用原口令。
    Partial,
    /// 两个都在：正常解锁。
    Complete,
}

/// 判定目录状态。
pub fn state(dir: &Path) -> DirState {
    // `.count()` 而非 `len()`：迭代器没有长度信息，但这里最多两个文件，无所谓开销。
    let present = Scheme::ALL
        .iter()
        .filter(|s| path_for(dir, **s).exists())
        .count();
    match present {
        0 => DirState::Empty,
        1 => DirState::Partial,
        _ => DirState::Complete,
    }
}

// ---------------------------------------------------------------------------
// 密码学原语
// ---------------------------------------------------------------------------

/// 构造 AEAD 的附加认证数据：`前缀:版本:曲线`。
///
/// 用 `String` 再 `.into_bytes()` 而非直接拼 `Vec<u8>`：这里只在启动/创建时各调一次，
/// 可读性远比省一次分配重要。
fn aad(version: u32, scheme: Scheme) -> Vec<u8> {
    format!("{AAD_PREFIX}:v{version}:{}", scheme.as_str()).into_bytes()
}

/// 从口令派生主密钥。
///
/// 返回 `Zeroizing<[u8; 64]>`：离开作用域时用 0 覆写。
/// `Zeroizing` 的 `Deref` 指向内部数组，所以调用方按普通数组用即可。
fn derive_master(password: &[u8], params: &KdfParams) -> anyhow::Result<Zeroizing<[u8; MASTER_LEN]>> {
    let salt = base64_decode(&params.salt, "kdf.salt")?;
    // `output_len` 是 `usize`（不是 u32）：Argon2 的输出长度最终要用来切缓冲区，
    // 用平台原生宽度更自然。别顺手 `as u32`，那样会引入一次无意义的转换。
    let params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(MASTER_LEN))
        .map_err(|e| anyhow::anyhow!("Argon2 参数非法: {e}"))?;
    // `Algorithm::Argon2id` + `Version::V0x13`（0x13 = 19，即 Argon2 的最终 RFC 版本）。
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = Zeroizing::new([0u8; MASTER_LEN]);
    argon2
        .hash_password_into(password, &salt, master.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("Argon2 派生失败: {e}"))?;
    Ok(master)
}

/// 由 mac_key 算出校验值。
///
/// **刻意只吃 mac_key**：一旦把密文也喂进来，密文损坏就会表现为校验值不匹配，
/// 于是「文件损坏」被误报成「口令错」，第 2 点里那张表就白分了。
fn verifier_for(mac_key: &[u8]) -> anyhow::Result<[u8; VERIFIER_LEN]> {
    let mut h = Blake2bVar::new(VERIFIER_LEN)
        .map_err(|e| anyhow::anyhow!("Blake2b 初始化失败: {e}"))?;
    h.update(VERIFIER_PREFIX.as_bytes());
    h.update(mac_key);
    let mut out = [0u8; VERIFIER_LEN];
    h.finalize_variable(&mut out)
        .map_err(|e| anyhow::anyhow!("校验值计算失败: {e}"))?;
    Ok(out)
}

/// 校验值比对：`==` 会按字节短路，泄露「前缀已经猜对几位」，故用恒定时间比较。
///
/// `ct_eq` 返回 `Choice` 而非 `bool`，必须再 `into()` 一次；
/// 这层包装是为了防止编译器把「比较结果」优化成可预测的分支。
fn verifier_matches(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    bool::from(expected.ct_eq(actual))
}

/// 生成随机的 Argon2 盐与 AES-GCM nonce。
///
/// 不需要 `scheme` 参数：盐本身已是全局唯一的随机值，域分离由它保证，
/// 再混进曲线名属于重复劳动——而且会让人误以为「盐相同也没关系，反正有 scheme 分开」。
fn random_params() -> (KdfParams, CipherParams) {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    // `OsRng` 是操作系统的 CSPRNG；`fill_bytes` 失败会 panic，这里它不会失败。
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    (
        KdfParams {
            name: "argon2id".to_string(),
            salt: base64_encode(&salt),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
            output_len: MASTER_LEN as u32,
        },
        CipherParams {
            name: "aes-256-gcm".to_string(),
            nonce: base64_encode(&nonce),
        },
    )
}

// ---------------------------------------------------------------------------
// 加解密
// ---------------------------------------------------------------------------

/// 用口令加密一个 32 字节种子，产出可直接落盘的 [`KeystoreFile`]。
pub fn encrypt_seed(
    password: &str,
    scheme: Scheme,
    seed: &[u8; SEED_LEN],
) -> anyhow::Result<KeystoreFile> {
    let (kdf, cipher_params) = random_params();
    let master = derive_master(password.as_bytes(), &kdf)?;

    // 前 32 字节作加密密钥，后 32 作校验密钥。
    let (enc_key, mac_key) = master.split_at(32);

    let key = Key::<Aes256Gcm>::from(<[u8; 32]>::try_from(enc_key)?);
    let nonce_bytes = base64_decode(&cipher_params.nonce, "cipher.nonce")?;
    let nonce = Nonce::from(<[u8; NONCE_LEN]>::try_from(nonce_bytes.as_slice())?);

    let aad = aad(KEYSTORE_VERSION, scheme);
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            // `Payload` 把 msg 与 aad 一起交给 AEAD：aad 参与认证但**不进密文**，
            // 所以磁盘上仍能看到 `scheme` 明文，只是改了就会被认证拒绝。
            Payload { msg: seed.as_slice(), aad: &aad },
        )
        .map_err(|e| anyhow::anyhow!("AES-GCM 加密失败: {e}"))?;

    Ok(KeystoreFile {
        version: KEYSTORE_VERSION,
        scheme,
        kdf,
        cipher: cipher_params,
        verifier: base64_encode(&verifier_for(mac_key)?),
        ciphertext: base64_encode(&ciphertext),
    })
}

/// 用口令解开一个 [`KeystoreFile`]，还原 32 字节种子。
///
/// 失败时区分「口令错」与「文件损坏」，见 [`VaultError`]。
pub fn decrypt_seed(
    password: &str,
    file: &KeystoreFile,
) -> Result<Zeroizing<[u8; SEED_LEN]>, VaultError> {
    if file.version != KEYSTORE_VERSION {
        return Err(VaultError::Other(anyhow::anyhow!(
            "keystore 版本 {} 不受支持（本程序只认 v{}）",
            file.version,
            KEYSTORE_VERSION
        )));
    }
    if file.kdf.name != "argon2id" {
        return Err(VaultError::Other(anyhow::anyhow!(
            "未知 KDF: {}（期望 argon2id）",
            file.kdf.name
        )));
    }
    if file.cipher.name != "aes-256-gcm" {
        return Err(VaultError::Other(anyhow::anyhow!(
            "未知加密算法: {}（期望 aes-256-gcm）",
            file.cipher.name
        )));
    }

    let master = derive_master(password.as_bytes(), &file.kdf)?;
    let (enc_key, mac_key) = master.split_at(32);

    // ——— 第一道：校验值。不通过 = 口令错，文件本身没问题。 ———
    let expected = verifier_for(mac_key)?;
    let stored = base64_decode(&file.verifier, "verifier")?;
    if !verifier_matches(&expected, &stored) {
        return Err(VaultError::WrongPassword);
    }

    // ——— 第二道：GCM 认证。校验值过了还失败 = 密文被改坏。 ———
    // 长度由 `MASTER_LEN` 与 `split_at(32)` 保证，理论上不可能失败；
    // 但仍转成 `Corrupt` 而不是 `unwrap()`：密码学路径上不留下 panic 点，
    // 免得将来有人把 MASTER_LEN 改成 48 时崩在运行时而不是编译期。
    let enc_key: [u8; 32] = enc_key.try_into().map_err(|_| {
        VaultError::Corrupt("派生密钥长度不是 32 字节".to_string())
    })?;
    let key = Key::<Aes256Gcm>::from(enc_key);
    let nonce_bytes = base64_decode(&file.cipher.nonce, "cipher.nonce")?;
    let nonce = Nonce::from(
        <[u8; NONCE_LEN]>::try_from(nonce_bytes.as_slice()).map_err(|_| {
            VaultError::Corrupt(format!("nonce 应为 {NONCE_LEN} 字节"))
        })?,
    );
    let aad = aad(file.version, file.scheme);

    let cipher = Aes256Gcm::new(&key);
    let ciphertext = base64_decode(&file.ciphertext, "ciphertext")?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload { msg: &ciphertext, aad: &aad },
        )
        .map_err(|_| {
            VaultError::Corrupt("密文未通过 GCM 认证（口令正确，但文件被改动或截断）".to_string())
        })?;

    // 长度不对说明字段被换过；`try_into` 把 `Vec<u8>` 转成定长数组，
    // 失败会带出实际长度，比自己 `assert_eq!` 写起来省事。
    let arr: [u8; SEED_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Corrupt(format!("种子长度应为 {SEED_LEN} 字节")))?;
    Ok(Zeroizing::new(arr))
}

// ---------------------------------------------------------------------------
// 读写文件
// ---------------------------------------------------------------------------

/// 落盘一个 keystore 文件，权限 0600（仅 Unix 有效）。
pub fn save(dir: &Path, file: &KeystoreFile) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let path = path_for(dir, file.scheme);
    // 换行结尾 + 缩进：方便 `cat` 和 diff，也避免 git 报 "no newline"。
    let body = serde_json::to_string_pretty(file)? + "\n";
    write_private(&path, body.as_bytes())?;
    Ok(path)
}

/// 读取一个 keystore 文件；不存在返回 `None`（这是「尚未创建」，不是错误）。
pub fn load(dir: &Path, scheme: Scheme) -> anyhow::Result<Option<KeystoreFile>> {
    let path = path_for(dir, scheme);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("读取 {} 失败: {e}", path.display()))?;
    serde_json::from_str(&body)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("{} 不是合法 keystore JSON: {e}", path.display()))
}

/// 以 0600 写入文件（Unix）。
///
/// 为什么单独一个函数：默认的 `fs::write` 会按 umask 给 0644，同机其他用户就能读到
/// 密文——虽然还有口令挡着，但密文泄露意味着可以离线暴破口令，属于白送的攻击面。
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        // `mode()` 只在**新建**时生效；文件已存在时不会改权限，故首次创建一次就够。
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    // 落盘而非留在页缓存：创建 keystore 后立刻断电也要保住文件。
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Vault：内存中的两个私钥
// ---------------------------------------------------------------------------

/// 本服务持有的全部私钥：两个曲线族各一条。
///
/// 字段用 `Zeroizing<[u8; 32]>`：进程结束（或 `Vault` 被 drop）时内存自动清零。
/// 实现 `Debug` 时**手动屏蔽种子**——默认的 `#[derive(Debug)]` 会把私钥打进日志，
/// 这是最容易发生、也最难察觉的私钥泄露方式。
pub struct Vault {
    secp256k1: Zeroizing<[u8; SEED_LEN]>,
    ed25519: Zeroizing<[u8; SEED_LEN]>,
}

impl Vault {
    /// 按曲线族取种子。返回引用：调用方只借不拿所有权，避免副本散落各处。
    pub fn seed_for(&self, scheme: Scheme) -> &[u8; SEED_LEN] {
        match scheme {
            Scheme::Secp256k1 => &self.secp256k1,
            Scheme::Ed25519 => &self.ed25519,
        }
    }

    /// 由两条种子组装。
    pub fn new(secp256k1: [u8; SEED_LEN], ed25519: [u8; SEED_LEN]) -> Self {
        Vault {
            secp256k1: Zeroizing::new(secp256k1),
            ed25519: Zeroizing::new(ed25519),
        }
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只印长度不印内容：Debug 输出会进日志/崩溃回溯，绝不能带私钥。
        f.debug_struct("Vault")
            .field("secp256k1", &format_args!("<{} bytes>", SEED_LEN))
            .field("ed25519", &format_args!("<{} bytes>", SEED_LEN))
            .finish()
    }
}

/// 一条 keystore 的处理结果，用于启动时向用户汇报发生了什么。
///
/// 可以 `derive(Debug)`：三个字段（曲线、是否新建、路径）都不含敏感信息，
/// 与 `Vault` 必须手写 Debug 屏蔽内容形成对照。
#[derive(Debug)]
pub struct Report {
    pub scheme: Scheme,
    /// `true` = 本次新建；`false` = 从已有文件解开。
    pub created: bool,
    pub path: PathBuf,
}

/// 打开 keystore 目录：已有文件就用口令解开，缺失的就随机生成并加密保存。
///
/// **幂等**：第二次用同一口令调用会解开第一次创建的种子，不会重新生成。
/// 这一点是 correctness 的底线——若每次启动都重新生成，用户上次收到的地址
/// 会永久失联（钱还在链上，但没有任何人控制它）。
///
/// 返回 `(vault, 汇报)`；汇报按顺序对应 [`Scheme::ALL`]。
pub fn open_or_fill(dir: &Path, password: &str) -> Result<(Vault, Vec<Report>), VaultError> {
    let mut reports = Vec::with_capacity(Scheme::ALL.len());
    let mut seeds = Vec::with_capacity(Scheme::ALL.len());

    for scheme in Scheme::ALL {
        let (seed, created, path) = match load(dir, scheme)? {
            // 文件在：解开。**口令错会把错误一路传出去**，绝不能退化成「重新生成」。
            Some(file) => {
                if file.scheme != scheme {
                    return Err(VaultError::Corrupt(format!(
                        "{} 里记录的曲线是 {}，与文件名不符",
                        path_for(dir, scheme).display(),
                        file.scheme.as_str()
                    )));
                }
                let seed = decrypt_seed(password, &file)?;
                (*seed, false, path_for(dir, scheme))
            }
            // 文件不在：生成一把新的，用同一口令加密落盘。
            None => {
                let seed = random_seed(scheme);
                let file = encrypt_seed(password, scheme, &seed)?;
                let path = save(dir, &file)?;
                (seed, true, path)
            }
        };
        seeds.push(seed);
        reports.push(Report { scheme, created, path });
    }

    // `seeds` 按 Scheme::ALL 顺序，即 [secp256k1, ed25519]。
    Ok((
        Vault::new(seeds[0], seeds[1]),
        reports,
    ))
}

/// 生成一条合法的随机种子。
///
/// **复用 `keys::random_seed`，不在这里另写一份**：两种曲线「随机字节是否等于合法私钥」
/// 的规则不同（secp256k1 有取值范围，ed25519 没有），这类知识只应存在一个地方。
/// 写两遍的代价不是多几行代码，而是将来改一处忘另一处。
fn random_seed(scheme: Scheme) -> [u8; SEED_LEN] {
    crate::keys::random_seed(scheme)
}

// ---------------------------------------------------------------------------
// base64 小工具
// ---------------------------------------------------------------------------

/// base64 编码（标准字母表、带 padding）。
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    // 必须 `use ... as _`：只为了把 trait 的方法带入作用域，
    // 不带名字可避免在当前作用域引入 `Engine` 这个标识符造成混淆。
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// base64 解码，失败时带上字段名——排查「到底是哪个字段坏了」时能省一轮。
fn base64_decode(raw: &str, field: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| anyhow::anyhow!("字段 {field} 不是合法 base64: {e}"))
}

#[cfg(test)] mod tests;
