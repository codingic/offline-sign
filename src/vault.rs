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

#[cfg(test)]
mod tests {
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
}
