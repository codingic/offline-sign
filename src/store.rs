//! 进程内密钥库：持有「地址 -> 种子」的映射。
//!
//! 设计要点：
//! - 私钥原材料只存 32 字节种子（secp256k1 标量 / ed25519 种子），签名时再按链重建具体签名器；
//!   这样存储层与任何链的具体密钥类型解耦，也不需要把各链的 SecretKey 类型塞进同一个 HashMap。
//! - 用 `Arc<Mutex<..>>` 包一层，便于通过 axum 的 `State` 在 handler 间共享，且 `KeyStore` 本身可 Clone。
//! - 本库**只在内存中**，进程退出即清空。种子本身来自 `vault` 模块在启动时用口令解开的
//!   两个持久私钥（见 `vault.rs`）：本库不做任何加密、也不碰磁盘。
//!   分层的理由是职责单一——磁盘格式改了（换 KDF、加字段）不需要动这里。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// 签名算法族。决定种子如何被解释、如何派生地址、如何签名。
///
/// 同时兼作**磁盘 keystore 文件的曲线标识**（见 `vault` 模块）：一个文件的 `scheme`
/// 字段被反序列化成这个值，所以这里必须能（且只能）接受两种拼写。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// ETH / BTC / CKB：secp256k1。
    Secp256k1,
    /// SOL / NEAR / APT / SUI / TON：ed25519。
    Ed25519,
}

impl Scheme {
    /// 本服务持有的两个曲线族，遍历顺序即启动时的装载/创建顺序。
    pub const ALL: [Scheme; 2] = [Scheme::Secp256k1, Scheme::Ed25519];

    /// 稳定字符串标识，用于 keystore 文件名与 AAD 绑定。
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Secp256k1 => "secp256k1",
            Scheme::Ed25519 => "ed25519",
        }
    }
}

/// 密钥库中的一条记录：算法族 + 32 字节种子。
///
/// 种子本身是敏感数据；本结构只在进程内传递，不会被序列化进任何响应。
///
/// # 为什么 `Debug` 是手写的
///
/// 判据与 `vault::Vault` **完全一致**：看结构里有没有不能外泄的字节，
/// 而不是看「这个结构平时会不会被打印」。默认 `derive(Debug)` 会把 32 个字节
/// 原样打出来，将来只要出现一行 `println!("{:?}", key)`，或某次 panic 回溯
/// 把它捎上，私钥就进了日志。这里目前确实没人打印它——正因为如此，
/// 现在补上打码的代价才最小；等真出了日志泄露再改就晚了。
#[derive(Clone, Copy)]
pub struct StoredKey {
    pub scheme: Scheme,
    pub seed: [u8; 32],
}

impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只印长度不印内容：Debug 输出会进日志/崩溃回溯，绝不能带私钥。
        // `scheme` 照常打印——它不是秘密，Debug 得保持排障价值。
        f.debug_struct("StoredKey")
            .field("scheme", &self.scheme)
            .field("seed", &format_args!("<{} bytes>", self.seed.len()))
            .finish()
    }
}

/// 进程内密钥库。
#[derive(Clone)]
pub struct KeyStore {
    map: Arc<Mutex<HashMap<String, StoredKey>>>,
}

#[allow(dead_code)]
impl KeyStore {
    /// 新建空库。
    pub fn new() -> Self {
        KeyStore {
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 以地址为键存入一条密钥。覆盖同地址旧值（同一地址重新生成即替换）。
    pub fn insert(&self, address: &str, key: StoredKey) {
        self.map.lock().unwrap().insert(address.to_string(), key);
    }

    /// 按地址取出密钥；不在内存中返回 `None`（地址在启动预热时已由 `populate` 全部登记，
    /// 调用方直接用 `/v1/chains` 列出的地址作为 `signtx` 的 fromaddress 即可）。
    pub fn get(&self, address: &str) -> Option<StoredKey> {
        self.map.lock().unwrap().get(address).copied()
    }

    /// 当前内存中密钥条数（用于状态/调试端点）。
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.map.lock().unwrap().is_empty()
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)] mod tests;
