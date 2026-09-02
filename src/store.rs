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

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一条种子可辨识的记录：`0xAB` 在十进制里是 171，
    /// 用它当填充字节，下面「Debug 不该出现 171」这条断言才不会误命中。
    fn key(fill: u8) -> StoredKey {
        StoredKey { scheme: Scheme::Secp256k1, seed: [fill; 32] }
    }

    /// **种子的三种形态都不许出现在 Debug 输出里**。
    ///
    /// 判据取 `Vault` 那条测试的同一思路（vault.rs 里有对应变异体 M19）：
    /// 这里同时查 hex、十进制数组两种形态，是因为只查一种会漏——
    /// `derive(Debug)` 打印 `[u8; 32]` 用的是**十进制**，
    /// 如果只断言 hex 不出现，把 `Debug` 改回 `derive` 照样能绿。
    #[test]
    fn debug_never_leaks_the_seed() {
        let k = key(0xAB);
        let out = format!("{:?}", k);

        assert!(
            !out.contains(&hex::encode(k.seed)),
            "Debug 输出里出现了种子的 hex 形式（说明用了 derive(Debug)）: {out}"
        );
        assert!(
            !out.contains("171"),
            "Debug 输出里出现了种子的十进制形式 171（derive(Debug) 就是这么打 [u8;32] 的）: {out}"
        );
        // 反证的另一半：Debug 得保留排障价值，不能为了打码把 scheme 也抹了。
        assert!(
            out.contains("Secp256k1"),
            "scheme 不是秘密，应当照常打印，否则 Debug 就没用了: {out}"
        );
        assert!(out.contains("<32 bytes>"), "应只显示长度: {out}");
    }

    /// `Scheme::as_str()` 必须与 **serde 的拼写**一致。
    ///
    /// 为什么这条值得测：`as_str()` 同时用于 keystore **文件名**与 AAD 绑定，
    /// 而 serde 的拼写（`#[serde(rename_all = "lowercase")]`）决定磁盘 JSON 里
    /// 那个 `scheme` 字段长什么样。两者一旦漂移，就会出现
    /// 「文件在 keystore-ed25519.json 里、内容却写着别的 scheme」这类
    /// 能写入但读不回来的事故。
    #[test]
    fn as_str_matches_the_serde_spelling_used_on_disk() {
        for scheme in Scheme::ALL {
            let json = serde_json::to_string(&scheme).expect("Scheme 应可序列化");
            let expected = format!("\"{}\"", scheme.as_str());
            assert_eq!(json, expected, "{scheme:?} 的两种拼写应一致");

            // 反向：磁盘上读回来的字符串必须能还原成同一个变体。
            let back: Scheme =
                serde_json::from_str(&json).expect("磁盘上的拼写应能反序列化");
            assert_eq!(back, scheme, "往返后应还原成同一个变体");
        }
    }

    /// `Scheme::ALL` 的**顺序**即启动时的装载顺序，不能随意调换。
    #[test]
    fn all_lists_the_two_curves_in_load_order() {
        assert_eq!(
            Scheme::ALL,
            [Scheme::Secp256k1, Scheme::Ed25519],
            "顺序即 keystore 的装载/创建顺序，调换会让启动日志与报错跟着变"
        );
    }

    /// `get` 返回的是**副本**：改动取出来的记录不能影响库里的内容。
    ///
    /// 这条属性靠 `StoredKey: Copy` + `HashMap::get(..).copied()` 成立。
    /// 若哪天改成返回引用或把 `Copy` 去掉，这里会红——
    /// 而「调用方手里那把钥匙会悄悄改动库里的钥匙」是很难排查的一类缺陷。
    #[test]
    fn get_returns_an_independent_copy() {
        let ks = KeyStore::new();
        ks.insert("addr", key(1));

        let mut got = ks.get("addr").expect("应能取回刚存入的钥匙");
        got.seed[0] = 0xFF;
        // 先确认副本**确实被改了**：没有这一句，下面那条断言即使
        // 「改动穿透到了库里」也仍然成立（两者会同为 0xFF），测试就成了空的。
        assert_eq!(got.seed[0], 0xFF, "取出的副本本身应被改动");

        assert_eq!(
            ks.get("addr").expect("仍在库中").seed[0],
            1,
            "改动返回的副本不应影响库里的种子"
        );
    }

    /// 未登记的地址返回 `None`，而不是 panic 或凭空造一把钥匙。
    #[test]
    fn an_unknown_address_yields_none() {
        let ks = KeyStore::new();
        assert!(ks.is_empty(), "新库应为空");
        assert!(ks.get("nope").is_none());
    }

    /// 同一地址重复存入应**覆盖**旧值（对应「同一地址重新生成即替换」）。
    #[test]
    fn inserting_the_same_address_overwrites() {
        let ks = KeyStore::new();
        ks.insert("addr", key(1));
        ks.insert("addr", key(2));

        assert_eq!(ks.len(), 1, "同地址不应产生两条记录");
        assert_eq!(ks.get("addr").expect("应存在").seed[0], 2, "应保留最后一次");
    }

    /// `KeyStore` 可 `Clone` 且**共享**同一份底层映射（axum `State` 需要克隆它）。
    ///
    /// 语法：`map` 是 `Arc<Mutex<..>>`，克隆只增加引用计数、不复制 HashMap，
    /// 所以两个句柄看到的是同一份数据——这正是它能穿过 axum 共享的原因。
    #[test]
    fn cloning_shares_the_underlying_map() {
        let ks = KeyStore::new();
        ks.insert("addr", key(7));

        let clone = ks.clone();
        clone.insert("other", key(8));

        assert_eq!(ks.len(), 2, "克隆应共享底层映射，另一侧的插入要可见");
        assert!(ks.get("other").is_some());
    }
}
