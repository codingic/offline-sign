//! ETH：secp256k1 **可恢复签名** + RLP 交易重组。
//!
//! # 为什么每条链单独一个文件
//!
//! 每条链的签名实现都拖着一大堆只在自己身上成立的依赖与编码约定
//! （ETH 的 RLP / SOL 的 bincode / NEAR 的 Borsh / APT 与 SUI 的 BCS）。
//! 全挤在一个文件里时，改 ETH 的一个 `use` 有可能顺手改坏 SOL 的解析；
//! 分文件后，每个文件只认自己那条链的序列化格式，依赖关系一眼可见，
//! 也便于将来按链增删（比如接 BTC 就是新增一个 `btc.rs`）。
//!
//! # 为什么只有 ETH 是 `async`
//!
//! 合金把 `TxSigner::sign_transaction` 定义成异步 trait 方法，为的是将来能接
//! 硬件钱包或远程签名器（一次签名可能要走 USB / 网络）。代价是整条调用链都得 `.await`。
//! 其余各链都是纯 CPU 的 ed25519 签名，保持同步。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`unsignedtxdatahex` —— hex 字符串（可带 `0x`），解码后是**完整交易**的 RLP 编码
//!   （结构完整、只差签名；typed / legacy 均可），对应 MetaMask 离线签名那一套输入。
//! - **输出**：`signedtxdatahex` = hex 的 `EthereumTxEnvelope` RLP 字节，
//!   可直接交给 `eth_sendRawTransaction`。
//! - **ERC20**：代币转账就是一笔 `to=token 合约`、`data=transfer(recipient,amount) calldata`、
//!   `value=0` 的 EIP-1559 交易，签名路径与 Native transfer 完全一致；`sign_eth` 会识别
//!   `transfer(address,uint256)` 选择器（前 4 字节 `0xa9059cbb`）并把 token/recipient/amount
//!   解码进 `note` 便于对账，签名行为本身不变。

use alloy::consensus::TypedTransaction;
use alloy::eips::eip2718::Encodable2718;
use alloy::network::TxSigner;
use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::signers::local::PrivateKeySigner;
use k256::ecdsa::SigningKey;

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// ETH 签名：用 k256 重建签名器，做 EIP-155 可恢复签名，再把签名装配回信封。
///
/// # 领域要点
///
/// EIP-155 的要点是签名的 `v` 里编码了 chain_id（而非固定的 27/28），
/// 这样同一条签过名的交易无法在另一条链上重放。
///
/// # 语法要点
///
/// `pub` 是必需的：本函数在子模块 `sign::eth` 里，父模块 `sign` 要调用它，
/// 不加 `pub` 的话它只在 `eth` 模块内可见（Rust 默认私有，且私有是**模块级**的）。
fn decode_unsignedtxdatahex(txdata: &[u8]) -> anyhow::Result<TypedTransaction> {
    let mut buf = txdata;
    TypedTransaction::decode_unsigned(&mut buf)
        .map_err(|e| anyhow::anyhow!("ETH 交易解码失败（需 RLP 未签名交易）: {e}"))
}

/// 从已解出的交易里抽取 `(to, input)`，用于识别 ERC20 transfer calldata。
///
/// # 语法要点
///
/// `TypedTransaction` 是枚举（Legacy / Eip2930 / Eip1559 / Eip4844 / Eip7702），
/// 各变体的 `to` / `input` 字段形态不完全一致（Eip7702 的 `to` 是 `Address`、
/// Eip4844 是变体枚举），逐个匹配会踩类型坑。这里只对真正会被 sign 签出的
/// Legacy / Eip2930 / Eip1559 三态精确抽取，其余罕见类型用 `_` 兜底返回
/// 「无 to / 空 input」——它们不会是 ERC20 transfer，识别成非 ERC20 即可。
/// 返回 **owned `Bytes`**（内部 `Arc` 克隆，零拷贝成本），避免与 `tx` 的生命周期纠缠。
fn tx_to_and_input(tx: &TypedTransaction) -> (Option<Address>, Bytes) {
    match tx {
        TypedTransaction::Legacy(t) => (t.to.to().copied(), t.input.clone()),
        TypedTransaction::Eip2930(t) => (t.to.to().copied(), t.input.clone()),
        TypedTransaction::Eip1559(t) => (t.to.to().copied(), t.input.clone()),
        _ => (None, Bytes::new()),
    }
}

/// 若 `tx` 是一笔 ERC20 `transfer(address,uint256)` 调用，解出 `(token, recipient, amount)`。
///
/// # 判定口径（不宽松，避免误判）
///
/// ERC20 `transfer` 的函数选择器是 `keccak256("transfer(address,uint256)")` 的前 4 字节
/// = `0xa9059cbb`（标准 ABI，所有 ERC20 代币共用）。
/// 合法 calldata 形态：`0xa9059cbb ‖ recipient(32 字节，末 20 字节为地址) ‖ amount(32 字节 uint256)`，
/// 共 4 + 32 + 32 = 68 字节。仅当：
/// 1. `to` 存在（合约调用；合约创建交易 `to=None` 不是 transfer）；
/// 2. `input` 长度恰为 68；
    /// 3. `input` 前 4 字节等于选择器；
    ///
    /// 三者同时满足才认定。
    ///
    /// 其余任何函数调用或任意长度 `data` 一律返回 `None`，
    /// 不让「恰好前缀对上」的其它调用被错当成 transfer。
///
/// # 为什么要单独成函数
///
/// 它只读 `typed`、不改签名流程，拆出来后 `sign_eth` 主流程只剩「解码 → 识别 → 签名 → 装配」
/// 一条主线；且本函数可被单测直接打（喂手造的 ERC20 tx，断言解出的 token/recipient/amount）。
fn erc20_transfer_info(tx: &TypedTransaction) -> Option<(Address, Address, U256)> {
    const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    let (to, input) = tx_to_and_input(tx);
    let token = to?; // 合约调用才有 `to`；无 `to`（合约创建）不是 transfer。
    if input.len() != 68 {
        return None;
    }
    if input[..4] != TRANSFER_SELECTOR {
        return None;
    }
    // recipient：32 字节 ABI 地址槽的**末 20 字节**（`address` 在 ABI 里左填充 0 到 32 字节）。
    let recipient = Address::from_slice(&input[16..36]);
    // amount：末 32 字节的 uint256（大端）。
    let amount = U256::from_be_slice(&input[36..68]);
    Some((token, recipient, amount))
}

/// 把 wei 计数的 `U256` 格式化成可读的 ETH 字符串（18 位小数，去尾随零）。
///
/// 仅用于 `note` 的人眼对账，不参与任何签名/哈希计算。
fn format_eth_str(v: U256) -> String {
    // 1 ETH = 10^18 wei。`U256::from(u128)` 在运行时求值（常量上下文里不能调非 const 函数）。
    let wei_per_eth = U256::from(1_000_000_000_000_000_000u128);
    let int_part = v / wei_per_eth;
    let frac = v % wei_per_eth;
    // `{frac:018}` 把余数补零到 18 位十进制，再切掉尾随零。
    let frac_trimmed = format!("{frac:018}").trim_end_matches('0').to_string();
    if frac_trimmed.is_empty() {
        format!("{int_part}")
    } else {
        format!("{int_part}.{frac_trimmed}")
    }
}

pub async fn sign_eth(unsignedtxdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。各链自己解码，报错时才能说清「这段字节本该是什么」。
    let txdata = decode_txdata(unsignedtxdatahex, "ETH 完整交易（RLP 未签名交易）")?;

    let sk = SigningKey::from_slice(&key.seed)
        .map_err(|e| anyhow::anyhow!("ETH 种子非法: {e}"))?;
    let signer = PrivateKeySigner::from_signing_key(sk);

    let mut typed = decode_unsignedtxdatahex(&txdata)?;

    // ERC20 识别：若这是一笔 `transfer(address,uint256)` 调用，把 token/recipient/amount
    // 解出来进 note，便于调用方对账。纯签名路径不受任何影响——ERC20 与 Native transfer
    // 对签名器而言都是「一笔完整 EIP-1559 交易」，区别只在 `to`/`data` 字段。
    let erc20 = erc20_transfer_info(&typed);

    // 合金签名器负责算哈希、EIP-155 v、产出可恢复签名。
    let signature = signer
        .sign_transaction(&mut typed)
        .await
        .map_err(|e| anyhow::anyhow!("ETH 签名失败: {e}"))?;

    // 把签名装配回信封，**按 EIP-2718 编码**成可广播字节。
    //
    // 这里必须用 `encoded_2718()` 而不是 `alloy::rlp::encode(&envelope)`：
    // 后者会在 2718 字节外面**再套一层 RLP 字符串头**（实测产出 `b875 02f872…`，
    // 前两字节 `b8 75` 是「长字符串，117 字节」的 RLP 头）。
    // 裸的 typed transaction 必须以类型字节开头（`02` = EIP-1559），
    // 节点收到多一层封装的字节会直接拒绝——属于「本地一切正常，只有广播时才失败」
    // 那类最贵的缺陷。
    let envelope = typed.into_envelope(signature);
    let tx_bytes = envelope.encoded_2718();
    // 单签名链：先把签名字符串绑成变量，`signature` 与 `signatures[0]` 共用同一个值。
    let sig_hex = format!("0x{}", hex::encode(signature.as_bytes()));
    // 链上 tx hash：keccak256(可广播字节)。以太坊节点对 `eth_sendRawTransaction` 的入参
    // 算出 `keccak256` 即为该交易 hash；EIP-2718 字节本身就是被哈希的对象，无需再套 RLP。
    let txhash = Some(format!("0x{}", hex::encode(keccak256(&tx_bytes).as_slice())));

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signedtxdatahex: Some(format!("0x{}", hex::encode(tx_bytes))),
        txhash,
        encoding: "hex".to_string(),
        note: Some(match erc20 {
            Some((token, recipient, amount)) => format!(
                "ERC20 transfer：token {token} → recipient {recipient}，\
                 amount {} wei (≈ {} ETH)。sign_eth 作为纯离线签名器直接对完整交易签名，\
                 不构造、不解析合约逻辑；txhash 为 keccak256(signedtxdatahex 字节)，\
                 可直接用于 eth_getTransactionReceipt / eth_getTransactionByHash 等查询。",
                amount,
                format_eth_str(amount)
            ),
            None => "ETH 的 txhash 为 keccak256(signedtxdatahex 字节)，随响应一并返回，\
                     可直接用于 eth_getTransactionReceipt / eth_getTransactionByHash 等查询"
                .to_string(),
        }),
    })
}

/// allchain SDK `build_transfer` 在 ETH **主网**实际产出的未签名交易。
///
/// 产生方式（真实链上状态，非手写）：
/// `acli build-transfer -c eth --from 0xd8dA6BF2… --to 0x28C6c062… --amount 0.001`
///
/// # 为什么钉这一条
///
/// SDK 与 sign 是两个**独立 crate**，只靠一句契约对接：
/// 「`unsignedtxdatahex` 是结构完整、只差签名的 RLP 未签名交易」。
/// 契约一旦漂移（比如 SDK 哪天改成只发 32 字节待签哈希），
/// 两侧各自的测试仍然全绿，**只有这条真实向量的解码测试会红**——
/// 这正是跨 crate 集成最该守的位置。
///
/// # 为什么用主网真实数据而不是随手编
///
/// 编造的字节会被「两边用同一个错误实现」掩盖：SDK 写错、sign 用同样的错法解，
/// 照样通过。真实数据是从链上 nonce / gas 估价算出来的，字段值无法用假数据凑齐。
///
/// # 为什么放在文件层而不是 `mod tests` 里
///
/// `sign.rs` 的分派测试要复用它来证明「`eth` 确实被路由到了 `sign_eth`」。
/// `mod tests` 是私有模块，父模块 `sign` 访问不到它里面的 `const`；
/// 放到文件层并标 `pub(crate)` 就能共享，也避免在两个文件里各抄一份真实向量
/// （抄两份的后果是：哪天向量更新了，只有一处跟着改，另一处悄悄过期）。
///
/// 语法：`#[cfg(test)]` 表示它只在 `cargo test` 编译期存在，
/// release 构建里连字节都不会进二进制。
#[cfg(test)]
pub(crate) const SDK_UNSIGNED_TX_HEX: &str =
    "0x02ef018217448301c5b284076c6f468252089428c6c06298d514db089934071355e5743bf21d6087038d7ea4c6800080c0";

#[cfg(test)] mod tests;
