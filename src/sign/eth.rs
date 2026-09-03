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
//! - **输入**：`txdatahex` —— hex 字符串（可带 `0x`），解码后是**完整交易**的 RLP 编码
//!   （结构完整、只差签名；typed / legacy 均可），对应 MetaMask 离线签名那一套输入。
//! - **输出**：`signed_tx` = hex 的 `EthereumTxEnvelope` RLP 字节，
//!   可直接交给 `eth_sendRawTransaction`。

use alloy::consensus::TypedTransaction;
use alloy::eips::eip2718::Encodable2718;
use alloy::network::TxSigner;
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
fn decode_unsigned_tx(txdata: &[u8]) -> anyhow::Result<TypedTransaction> {
    let mut buf = txdata;
    TypedTransaction::decode_unsigned(&mut buf)
        .map_err(|e| anyhow::anyhow!("ETH 交易解码失败（需 RLP 未签名交易）: {e}"))
}

pub async fn sign_eth(txdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。各链自己解码，报错时才能说清「这段字节本该是什么」。
    let txdata = decode_txdata(txdatahex, "ETH 完整交易（RLP 未签名交易）")?;

    let sk = SigningKey::from_slice(&key.seed)
        .map_err(|e| anyhow::anyhow!("ETH 种子非法: {e}"))?;
    let signer = PrivateKeySigner::from_signing_key(sk);

    let mut typed = decode_unsigned_tx(&txdata)?;

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

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signed_tx: Some(format!("0x{}", hex::encode(tx_bytes))),
        encoding: "hex".to_string(),
        note: None,
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
/// 「`txdatahex` 是结构完整、只差签名的 RLP 未签名交易」。
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
