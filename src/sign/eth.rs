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

#[cfg(test)]
mod tests {
    use super::*;
    // `nonce` / `value` / `gas_limit` 这些**读取类**方法不在 `TypedTransaction`
    // 的固有实现里，而是来自 alloy-consensus 的 `Transaction` trait。
    // 必须先把它引入作用域才能调用——Rust 的方法解析要求 trait 在作用域内，
    // 光是类型实现了 trait 不够（这是为了避免两个 trait 提供同名方法时产生歧义）。
    // 路径是 `alloy::consensus` 而非 `alloy::alloy_consensus`：后者是 alloy 内部
    // crate 的名字，只在开了对应 feature 时才会被 `alloy` 门面再导出一层。
    // 报错里提示的 `alloy::alloy_consensus` 是编译器的猜测，按它写会 `unresolved import`。
    use alloy::consensus::Transaction;
    // `StoredKey.scheme` 的类型。`sign_eth` 只用得到 `seed`，
    // 但构造 `StoredKey` 字面量必须填满所有字段，所以这里要把 `Scheme` 也引进来。
    use crate::store::Scheme;
    #[test]
    fn decodes_the_unsigned_tx_that_the_sdk_actually_emits() {
        // 本 crate 没有 `hexutil`（那是 SDK workspace 的），这里手动剥 `0x`。
        // `trim_start_matches` 会把连续的前缀全去掉，对 `0x…` 而言恰好只去一次。
        let body = SDK_UNSIGNED_TX_HEX.trim_start_matches("0x");
        let bytes = hex::decode(body).expect("向量应是合法 hex");
        let typed = decode_unsigned_tx(&bytes).expect("SDK 产出的未签名交易必须能被解码");

        // 类型字节：0x02 = EIP-1559。
        assert_eq!(bytes[0], 0x02, "向量应为 EIP-1559 交易");

        // 往返一致性：解码后重新 RLP 编码必须逐字节还原。
        // 这一条比逐个字段断言更强——它同时钉住了字段**顺序**与整数的最小编码。
        //
        // 为什么要先 `match` 出 `Eip1559` 变体：`TypedTransaction` 是个枚举，
        // 它本身没有无歧义的 RLP 编码（不同变体的类型字节不同）。先匹配变体，
        // 既拿到了可编码的具象类型，又顺带断言了「解出来确实是 EIP-1559 而不是别的」。
        //
        // `let ... else` 是 Rust 1.65+ 的写法：匹配失败时**必须** diverge
        // （`panic!` / `return` / `break`），否则变量在 else 分支外就没有值了。
        let TypedTransaction::Eip1559(eip1559) = &typed else {
            panic!("SDK 产出的向量应解为 EIP-1559，实际是 {typed:?}");
        };
        let mut rebuilt = vec![0x02u8]; // EIP-2718 类型字节
        rebuilt.extend_from_slice(&alloy::rlp::encode(eip1559));
        assert_eq!(
            hex::encode(&rebuilt),
            body,
            "解码再编码应逐字节还原；不一致说明 SDK 的序列化与本 crate 的解码对不上"
        );

        // 字段级断言：即便往返碰巧一致，也要确认解出来的**语义**对得上真实链上状态。
        // 这些值来自 ETH 主网查询（nonce 是那个地址当时的真实值，不是编的）。
        assert_eq!(typed.nonce(), 5956, "nonce 应解为该地址当时的真实值");
        assert_eq!(
            typed.chain_id(),
            Some(1),
            "EIP-1559 必须带 chain_id，否则跨链重放防护失效"
        );
        assert_eq!(
            typed.value(),
            alloy::primitives::U256::from(1_000_000_000_000_000u64),
            "0.001 ETH = 1e15 wei"
        );
        assert_eq!(u128::from(typed.gas_limit()), 21_000, "纯转账固定 21000 gas");
    }

    /// **端到端产出**：`signed_tx` 必须是**裸的 EIP-2718 交易**，不能多套一层 RLP。
    ///
    /// # 这个 bug 是怎么藏住的
    ///
    /// 原本写的是 `alloy::rlp::encode(&envelope)`，产出 `0xb87502f872…`——
    /// 前面多出 `b8 75`（RLP 长字符串头，意为「后面 117 字节」）。
    /// 节点期望的裸 typed transaction 应以类型字节 `02` 开头，
    /// 收到多一层封装的字节会直接拒绝。
    /// 而在此之前本文件**只有解码测试、没有任何签名产出的测试**，
    /// 所以它能藏在 60+ 项全绿的测试里，直到活体冒烟去断言 `starts_with("0x02")` 才暴露。
    ///
    /// # 反证的那一半
    ///
    /// 只断言「以 0x02 开头」还不够稳（万一将来改用别的类型字节呢），
    /// 所以再断言「不以 RLP 字符串头开头」，并把**解回来**的字段与原交易逐一对照。
    #[tokio::test]
    async fn signed_tx_is_a_bare_eip2718_envelope() {
        use alloy::consensus::{EthereumTxEnvelope, TxEip1559};
        use alloy::eips::eip2718::Decodable2718;

        // 固定种子，让测试可复现（1…1 是合法的 secp256k1 标量）。
        let key = StoredKey { scheme: Scheme::Secp256k1, seed: [1u8; 32] };
        let r = sign_eth(SDK_UNSIGNED_TX_HEX, &key)
            .await
            .expect("真实向量应能签名");
        let raw = r.signed_tx.expect("ETH 必须产出 signed_tx");

        // 主断言：类型字节 0x02 = EIP-1559。
        assert!(
            raw.starts_with("0x02"),
            "signed_tx 应以 EIP-1559 类型字节 0x02 开头，实际: {raw}"
        );
        // 反证：不能带 RLP 字符串头。`b8` 是「长字符串」头，
        // 它出现在开头就说明又套了一层。
        assert!(
            !raw.starts_with("0xb8"),
            "signed_tx 不应带 RLP 长字符串头（说明多套了一层 RLP 封装），实际: {raw}"
        );

        // 往返：解回来后字段必须与原交易一致——只比对前缀挡不住「类型字节对但内容错」。
        let bytes = hex::decode(&raw[2..]).expect("signed_tx 应是合法 hex");
        let decoded: EthereumTxEnvelope<TxEip1559> =
            EthereumTxEnvelope::decode_2718(&mut bytes.as_slice())
                .expect("产出的字节必须能被解回一个信封");
        assert_eq!(
            decoded.nonce(),
            5956,
            "解回来的 nonce 应与原交易一致（说明签的是同一笔交易）"
        );
        assert_eq!(decoded.chain_id(), Some(1), "解回来的 chain_id 应为 1");
        assert_eq!(
            decoded.value(),
            alloy::primitives::U256::from(1_000_000_000_000_000u64),
            "解回来的金额应为 0.001 ETH"
        );
    }

    /// 反向反证：**只**喂一个 32 字节哈希必须失败。
    ///
    /// 没有这条，上面那条可能在「解码器来者不拒」的情况下恒真。
    /// 32 字节在 RLP 里会被当成 32 字节的字符串，解不成一个交易列表，应当报错。
    #[test]
    fn rejects_a_bare_32_byte_signing_hash() {
        let hash = vec![0xab_u8; 32];
        assert!(
            decode_unsigned_tx(&hash).is_err(),
            "契约规定输入是完整交易而非单独的待签哈希；喂哈希必须报错，\
             否则调用方传错东西时会静默签出无效签名"
        );
    }
}
