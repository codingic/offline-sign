//! APT（Aptos）：ed25519 签名 + BCS 交易重组（输出 hex）。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`txdatahex` —— hex 字符串（可带 `0x`），解码后是**完整交易**的
//!   BCS 编码，即 `aptos_sdk::transaction::types::RawTransaction`
//!   （Aptos 里未签名交易就叫 RawTransaction，它本身就是结构完整的交易体）。
//! - **输出**：`signed_tx` = hex 的 BCS `SignedTransaction`，可直接 `submit`。
//!
//! # 与 SUI 的对比（两个最容易被写反的邻居）
//!
//! APT 与 SUI 都用 ed25519 + BCS，但**待签字节的构造完全不同**：
//! - APT：直接签 `BCS(RawTransaction)`，没有前缀；
//! - SUI：签 `intent(3 字节) ‖ BCS(Transaction)`，intent 在前。
//!
//! 两者混用不会报错，只会产出一条节点永远拒绝的交易——属于「静默失败」，
//! 所以分文件、各自写清契约，比挤在一起靠注释区分更安全。

use aptos_sdk::crypto::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use aptos_sdk::transaction::authenticator::TransactionAuthenticator;
use aptos_sdk::transaction::types::{RawTransaction, SignedTransaction};

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// APT 签名：对 RawTransaction 签名，BCS 组装 SignedTransaction（hex）。
///
/// # 领域要点
///
/// Aptos 的 `SignedTransaction` = `RawTransaction` + `TransactionAuthenticator`。
/// authenticator 要同时带上**公钥与签名**，因为节点只有交易本身，
/// 并不知道签名者是谁（Aptos 的账户地址是 `sha3-256(公钥 ‖ 0x00)`，
/// 只有拿到公钥才能反推出该用哪个账户的序列号与余额）。
pub fn sign_apt(txdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。各链自己解码，报错时才能说清「这段字节本该是什么」。
    let txdata = decode_txdata(txdatahex, "APT 完整交易（BCS RawTransaction）")?;

    let sk = Ed25519PrivateKey::from_bytes(&key.seed)
        .map_err(|e| anyhow::anyhow!("APT 私钥重建失败: {e}"))?;
    let raw: RawTransaction = bcs::from_bytes(&txdata)
        .map_err(|e| anyhow::anyhow!("APT 交易解码失败（需 BCS RawTransaction）: {e}"))?;

    // ⚠️ **待签字节不是 `BCS(RawTransaction)`**，而是
    //   `sha3_256("APTOS::RawTransaction")` ‖ `BCS(RawTransaction)`
    //
    // 前面那 32 字节是 Aptos 的**域分离盐**（domain separation salt）。
    // 直接签裸 BCS 时：签名在数学上完全合法、本地验签也能过，
    // 但节点会判定「签的不是这笔交易」而拒绝——不报错、不上链，属于最难排查的一类失败。
    //
    // 所以这里**不自己拼**，而是直接调官方 `signing_message()`：
    // 期望值/算法来自官方实现，才算对拍；自己拼一遍等于自证，官方哪天改了口径也发现不了。
    // 底部测试 `signature_verifies_against_the_official_signing_message` 用同一个官方函数
    // 当判据把这条钉死了（并配了反证：盐确实改变了待签字节）。
    let raw_bytes = raw
        .signing_message()
        .map_err(|e| anyhow::anyhow!("APT signing_message 计算失败: {e}"))?;
    // aptos-crypto 的 `sign` 直接返回签名（非 Result）。
    let signature: Ed25519Signature = sk.sign(&raw_bytes);
    let public_key: Ed25519PublicKey = sk.public_key();

    // SignedTransaction 由 RawTransaction + TransactionAuthenticator 组成；
    // authenticator 的 ed25519 构造接收 (公钥字节, 签名字节)。
    let authenticator = TransactionAuthenticator::ed25519(
        public_key.to_bytes().to_vec(),
        signature.to_bytes().to_vec(),
    );
    let signed = SignedTransaction::new(raw, authenticator);
    let out = bcs::to_bytes(&signed)
        .map_err(|e| anyhow::anyhow!("APT 交易重组失败: {e}"))?;

    // 单签名链：见 `eth.rs` 里同名的说明。
    let sig_hex = format!("0x{}", hex::encode(signature.to_bytes()));

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signed_tx: Some(format!("0x{}", hex::encode(out))),
        encoding: "hex".to_string(),
        note: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Scheme;
    use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};

    /// 一条确定性构造的 `RawTransaction`（字段抄自 aptos-sdk 自带测试的夹具）。
    ///
    /// 用固定值而非随机值，是为了让整条断言链可复现。
    fn fixture_raw_tx() -> RawTransaction {
        use aptos_sdk::transaction::payload::{EntryFunction, TransactionPayload};
        use aptos_sdk::types::{AccountAddress, ChainId, MoveModuleId};

        RawTransaction::new(
            AccountAddress::ONE,
            0,
            TransactionPayload::EntryFunction(EntryFunction {
                module: MoveModuleId::from_str_strict("0x1::coin").unwrap(),
                function: "transfer".to_string(),
                type_args: vec![],
                args: vec![],
            }),
            100_000,
            100,
            1_000_000_000,
            ChainId::testnet(),
        )
    }

    /// **端到端产出**：`sign_apt` 的签名必须能通过**官方 `signing_message()`** 的验签。
    ///
    /// # 这条测试抓到过一个真实缺陷
    ///
    /// Aptos 的待签字节**不是**裸的 `BCS(RawTransaction)`，而是
    /// `sha3_256("APTOS::RawTransaction")` ‖ `BCS(RawTransaction)` —— 前面有 32 字节盐。
    /// 少算这 32 字节时，签名在数学上完全合法、本地验签也过得去，
    /// 但节点会判定「签的不是这笔交易」而拒绝：不报错、不上链。
    ///
    /// 这里不自己去拼那个盐，而是直接调官方 `RawTransaction::signing_message()` 当
    /// **判据**——期望值来自另一个实现，才算对拍；自己拼一遍就等于自证。
    #[test]
    fn signature_verifies_against_the_official_signing_message() {
        let raw = fixture_raw_tx();
        let txdatahex = hex::encode(bcs::to_bytes(&raw).expect("RawTransaction 应可 BCS 序列化"));
        let key = StoredKey {
            scheme: Scheme::Ed25519,
            seed: [7u8; 32],
        };

        let out = sign_apt(&txdatahex, &key).expect("合法的 RawTransaction 应能签名");

        // 判据：官方口径的待签字节（含 32 字节盐前缀）。
        let official = raw
            .signing_message()
            .expect("官方应能算出 signing_message");

        let sig_hex = out.signature.strip_prefix("0x").expect("出参应带 0x 前缀");
        let sig_bytes: [u8; 64] = hex::decode(sig_hex)
            .expect("签名应是合法 hex")
            .try_into()
            .expect("ed25519 签名应是 64 字节");

        let sk = Ed25519PrivateKey::from_bytes(&key.seed).expect("种子应可重建私钥");
        // `to_bytes()` 已经返回 `[u8; 32]`——不需要再 `try_into`，
        // 多余的转换会被 clippy 的 `useless_conversion` 拦下。
        let pk_bytes: [u8; 32] = sk.public_key().to_bytes();
        let vk = VerifyingKey::from_bytes(&pk_bytes).expect("公钥应可解析");
        let dalek_sig = DalekSignature::from_bytes(&sig_bytes);

        assert!(
            vk.verify(&official, &dalek_sig).is_ok(),
            "sign_apt 的签名必须能验过官方 signing_message（= sha3_256(\"APTOS::RawTransaction\") ‖ BCS）；\
             验不过说明待签字节的口径错了——这是「本地全绿、只有节点拒绝」那类缺陷"
        );
    }

    /// **反证**：上面那条断言不能是空的——盐前缀确实改变了待签字节。
    ///
    /// 若 `signing_message()` 恰好就等于 `BCS(raw)`（即盐是空的），
    /// 上一条测试就会退化成「签裸 BCS 也能过」，从而永远为真。
    /// 这里断言：**裸 BCS 字节 ≠ 官方 signing_message**，且用裸字节验签必然失败。
    #[test]
    fn the_salt_prefix_actually_changes_the_signing_message() {
        let raw = fixture_raw_tx();
        let bare = bcs::to_bytes(&raw).expect("应可 BCS 序列化");
        let official = raw
            .signing_message()
            .expect("官方应能算出 signing_message");

        assert_ne!(
            bare, official,
            "官方 signing_message 必须比裸 BCS 多出 32 字节盐前缀；\
             若两者相等，前一条测试就是空的"
        );
        assert_eq!(
            official.len(),
            bare.len() + 32,
            "盐前缀应恰好 32 字节（sha3-256 的输出长度）"
        );
        assert_eq!(
            &official[..32],
            aptos_sdk::crypto::sha3_256(b"APTOS::RawTransaction").as_slice(),
            "前缀应等于 sha3_256(\"APTOS::RawTransaction\")"
        );

        // 用**裸 BCS 字节**验同一个签名必须失败——证明盐不是摆设。
        let key = StoredKey {
            scheme: Scheme::Ed25519,
            seed: [7u8; 32],
        };
        let out = sign_apt(&hex::encode(&bare), &key).expect("应能签名");
        let sig_hex = out.signature.strip_prefix("0x").unwrap();
        let sig_bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();
        let sk = Ed25519PrivateKey::from_bytes(&key.seed).unwrap();
        let pk_bytes: [u8; 32] = sk.public_key().to_bytes();
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let dalek_sig = DalekSignature::from_bytes(&sig_bytes);

        assert!(
            vk.verify(&bare, &dalek_sig).is_err(),
            "若签名是对裸 BCS 做的，它就不该验过裸 BCS——\
             这条只在实现已修好（签的是带盐的消息）时成立"
        );
    }

    /// 非 BCS 的垃圾输入必须报错，且错误信息点名 APT。
    #[test]
    fn garbage_txdata_is_rejected() {
        let key = StoredKey {
            scheme: Scheme::Ed25519,
            seed: [7u8; 32],
        };
        // 合法 hex，但不是 BCS RawTransaction。
        let err = sign_apt(&"ab".repeat(32), &key).unwrap_err();
        assert!(
            err.to_string().contains("APT"),
            "错误信息应带链名以便定位，实际: {err}"
        );
    }
}
