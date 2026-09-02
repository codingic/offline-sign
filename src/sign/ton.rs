//! TON：仅做 ed25519 签名，**不组装** external message。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # 为什么 TON 是六条链里的例外
//!
//! TON 的真实地址由**钱包合约的 code + state-init** 共同决定，仅凭公钥算不出来；
//! 而一笔可广播的 external message 又必须带上 state-init（首次部署时）。
//! 通用离线签名器既不知道用户用的是哪个钱包版本（v3 / v4 / highload），
//! 也不知道该不该带 init，因此这里**刻意只返回签名**，`signed_tx` 恒为 `None`。
//! 强行在这里拼 message 会产出「能广播但打到错误地址」的交易，那比不做更危险。
//!
//! # 输入 / 输出契约
//!
//! - **输入**：`txdatahex` —— hex 字符串（可带 `0x`），解码后是 external message 的
//!   **完整序列化字节**——与其余各链口径一致，是「结构完整、只差签名」的交易本体，
//!   **不是**单独的待签哈希或摘要。
//! - **输出**：`signature` = `0x` + 64 字节 ed25519 签名 hex；`signed_tx` = `None`。

use ed25519_dalek::{Signer, SigningKey};

use crate::sign::{SignedResult, decode_txdata};
use crate::store::StoredKey;

/// TON 签名：对给定字节做 ed25519 签名，不做任何交易组装。
///
/// # 领域要点
///
/// 这里**不校验**输入是不是合法的 TON 消息：本函数只保证「用这把私钥对这段字节
/// 签出了有效签名」。判断该签什么，是调用方（钱包层）的责任。
///
/// # 一个需要留意的口径
///
/// 本函数直接对**收到的完整字节**签名，内部**不额外做 sha256**。
/// 这是刻意的：与其余各链保持同一口径——签传入的完整交易字节，
/// 而不是由签名服务替调用方决定「该签原文还是签哈希」。
///
/// 若某个上游场景约定的是「签 body 的哈希」（TON 钱包常见做法），
/// 应由调用方在构造 `txdatahex` 时就传入哈希后的字节，或明确要求本函数加一步哈希；
/// **不要**默默在这里加，否则其余五条链的口径就不一致了。
pub fn sign_ton(txdatahex: &str, key: &StoredKey) -> anyhow::Result<SignedResult> {
    // hex 字符串 -> 字节。TON 是唯一不解析字节结构的链（只做裸签名），
    // 但解码仍要在本函数内完成：调用方给的是字符串，解码失败得由这里说清楚。
    let txdata = decode_txdata(txdatahex, "TON external message（完整序列化字节）")?;

    let sk = SigningKey::from_bytes(&key.seed);
    let sig = sk.sign(&txdata);
    // 单签名链：见 `eth.rs` 里同名的说明。
    let sig_hex = format!("0x{}", hex::encode(sig.to_bytes()));

    Ok(SignedResult {
        signature: sig_hex.clone(),
        signatures: vec![sig_hex],
        signed_tx: None,
        encoding: "hex".to_string(),
        note: Some(
            "TON 仅返回 ed25519 签名；完整 external message 组装需钱包 code + state-init，通用签名器不负责"
                .to_string(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Scheme;
    use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};

    fn fixture_key() -> StoredKey {
        StoredKey {
            scheme: Scheme::Ed25519,
            seed: [6u8; 32],
        }
    }

    /// **端到端口径**：签的就是**收到的原始字节**，中间**不额外做 sha256**。
    ///
    /// 这条契约很容易被「好心」改坏：TON 钱包常见做法是签 body 的哈希，
    /// 于是后来者可能顺手在这里加一步 `sha256`。加了以后签名仍然完全合法，
    /// 但**节点验的是原文**，于是永远拒绝——本地却一片绿。
    ///
    /// 判据用 dalek 验「原文」，而不是用本实现自己算的东西对照。
    #[test]
    fn signs_the_raw_bytes_without_an_extra_hash() {
        let key = fixture_key();
        // 用一段能看出「没被哈希」的形态：不是 32 字节，长度也不是哈希输出长度。
        let body: Vec<u8> = b"ton external message body".to_vec();
        let txdatahex = hex::encode(&body);

        let out = sign_ton(&txdatahex, &key).expect("合法 hex 应能签名");

        let sig_hex = out.signature.strip_prefix("0x").expect("出参应带 0x");
        let sig: [u8; 64] = hex::decode(sig_hex)
            .expect("签名应是合法 hex")
            .try_into()
            .expect("ed25519 签名应是 64 字节");

        let sk = SigningKey::from_bytes(&key.seed);
        let vk = VerifyingKey::from(&sk);
        assert!(
            vk.verify(&body, &DalekSignature::from_bytes(&sig)).is_ok(),
            "签名必须验得过**原始字节**；验不过说明内部多加了一步哈希，\
             那会导致节点验签失败（节点验的是原文）"
        );

        // 反证：签名必须**严格绑定**在这段字节上。
        // 没有这条，上面的 `verify` 有可能因为实现上的意外（比如验的是空消息）而恒真。
        let mut tampered = body.clone();
        tampered[0] ^= 0x01;
        assert!(
            vk.verify(&tampered, &DalekSignature::from_bytes(&sig))
                .is_err(),
            "改动任意一个字节后必须验签失败——否则说明签名没有真正绑定到原文"
        );
    }

    /// TON 刻意**不**组装交易：`signed_tx` 恒为 `None`，并给出说明。
    #[test]
    fn never_assembles_a_full_transaction() {
        let out = sign_ton("0x00ff", &fixture_key()).expect("合法 hex 应能签名");
        assert!(
            out.signed_tx.is_none(),
            "TON 必须只返回签名：完整 external message 需要钱包 code + state-init，\
             通用签名器拼出来会打到错误地址"
        );
        let note = out.note.expect("TON 应给出说明，避免调用方误以为能用 signed_tx");
        assert!(note.contains("钱包"), "说明应点明原因，实际: {note}");
    }

    /// 非 hex 输入必须报错，且错误信息点名 TON。
    #[test]
    fn non_hex_txdata_is_rejected() {
        let err = sign_ton("0xZZZZ", &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("TON"),
            "错误信息应带链名以便定位，实际: {err}"
        );
    }
}
