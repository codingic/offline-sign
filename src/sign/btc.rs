//! BTC：逐输入重算 sighash 并签名，**只出签名，不组装交易**。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # BTC 与其余六条链的根本差异：待签对象有 N 个
//!
//! 其余链都是账户模型，一笔交易只有一个待签哈希。BTC 是 **UTXO 模型**，
//! 签名粒度是「每个输入一个」：N 个输入 → N 个 sighash → N 个签名。
//! 且每个 sighash 覆盖「全部输入 + 全部输出」的组合摘要，
//! **改动任何一个输入都会让其它所有输入的签名失效**。
//!
//! # 为什么必须额外收一个 `context`
//!
//! P2WPKH 的 sighash 走 **BIP143**，它把**当前输入的金额**也混进哈希——
//! 这正是为了堵住硬件钱包「被隐瞒真实输入金额 → 少找零」的攻击面。
//! 但金额**不在交易字节里**，所以只凭 `txdatahex` 算不出正确的 sighash。
//!
//! `context` 就是 SDK `build_transfer` 下发的 `extra.submit_context`，
//! 里面带齐了每个输入的 `value` 与 `script_pubkey`。
//!
//! # 分工：sign 只签名，SDK 只组装
//!
//! 本函数**不**做 DER 编码、**不**做低 S 归一化（BIP62）、**不**填见证 / scriptSig。
//! 这三件事都由 SDK 的 `submit_tx` 在重组时完成，并在广播前逐个验签。
//!
//! 理由与 TON 一致：让签名器去拼交易，出错时产出的是**格式合法但语义错误**的字节——
//! 本地签名成功、序列化成功，直到广播才被节点以
//! `non-mandatory-script-verify-flag` 拒掉，而错误信息不会告诉你错在哪一步。
//!
//! # 为什么自己重算 sighash，而不是直接用 SDK 下发的 `signing_payloads`
//!
//! SDK 的 `extra.signing_payloads[].sighash` 本来就是现成的摘要，直接签它最省事。
//! 但那意味着**盲信**对侧：一旦上下文在往返途中被改过（或调用方传错了笔交易），
//! 签出来的签名照样是「有效签名」，只是签在另一笔交易上——而这类错误
//! 在广播前不会有任何提示。
//!
//! 自己从 `txdatahex` + `context` 重算，并在签之前校验两者描述的是同一笔交易，
//! 就把「盲信」变成了「验证后使用」。
//!
//! # 输入 / 输出契约
//!
//! - **输入 `txdatahex`**：序列化后的**未签名交易**（`unsigned_tx_hex`，
//!   scriptSig / witness 均为空），与其余各链口径一致。
//! - **输入 `context`**：SDK 下发的 `submit_context`；必须与 `txdatahex` 描述同一笔交易。
//! - **输出**：`signatures` = 与输入一一对应的 **64 字节紧凑签名**（`r || s`）十六进制数组；
//!   `signed_tx` = `None`（组装是 SDK 的事）。

use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, ScriptBuf, Transaction};
use serde::Deserialize;
use serde_json::Value;

use crate::sign::{SignedResult, decode_txdata, strip_0x};
use crate::store::{Scheme, StoredKey};

/// 紧凑签名的长度：`r(32) || s(32)`。
const COMPACT_SIGNATURE_LEN: usize = 64;

/// 本服务只认主网（理由见 `keys::btc_info`：地址编码含网络前缀，换网络就是另一套地址）。
const EXPECTED_NETWORK: &str = "mainnet";

/// SDK `build_transfer` 下发的 `extra.submit_context`——**只挑本函数需要的字段**。
///
/// # 为什么在这里重新定义一份，而不是直接依赖 SDK 的 crate
///
/// sign 是**独立** crate，这是刻意的：离线签名器的全部价值就在于它不碰网络，
/// 依赖 SDK 会把「离线签名器」和「联网查询器」绑进同一个编译单元。
///
/// # 为什么只挑需要的字段
///
/// 挑字段而非全量镜像，让「契约」保持最小：SDK 往上下文里加信息性字段时，
/// 本 crate 不需要跟着改。但**改名或改类型**会在这里表现为解析失败，
/// 而不是静默漏掉一个字段——这正是我们想要的方向：
/// 「少一个字段」必须报错，不能变成「按默认值继续」。
#[derive(Debug, Deserialize)]
struct SubmitContext {
    network: String,
    /// 签名所用公钥（压缩格式，33 字节，十六进制）。
    public_key: String,
    inputs: Vec<ContextInput>,
    /// 构造阶段的未签名交易字节，用于校验「上下文与 txdatahex 是同一笔交易」。
    unsigned_tx_hex: String,
}

/// 上下文里的单个输入：只挑 sighash 计算真正需要的三项。
#[derive(Debug, Deserialize)]
struct ContextInput {
    /// 该输入值多少 satoshi——**BIP143 sighash 需要它**，而它不在交易字节里。
    value: u64,
    /// 锁定脚本 `scriptPubKey` 的十六进制。
    script_pubkey: String,
    /// 脚本类型：`p2wpkh` / `p2pkh`。两者 sighash 算法不同。
    script_type: String,
}

/// BTC 签名：从 `txdatahex` + `context` 重算逐输入 sighash，逐个签出 64 字节紧凑签名。
///
/// # 输入 / 输出都是 hex 字符串
///
/// - **入参 `txdatahex: &str`**：序列化后的**未签名交易**的 hex（可带 `0x`、可有首尾空白）。
/// - **出参**：每个输入一个 `"0x" + 128 位 hex`，即 64 字节紧凑签名 `r(32) ‖ s(32)`。
///
/// 两端都用 hex 字符串，是为了与 HTTP 请求体里的 `txdatahex` 字段、以及 SDK
/// `submit_tx` 期望的签名数组形态**直接对齐**，中间不再有一次「谁负责编解码」的猜测。
///
/// # 语法要点
///
/// `context: &Value` 而非 `&SubmitContext`：调用方拿到的是 HTTP 请求体里的裸 JSON，
/// 这里才做「结构化」。把反序列化留在本函数内部，错误处理就能带上
/// 「你传的应该是什么」这句人话，而不是一句类型不匹配。
pub fn sign_btc(
    txdatahex: &str,
    context: &Value,
    key: &StoredKey,
) -> anyhow::Result<SignedResult> {
    if key.scheme != Scheme::Secp256k1 {
        return Err(anyhow::anyhow!(
            "BTC 需要 secp256k1 密钥，实际拿到的是 {}",
            key.scheme.as_str()
        ));
    }

    // `from_value` 要**吃掉** `Value`（不是借用），故这里克隆一份。
    // 上下文最多几十字段，一次克隆的开销远小于为省它而改造整条调用链。
    let ctx: SubmitContext = serde_json::from_value(context.clone()).map_err(|e| {
        anyhow::anyhow!(
            "context 解析失败（应原样传 build_transfer 下发的 extra.submit_context）: {e}"
        )
    })?;

    // —— 第一道：网络必须是主网 ——
    //
    // 地址编码含网络前缀，跨网签出的签名最终会被 SDK 的跨网护栏拦下，
    // 但那已经绕了一整圈；在这里拦，错误信息能直接指出问题。
    if ctx.network != EXPECTED_NETWORK {
        return Err(anyhow::anyhow!(
            "只支持 {} 上下文，收到 {}",
            EXPECTED_NETWORK,
            ctx.network
        ));
    }

    // —— 第二道：`txdatahex` 与 context 必须描述同一笔交易 ——
    //
    // 这是整条链路上最重要的一次校验：金额与脚本来自 context、交易结构来自 txdatahex，
    // 两者若不是同一次 `build_transfer` 的产物，下面每一步都会「正常执行」，
    // 只是签在了另一笔交易上。
    // 先解成字节：后续反序列化、重序列化、算 sighash 全都要字节形态。
    // `decode_txdata` 只负责「hex 字符串 -> 字节」，错误信息里的
    // 「序列化的未签名交易」是本链补的那句话。
    let txdata = decode_txdata(txdatahex, "BTC 未签名交易（序列化的未签名交易）")?;
    let tx: Transaction = encode::deserialize(&txdata)
        .map_err(|e| anyhow::anyhow!("BTC 交易解码失败（需序列化的未签名交易）: {e}"))?;
    let tx_hex = encode::serialize_hex(&tx);
    if tx_hex != strip_0x(ctx.unsigned_tx_hex.trim()) {
        return Err(anyhow::anyhow!(
            "txdatahex 与 context.unsigned_tx_hex 不是同一笔交易：\
             两者必须来自同一次 build_transfer，否则签名会落在另一笔交易上"
        ));
    }

    // —— 输入数量不再单独预检 ——
    //
    // 数量一致性由下面的签名循环**就地**保证：循环以 `tx.input` 为权威集合、
    // 用 `index` 去 `ctx.inputs` 取元数据。少一条会在循环里立刻报
    // 「缺第 N 个输入的元数据」（不会静默少签）；多一条则根本用不到、被忽略
    // （良性）。这样「签 input」就是唯一入口，不必再写一行看起来像第二道冗余的
    // count 判断——第三道已融进循环，见下方 `for` 循环。

    // —— 第四道：context 里的公钥必须就是本密钥的公钥 ——
    //
    // 若不是同一把钥匙，签出的签名在 SDK 验签时必然失败；
    // 在这里拦，能直接说清「钥匙和交易不是一套」，而不是留给对侧一句「验签失败」。
    let secret = SecretKey::from_slice(&key.seed)
        .map_err(|e| anyhow::anyhow!("BTC 种子不是合法 secp256k1 私钥: {e}"))?;
    let secp = Secp256k1::new();
    // `from_secret_key` 返回的 `PublicKey` 用 `serialize()` 输出时就是**压缩**格式（33 字节），
    // 与 context 里存的格式一致。
    let ours = SecpPublicKey::from_secret_key(&secp, &secret).serialize();
    let theirs = hex::decode(strip_0x(ctx.public_key.trim())).map_err(|e| {
        anyhow::anyhow!("context.public_key 不是合法十六进制: {e}")
    })?;
    // `as_slice()` 而非直接 `!=`：`ours` 是定长数组 `[u8; 33]`、`theirs` 是 `Vec<u8>`，
    // 两者没有现成的 `PartialEq` 实现（只有 `Vec<u8> == [u8; 33]` 这一个方向）。
    // 统一转成切片比较，顺带让长度不等时也走同一条比较路径。
    if ours.as_slice() != theirs.as_slice() {
        return Err(anyhow::anyhow!(
            "context.public_key 与本 keystore 的公钥不一致：\
             该上下文是用另一把钥匙的公钥构造的，签出来的签名 SDK 必然验签失败"
        ));
    }

    // —— 逐输入算 sighash 并签名 ——
    //
    // `SighashCache` 会缓存中间结果（如全部输出的哈希），
    // 逐输入签名时能避免重复计算，所以它要求 `&mut self`。
    let mut cache = SighashCache::new(&tx);
    let mut signatures: Vec<[u8; COMPACT_SIGNATURE_LEN]> = Vec::with_capacity(tx.input.len());

    // 循环**以 `tx.input` 为准**：交易的真实输入就是必须签的全部，
    // 每个 `index` 去 `ctx.inputs` 取签名元数据。取不到说明 context 的 inputs
    // 比交易少——这正是「静默少签」的唯一切口，必须当场报错，
    // 不能让 `for` 提前结束、悄悄少签。多出来的 `ctx.inputs` 条目用不到，
    // 自然被忽略（多一条是良性情况，不再报错）。
    for (index, _input) in tx.input.iter().enumerate() {
        let meta = match ctx.inputs.get(index) {
            Some(m) => m,
            None => return Err(anyhow::anyhow!(
                "context 缺少第 {index} 个输入的签名元数据：inputs 必须与交易的输入一一对应"
            )),
        };
        // `ScriptBuf::from(Vec<u8>)` 直接吃解码后的字节；
        // 没有校验脚本是否合法——sighash 计算只把它当字节串用，
        // 而上下文是 SDK 产出的，脚本合法性由 SDK 侧保证。
        let script = ScriptBuf::from(
            hex::decode(strip_0x(meta.script_pubkey.trim())).map_err(|e| {
                anyhow::anyhow!("第 {index} 个输入的 script_pubkey 不是合法十六进制: {e}")
            })?,
        );

        // 两种脚本的 sighash 算法**不同**：
        // - p2wpkh 走 BIP143，把输入金额也混进哈希（堵少找零攻击）；
        // - p2pkh 走传统算法，不含金额。
        // 用错算法不会报错，只会产出永远无效的签名，所以这里按标签严格分派，
        // 未知标签直接拒绝而不是「按 p2wpkh 兜底」。
        let sighash = match meta.script_type.as_str() {
            "p2wpkh" => cache
                .p2wpkh_signature_hash(
                    index,
                    &script,
                    Amount::from_sat(meta.value),
                    EcdsaSighashType::All,
                )
                .map_err(|e| anyhow::anyhow!("第 {index} 个输入的 BIP143 sighash 计算失败: {e}"))?
                .to_byte_array(),
            "p2pkh" => cache
                .legacy_signature_hash(index, &script, EcdsaSighashType::All.to_u32())
                .map_err(|e| anyhow::anyhow!("第 {index} 个输入的传统 sighash 计算失败: {e}"))?
                .to_byte_array(),
            other => {
                return Err(anyhow::anyhow!(
                    "第 {index} 个输入是不支持的脚本类型 {other}（仅支持 p2wpkh / p2pkh）"
                ))
            }
        };

        // 签名：输入是**已经是摘要**的 32 字节，不要再哈希一次。
        let message = Message::from_digest(sighash);
        let sig = secp.sign_ecdsa(&message, &secret);

        // 自检：签完立刻用同一把公钥验一遍。
        //
        // 这不是冗余——它把「密钥与签名器不匹配」「内存被踩坏」这类
        // 极低概率但后果致命的问题，变成一次当场报错，
        // 而不是等到广播被拒时才发现。
        secp.verify_ecdsa(&message, &sig, &SecpPublicKey::from_secret_key(&secp, &secret))
            .map_err(|e| anyhow::anyhow!("第 {index} 个输入的签名自检失败: {e}"))?;

        signatures.push(sig.serialize_compact());
    }

    // `signature`（单数）保留第一个，让「单签名链」的调用方无需按链分支；
    // BTC 的完整结果请看 `signatures`。
    let first = *signatures.first().unwrap_or(&[0u8; COMPACT_SIGNATURE_LEN]);

    Ok(SignedResult {
        signature: format!("0x{}", hex::encode(first)),
        signatures: signatures
            .iter()
            .map(|s| format!("0x{}", hex::encode(s)))
            .collect(),
        signed_tx: None,
        encoding: "hex".to_string(),
        note: Some(
            "BTC 只返回逐输入的 64 字节紧凑签名（r||s）；\
             最终交易由 SDK 用 submit_context + signatures 组装并广播"
                .to_string(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::store::Scheme;

    // ——— 外部真值：allchain SDK 的 `chain/btc` 实际产出的上下文 ———
    //
    // 产生方式：在 SDK 的 `chain/btc/src/tx.rs` 测试里用 `two_input_fixture()`
    // （两输入 + 收款 + 找零，走真实的 `select_coins` 与 `build_unsigned_transaction`）
    // 造出 `SubmitContext`，再调用 SDK 自己的 `sighashes()` 打印摘要，原样抄在这里。
    //
    // 为什么用它而不是自己造：这是**另一个 crate 的真实输出**，
    // 两侧任何一处对 sighash 的理解发生漂移（脚本类型分派、金额的单位、
    // SIGHASH 标志、缓存用法），这条测试都会红。
    // 自己造向量则会被「两边用同一个错误理解」掩盖。
    //
    // 该上下文对应的私钥来自 SDK 测试用的 WIF
    // `L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy`，
    // 由 Python 独立解码 Base58Check 得到下面这 32 字节
    // （并已验证它派生的压缩公钥与上下文里的 `public_key` 逐字节一致）。

    /// 上下文里的签名公钥对应的私钥（裸 32 字节十六进制）。
    const FIXTURE_PRIVKEY: &str =
        "8c112cf628362ecf4d482f68af2dbb50c8a2cb90d226215de925417aa9336a48";

    /// SDK `build_transfer` 下发的 `extra.submit_context`（原样）。
    const FIXTURE_CONTEXT: &str = r#"{
      "network": "mainnet",
      "version": 2,
      "locktime": 0,
      "public_key": "029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59f",
      "inputs": [
        {
          "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
          "vout": 0,
          "sequence": 4294967293,
          "value": 100000,
          "script_pubkey": "001447862fe165e6121af80d5dde1ecb478ed170565b",
          "script_type": "p2wpkh"
        },
        {
          "txid": "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
          "vout": 1,
          "sequence": 4294967293,
          "value": 60000,
          "script_pubkey": "001447862fe165e6121af80d5dde1ecb478ed170565b",
          "script_type": "p2wpkh"
        }
      ],
      "outputs": [
        { "value": 120000, "script_pubkey": "001447862fe165e6121af80d5dde1ecb478ed170565b" },
        { "value": 38955,  "script_pubkey": "001447862fe165e6121af80d5dde1ecb478ed170565b" }
      ],
      "unsigned_tx_hex": "02000000023ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a0000000000fdffffff982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e0100000000fdffffff02c0d401000000000016001447862fe165e6121af80d5dde1ecb478ed170565b2b9800000000000016001447862fe165e6121af80d5dde1ecb478ed170565b00000000"
    }"#;

    /// SDK 用同一个 `sighashes()` 算出的逐输入摘要。
    const FIXTURE_SIGHASHES: [&str; 2] = [
        "b17d171956505e2a424922a4dcc35823cea4c49d8cbf8c3b63aa56203e72b4ab",
        "a8376c9c5f8b35b254a75cb42f925037b156b8b5c01f54a9f812fcc3bbaa8970",
    ];

    /// 由上下文里的 `unsigned_tx_hex` 解出的字节。
    fn fixture_txdata_bytes() -> Vec<u8> {
        let ctx: SubmitContext = serde_json::from_str(FIXTURE_CONTEXT).unwrap();
        hex::decode(&ctx.unsigned_tx_hex).unwrap()
    }

    /// `sign_btc` 的入参形态：**hex 字符串**，不是字节。
    ///
    /// 与生产路径一致——HTTP 传进来的就是 `txdatahex` 字符串，
    /// 测试若直接喂字节就绕过了「hex 解码」这一层，那层出错时测试不会红。
    fn fixture_txdata() -> String {
        hex::encode(fixture_txdata_bytes())
    }

    /// 夹具交易**真实**的输入数（来自 `txdata`，不来自 context）。
    ///
    /// 用于断言「多出来的 context 条目不会凭空多产出签名」——
    /// 若直接写死 2，夹具改了输入数这条测试会静默失效。
    fn fixture_input_count() -> usize {
        let tx: Transaction = encode::deserialize(&fixture_txdata_bytes()).unwrap();
        tx.input.len()
    }

    fn fixture_context() -> Value {
        serde_json::from_str(FIXTURE_CONTEXT).unwrap()
    }

    fn fixture_key() -> StoredKey {
        let seed: [u8; 32] = hex::decode(FIXTURE_PRIVKEY).unwrap().try_into().unwrap();
        StoredKey { scheme: Scheme::Secp256k1, seed }
    }

    /// **对拍**：本 crate 重算出的 sighash 必须与 SDK 的逐字节相同。
    ///
    /// 这是 sign 与 SDK 之间唯一的跨 crate 契约落点。
    /// 它不能直接调用 `sign_btc` 读到 sighash（sighash 不出现在结果里），
    /// 所以用一个中间的「只算哈希」测试函数来钉：签名本身由下一条测试覆盖。
    ///
    /// **局限（变异测试实测出来的）**：本测试在测试代码里**重算**了一遍哈希，
    /// 而不是读 `sign_btc` 的产物。所以把 `sign_btc` 的脚本类型分派改坏
    /// （例如让 p2wpkh 走传统算法），本测试**仍然是绿的**——它钉住的是
    /// 「SDK 与本 crate 的算法一致」，不是「`sign_btc` 走对了分支」。
    /// 后者由 `signatures_verify_against_the_context_public_key` 与
    /// `a_p2wpkh_input_is_not_signed_with_the_legacy_algorithm` 兜住。
    #[test]
    fn recomputed_sighashes_match_the_sdk_output() {
        let tx: Transaction = encode::deserialize(&fixture_txdata_bytes()).unwrap();
        let ctx: SubmitContext = serde_json::from_str(FIXTURE_CONTEXT).unwrap();
        let mut cache = SighashCache::new(&tx);

        for (index, expected) in FIXTURE_SIGHASHES.iter().enumerate() {
            let meta = &ctx.inputs[index];
            // 只走 p2wpkh 分支：夹具里两个输入都是 p2wpkh，
            // 与 SDK 的 `sighashes` 走同一条路径。
            assert_eq!(meta.script_type, "p2wpkh");
            let script = ScriptBuf::from(hex::decode(&meta.script_pubkey).unwrap());
            let got = cache
                .p2wpkh_signature_hash(
                    index,
                    &script,
                    Amount::from_sat(meta.value),
                    EcdsaSighashType::All,
                )
                .unwrap()
                .to_byte_array();
            assert_eq!(
                hex::encode(got),
                *expected,
                "第 {index} 个输入的 sighash 与 SDK 不一致"
            );
        }
    }

    /// 端到端：签出的每个签名都必须能被**上下文里的公钥**验过。
    ///
    /// 这一条比上一条更强——它证明的不只是「哈希算对了」，
    /// 而是「用对的那把钥匙、对的那笔交易、对的那组摘要签出了有效签名」。
    #[test]
    fn signatures_verify_against_the_context_public_key() {
        let result = sign_btc(&fixture_txdata(), &fixture_context(), &fixture_key())
            .expect("夹具应能正常签名");

        assert_eq!(result.signatures.len(), FIXTURE_SIGHASHES.len());
        assert!(result.signed_tx.is_none(), "BTC 不组装交易");

        let ctx: SubmitContext = serde_json::from_str(FIXTURE_CONTEXT).unwrap();
        let secp = Secp256k1::new();
        let public_key = SecpPublicKey::from_slice(&hex::decode(&ctx.public_key).unwrap()).unwrap();

        for (index, sig_hex) in result.signatures.iter().enumerate() {
            let raw = hex::decode(strip_0x(sig_hex)).unwrap();
            assert_eq!(
                raw.len(),
                COMPACT_SIGNATURE_LEN,
                "第 {index} 个签名应为 64 字节紧凑格式"
            );
            let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&raw)
                .expect("64 字节应能解析成紧凑签名");
            let message = Message::from_digest(
                hex::decode(FIXTURE_SIGHASHES[index]).unwrap().try_into().unwrap(),
            );
            assert!(
                secp.verify_ecdsa(&message, &sig, &public_key).is_ok(),
                "第 {index} 个签名没能用上下文公钥验过"
            );
        }
    }

    /// **反证**：p2wpkh 输入**不许**用传统算法签。
    ///
    /// 上一条只证明了「算法一致」，这条才证明「分派正确」：
    /// 传统算法与 BIP143 在本夹具上必须算出**不同**的摘要（第一组断言，
    /// 否则本测试就是空的），且 `sign_btc` 产出的签名必须**验不过**
    /// 传统摘要（第二组断言，否则说明走错了分支）。
    ///
    /// 这条之所以重要：写错算法不会报任何错，只会产出「格式完全合法、
    /// 但节点永远拒绝」的签名——是本模块最贵的一种缺陷。
    #[test]
    fn a_p2wpkh_input_is_not_signed_with_the_legacy_algorithm() {
        let tx: Transaction = encode::deserialize(&fixture_txdata_bytes()).unwrap();
        let ctx: SubmitContext = serde_json::from_str(FIXTURE_CONTEXT).unwrap();
        let result = sign_btc(&fixture_txdata(), &fixture_context(), &fixture_key())
            .expect("夹具应能正常签名");

        let secp = Secp256k1::new();
        let public_key = SecpPublicKey::from_slice(&hex::decode(&ctx.public_key).unwrap()).unwrap();
        // 注意这里**没有** `mut`：传统 `legacy_signature_hash` 取 `&self`，
        // 而 BIP143 的 `p2wpkh_signature_hash` 取 `&mut self`（它要写缓存）。
        // 差别在于传统算法无需缓存「全部输出的哈希」这一中间结果。
        let cache = SighashCache::new(&tx);

        for (index, sig_hex) in result.signatures.iter().enumerate() {
            let meta = &ctx.inputs[index];
            assert_eq!(meta.script_type, "p2wpkh", "夹具应全为 p2wpkh 输入");
            let script = ScriptBuf::from(hex::decode(&meta.script_pubkey).unwrap());

            // 传统算法（不含金额）算出的摘要。
            let legacy = cache
                .legacy_signature_hash(index, &script, EcdsaSighashType::All.to_u32())
                .unwrap()
                .to_byte_array();

            // 第一组：两条算法必须真的不同，否则下面那条断言恒真。
            assert_ne!(
                hex::encode(legacy),
                FIXTURE_SIGHASHES[index],
                "第 {index} 个输入上传统算法与 BIP143 算出了同一个摘要，本测试失去意义"
            );

            // 第二组：真实签名必须验不过传统摘要。
            let message = Message::from_digest(legacy);
            let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(
                &hex::decode(strip_0x(sig_hex)).unwrap(),
            )
            .unwrap();
            assert!(
                secp.verify_ecdsa(&message, &sig, &public_key).is_err(),
                "第 {index} 个签名竟然用传统摘要验过了：说明 p2wpkh 走错了算法分支"
            );
        }
    }

    /// **反证一**：换了另一笔交易的 `txdatahex`（上下文不变）必须被拒绝。
    ///
    /// 没有这条，第二道校验可能根本没生效——而「签名落在另一笔交易上」
    /// 正是本模块最想防的事故。
    #[test]
    fn a_mismatched_txdatahex_is_rejected() {
        // 改一个输出金额，得到一笔结构合法但不同的交易。
        let mut tx: Transaction = encode::deserialize(&fixture_txdata_bytes()).unwrap();
        tx.output[0].value = bitcoin::Amount::from_sat(1);
        // 入参是 hex 字符串，所以篡改后也要重新编成 hex 再传进去。
        let tampered = encode::serialize_hex(&tx);

        let err = sign_btc(&tampered, &fixture_context(), &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("不是同一笔交易"),
            "应报「不是同一笔交易」，实际: {err}"
        );
    }

    /// **反证二**：用另一把钥匙的私钥去签这个上下文必须被拒绝（第四道校验）。
    #[test]
    fn signing_with_a_different_key_is_rejected() {
        let other = StoredKey { scheme: Scheme::Secp256k1, seed: [7u8; 32] };
        let err = sign_btc(&fixture_txdata(), &fixture_context(), &other).unwrap_err();
        assert!(
            err.to_string().contains("公钥不一致"),
            "应报「公钥不一致」，实际: {err}"
        );
    }

    /// **反证三**：context 缺字段（比如少 `value`）必须报错，不能按默认值继续。
    ///
    /// 少了 `value` 若被当成 0，sighash 会算出一个**看着正常**的值，
    /// 签名也验得过自己，只有节点会拒——这是最坏的一类失败。
    #[test]
    fn a_context_missing_input_value_is_rejected() {
        let mut ctx: Value = fixture_context();
        ctx["inputs"][0].as_object_mut().unwrap().remove("value");

        let err = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("context 解析失败"),
            "缺字段应报解析失败，实际: {err}"
        );
    }

    /// 未知脚本类型必须拒绝，而不是按 p2wpkh 兜底。
    #[test]
    fn an_unknown_script_type_is_rejected() {
        let mut ctx: Value = fixture_context();
        ctx["inputs"][1]["script_type"] = Value::String("p2tr".to_string());

        let err = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("不支持的脚本类型"),
            "应报脚本类型不支持，实际: {err}"
        );
    }

    /// 非主网上下文必须拒绝（否则跨网签出的签名会被 SDK 的跨网护栏拦下，绕远路）。
    #[test]
    fn a_testnet_context_is_rejected() {
        let mut ctx: Value = fixture_context();
        ctx["network"] = Value::String("testnet".to_string());

        let err = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).unwrap_err();
        assert!(err.to_string().contains("只支持 mainnet"), "实际: {err}");
    }

    /// 输入数量比交易**少**一条时必须拒绝。
    ///
    /// 为什么这条要单独存在：循环以 `tx.input` 为准、按 `index` 取 `ctx.inputs`，
    /// 少一条时 `ctx.inputs.get(index)` 取不到，当场报「缺第 N 个输入的元数据」，
    /// 而不是让 `for` 提前结束、**静默少签**（返回 ok 却只带 N-1 个签名——实测确认）。
    /// 没有这条兜底，这类「不报错、只给错答案」的缺陷在本地是全绿的。
    #[test]
    fn a_context_with_the_wrong_input_count_is_rejected() {
        let mut ctx: Value = fixture_context();
        let inputs = ctx["inputs"].as_array_mut().unwrap();
        inputs.pop();

        let err = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("一一对应"),
            "应报输入数量不一致，实际: {err}"
        );
    }

    /// **另一个方向**：`inputs` **多**一条时不再报错，而是良性忽略。
    ///
    /// 与上面「少一条必须拒绝」的分工：以 `tx.input` 为权威集合后，
    /// 多出来的 `ctx.inputs` 条目根本不会被循环取到，所以无害——
    /// `sign_btc` 直接签出交易真实拥有的 N 个签名。这条把「多一条被误拒」
    /// 钉死，免得有人又把独立 count 检查加回来、把良性情况当错误处理。
    #[test]
    fn an_extra_context_input_is_ignored_as_benign() {
        let mut ctx: Value = fixture_context();
        let inputs = ctx["inputs"].as_array_mut().unwrap();
        // 复制第一条凑数：多出来的这条不再触发任何校验，应当被直接忽略。
        let extra = inputs[0].clone();
        inputs.push(extra);

        let sigs = sign_btc(&fixture_txdata(), &ctx, &fixture_key())
            .unwrap_or_else(|e| panic!("多一条 input 应被忽略而非报错，实际: {e}"));
        // 签名数量必须等于交易的真实输入数，多出来的 context 条目不会凭空多产出签名。
        assert_eq!(
            sigs.signatures.len(),
            fixture_input_count(),
            "签名数应等于交易输入数，实际: {}",
            sigs.signatures.len()
        );
    }

    /// 喂一段不是交易的字节必须报错，不能静默产出废签名。
    ///
    /// 这条顺带钉住「hex 解码层」：入参是**合法 hex 但解不出交易**，
    /// 所以报错必须来自**交易解码**（不是 hex 解码）——错误信息里会有「交易解码失败」。
    #[test]
    fn garbage_txdata_is_rejected() {
        let err = sign_btc(&"ab".repeat(32), &fixture_context(), &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("解码失败"),
            "应报解码失败，实际: {err}"
        );
    }

    /// **hex 解码本身**失败时也必须报错，且错误信息要带上「这段字节本该是什么」。
    ///
    /// 与上一条分工：上一条是「hex 对但内容不是交易」，这条是「连 hex 都不对」。
    /// 两条都要有——只留前者时，把 `decode_txdata` 删掉（改回收字节）也不会红。
    #[test]
    fn a_non_hex_txdata_is_rejected() {
        let err = sign_btc("0xZZZZ_not_hex", &fixture_context(), &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("hex 解码失败"),
            "应报 hex 解码失败，实际: {err}"
        );
        // 错误信息里必须点明这是 BTC 的未签名交易，而不是一句放之四海皆准的「需 hex」。
        assert!(
            err.to_string().contains("BTC"),
            "错误信息应带链名以便定位，实际: {err}"
        );
    }

    /// `0x` 前缀与首尾空白都必须被容忍（调用方常把 hex 嵌在多行 JSON 里）。
    ///
    /// 这是**反证的另一半**：上两条证明「坏输入会被拒」，这条证明
    /// 「好输入不会因为格式细节被误拒」——只加拒绝测试而不加这条，
    /// 有人把 `strip_0x` 或 `trim` 删掉时测试照样全绿。
    #[test]
    fn a_prefixed_and_padded_txdatahex_is_accepted() {
        let plain = fixture_txdata();
        for variant in [
            plain.clone(),
            format!("0x{plain}"),
            format!("0X{plain}"),
            format!("  {plain}\n"),
            format!("0x{plain}  "),
        ] {
            sign_btc(&variant, &fixture_context(), &fixture_key())
                .unwrap_or_else(|e| panic!("形态 {variant:?} 应被接受，实际报错: {e}"));
        }
    }

    /// ed25519 的密钥不能拿去签 BTC。
    #[test]
    fn an_ed25519_key_is_rejected() {
        let wrong = StoredKey { scheme: Scheme::Ed25519, seed: [9u8; 32] };
        let err = sign_btc(&fixture_txdata(), &fixture_context(), &wrong).unwrap_err();
        assert!(
            err.to_string().contains("需要 secp256k1"),
            "实际: {err}"
        );
    }
}
