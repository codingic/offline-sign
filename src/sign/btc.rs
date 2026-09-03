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

#[cfg(test)] mod tests;
