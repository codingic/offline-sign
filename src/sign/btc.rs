//! BTC：逐输入重算 **P2WPKH（BIP143）** sighash 并签名，**只出签名，不组装交易**。
//!
//! # 为什么每条链单独一个文件
//!
//! 见 [`crate::sign`] 模块文档：每条链只认自己的序列化格式，分文件后
//! 改一条链不会误伤另一条链的 `use` 与编码约定。
//!
//! # BTC 与其余七条链的根本差异：待签对象有 N 个
//!
//! 其余链都是账户模型，一笔交易只有一个待签哈希。BTC 是 **UTXO 模型**，
//! 签名粒度是「每个输入一个」：N 个输入 → N 个 sighash → N 个签名。
//! 且每个 sighash 覆盖「全部输入 + 全部输出」的组合摘要，
//! **改动任何一个输入都会让其它所有输入的签名失效**。
//!
//! # 只支持 P2WPKH：为什么，以及代价
//!
//! 同一个公钥在 BTC 上能派生两类地址，对应两套**互不相通**的签名规则：
//!
//! | 类型 | 地址 | 锁定脚本 | 签名落在 | sighash 算法 | 需要输入金额 |
//! |---|---|---|---|---|---|
//! | **P2WPKH** | `bc1q…` | `OP_0 <h160>` | `witness` | **BIP143** | **需要** |
//! | P2PKH | `1…` | `OP_DUP OP_HASH160 <h160> … OP_CHECKSIG` | `scriptSig` | 传统算法 | 不需要 |
//!
//! P2WPKH（2017 年 SegWit）是当前主流：见证数据享 75% 权重折扣，手续费比 P2PKH
//! 低三到四成；签名挪出 txid 的计算范围，顺带修掉了交易延展性。
//! 主流钱包的默认接收地址都是 `bc1q…`，2017 年前的 P2PKH 已是遗留类型。
//!
//! 代价是 BIP143 的定义要求把**本输入的金额**混进摘要——这正是它比传统算法
//! 更安全的地方（堵住「硬件钱包被隐瞒真实输入金额 → 少找零」的攻击）。
//! 但金额**不在交易字节里**（`TxIn` 只有 `txid ‖ vout ‖ sequence`），
//! 所以必须由 `context` 提供。这就是 BTC 成为唯一需要额外入参那条链的原因。
//!
//! **P2PKH 输入会被明确拒绝**：`context` 里的 `script_type` 字段给出了明确信号，
//! 不需要靠猜。传统算法虽然不要金额、只凭 `unsignedtxdatahex` 就能签，但同时支持两套
//! 会把「地址类型必须与签名算法配套」这条约束变成调用方的心智负担——
//! 宁可只支持一种、并把另一种拒绝得清清楚楚。
//!
//! # 为什么必须额外收一个 `context`
//!
//! `context` 就是 SDK `build_transfer` 下发的 `extra.submit_context`，
//! 里面带齐了每个输入的 `value` 与 `script_pubkey`。
//!
//! 拿到金额后**不是直接拿来用**，而是从 `unsignedtxdatahex` + `context` **重算**每个
//! sighash，并在签之前用 `context.unsigned_tx_hex` 校验两者描述的是同一笔交易。
//! 直接签 SDK 下发的 `signing_payloads[].sighash` 最省事，但那是**盲信**对侧：
//! 一旦上下文在往返途中被改过（或调用方传错了笔交易），签出来的签名照样
//! 是「有效签名」，只是签在另一笔交易上——而这类错误在广播前不会有任何提示。
//! 重算就把「盲信」变成了「验证后使用」。
//!
//! # 分工：sign 签名、且组装完整可广播交易
//!
//! 本函数把紧凑签名转成**比特币网络要求的形态**后，直接填进每个输入的 witness，
//! 返回一笔可直接广播的交易（`signedtxdatahex`）。这样做的好处是调用方（SDK/前端）
//! 拿到 `signedtxdatahex` 即可广播，不必再自己拼 witness——离线签名器的典型用法正是
//! 「传未签名交易、拿回能广播的交易」。
//!
//! 依旧**不**改 nonce/金额/输出：交易结构全由 SDK 的 `build_transfer` 定好，
//! sign 只负责「按 BIP143 算 sighash → 签名 → 装 witness」。装完立即用同一把公钥
//! 重验 witness 里的 DER 签名（见函数末尾的自检），把「witness 填错形态/顺序」这类
//! 「本地签名成功、广播才拒」的隐患前移成当场报错。
//!
//! # 输入 / 输出契约
//!
//! - **输入 `unsignedtxdatahex`**：序列化后的**未签名交易**（witness 为空），与其余各链口径一致。
//! - **输入 `context`**：SDK 下发的 `submit_context`；必须与 `unsignedtxdatahex` 描述同一笔交易。
//! - **输出**：`signatures` = 与输入一一对应的 **64 字节紧凑签名**（`r || s`）十六进制数组；
//!   `signedtxdatahex` = 已填好 witness 的**完整可广播 segwit 交易**（`0x` + hex）。

use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{ecdsa::Signature as SecpSignature, All, Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, ScriptBuf, Transaction, Witness};
use serde::Deserialize;
use serde_json::Value;

use crate::sign::{SignedResult, decode_txdata, strip_0x};
use crate::store::{Scheme, StoredKey};

/// 紧凑签名的长度：`r(32) || s(32)`。
const COMPACT_SIGNATURE_LEN: usize = 64;

/// `SIGHASH_ALL` 在 witness 签名尾追加的字节（BIP143 规定 All = 1）。
///
/// 比特币网络要求 witness 里的签名是 `DER 编码 || <sighash 字节>` 的形态，
/// 光有签名本体还不够——节点会按这个尾巴判断签名覆盖哪些输入/输出。
const SIGHASH_ALL_BYTE: u8 = 0x01;

/// 本服务只认主网（理由见 `keys::btc_info`：地址编码含网络前缀，换网络就是另一套地址）。
const EXPECTED_NETWORK: &str = "mainnet";

/// 唯一支持的脚本类型标签。
///
/// 为什么抽成常量而不是内联在校验里：这个字符串同时出现在**校验**、
/// **错误信息**与**测试**三处，散落时改名极易漏掉一处，而漏掉的那处会静默
/// 变成「永远拒绝」或「永远放行」——两种都不报错，只是行为悄悄反了。
const SCRIPT_TYPE: &str = "p2wpkh";

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
    /// 构造阶段的未签名交易字节，用于校验「上下文与 unsignedtxdatahex 是同一笔交易」。
    unsigned_tx_hex: String,
}

/// 上下文里的单个输入：只挑 sighash 计算真正需要的三项。
#[derive(Debug, Deserialize)]
struct ContextInput {
    /// 该输入值多少 satoshi——**BIP143 sighash 需要它**，而它不在交易字节里。
    value: u64,
    /// 锁定脚本 `scriptPubKey` 的十六进制。
    script_pubkey: String,
    /// 脚本类型；只接受 `p2wpkh`，其余一律拒绝。
    script_type: String,
}

/// BTC 签名：从 `unsignedtxdatahex` + `context` 重算逐输入 BIP143 sighash，逐个签出 64 字节紧凑签名。
///
/// # 输入 / 输出都是 hex 字符串
///
/// - **入参 `unsignedtxdatahex: &str`**：序列化后的**未签名交易**的 hex（可带 `0x`、可有首尾空白）。
/// - **出参**：每个输入一个 `"0x" + 128 位 hex`，即 64 字节紧凑签名 `r(32) ‖ s(32)`。
///
/// 两端都用 hex 字符串，是为了与 HTTP 请求体里的 `unsignedtxdatahex` 字段、以及 SDK
/// 期望的签名数组形态**直接对齐**，中间不再有一次「谁负责编解码」的猜测。
///
/// # 语法要点
///
/// `context: &Value` 而非 `&SubmitContext`：调用方拿到的是 HTTP 请求体里的裸 JSON，
/// 这里才做「结构化」。把反序列化留在本函数内部，错误处理就能带上
/// 「你传的应该是什么」这句人话，而不是一句类型不匹配。
pub fn sign_btc(
    unsignedtxdatahex: &str,
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

    // —— 第二道：`unsignedtxdatahex` 与 context 必须描述同一笔交易 ——
    //
    // 这是整条链路上最重要的一次校验：金额与脚本来自 context、交易结构来自 unsignedtxdatahex，
    // 两者若不是同一次 `build_transfer` 的产物，下面每一步都会「正常执行」，
    // 只是签在了另一笔交易上。
    // `decode_txdata` 只负责「hex 字符串 -> 字节」，错误信息里的
    // 「序列化的未签名交易」是本链补的那句话。
    let txdata = decode_txdata(unsignedtxdatahex, "BTC 未签名交易（序列化的未签名交易）")?;
    let mut tx: Transaction = encode::deserialize(&txdata)
        .map_err(|e| anyhow::anyhow!("BTC 交易解码失败（需序列化的未签名交易）: {e}"))?;
    let tx_hex = encode::serialize_hex(&tx);
    if tx_hex != strip_0x(ctx.unsigned_tx_hex.trim()) {
        return Err(anyhow::anyhow!(
            "unsignedtxdatahex 与 context.unsigned_tx_hex 不是同一笔交易：\
             两者必须来自同一次 build_transfer，否则签名会落在另一笔交易上"
        ));
    }
    // 循环以 `tx.input` 为准，若它为空则循环一次都不跑、直接返回空签名数组——
    // 那是个「假成功」：调用方拿到 0 个签名去组装，报错会出现在完全无关的环节。
    if tx.input.is_empty() {
        return Err(anyhow::anyhow!(
            "BTC 交易没有输入：unsignedtxdatahex 不是一笔可签名的交易"
        ));
    }

    // —— 第三道：context 里的公钥必须就是本密钥的公钥 ——
    //
    // 若不是同一把钥匙，签出的签名在 SDK 验签时必然失败；
    // 在这里拦，能直接说清「钥匙和交易不是一套」，而不是留给对侧一句「验签失败」。
    let secret = SecretKey::from_slice(&key.seed)
        .map_err(|e| anyhow::anyhow!("BTC 种子不是合法 secp256k1 私钥: {e}"))?;
    let secp = Secp256k1::new();
    // `from_secret_key` 返回的 `PublicKey` 用 `serialize()` 输出时就是**压缩**格式（33 字节），
    // 与 context 里存的格式一致。留着 `public_key` 本身，下面签名自检还要用。
    let public_key = SecpPublicKey::from_secret_key(&secp, &secret);
    let ours = public_key.serialize();
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
    // BIP143 的 `p2wpkh_signature_hash` 取 `&mut self`——它要往缓存里写
    // 「全部输出的哈希」这类中间结果，逐输入签名时能避免重复计算。
    let mut cache = SighashCache::new(&tx);
    // 收集原始 `Signature`：`serialize_compact()` 给调用方对账用的紧凑数组，
    // `serialize_der()` 给下面填 witness 用的 DER 形态——两者同出一签。
    let mut ecdsa_sigs: Vec<SecpSignature> = Vec::with_capacity(tx.input.len());
    // 每个输入的 scriptCode + 金额，组装后自检 witness 时还要用。
    let mut witness_metas: Vec<(ScriptBuf, Amount)> = Vec::with_capacity(tx.input.len());

    // 循环**以 `tx.input` 为准**：交易的真实输入就是必须签的全部，
    // 每个 `index` 去 `ctx.inputs` 取签名元数据。取不到说明 context 的 inputs
    // 比交易少——这正是「静默少签」的唯一切口，必须当场报错，
    // 不能让 `for` 提前结束、悄悄少签。
    for (index, input) in tx.input.iter().enumerate() {
        let meta = match ctx.inputs.get(index) {
            Some(m) => m,
            None => return Err(anyhow::anyhow!(
                "context 缺少第 {index} 个输入的签名元数据：inputs 必须与交易的输入一一对应"
            )),
        };
        // 必须是**未签名**模板：见证里已经有东西，说明这笔交易签过了。
        // 放行也能算出正确的哈希（BIP143 不看本输入的 witness），
        // 但重签一遍毫无意义，还可能覆盖已有签名。
        if !input.witness.is_empty() {
            return Err(anyhow::anyhow!(
                "第 {index} 个输入的见证非空：unsignedtxdatahex 必须是未签名交易模板（witness 为空）"
            ));
        }
        // 第四道：只支持 P2WPKH。
        //
        // context 的 `script_type` 给出了**明确信号**，不需要靠猜。
        // 为什么连 P2PKH 也一并拒绝而不是顺手支持：它走的是另一套算法
        // （传统 sighash，不含金额），支持它就意味着调用方必须时刻记住
        // 「地址类型与签名算法要配套」。只留一种，配错的代价从
        // 「广播失败」前移成「签名时立刻报错」。
        if meta.script_type != SCRIPT_TYPE {
            return Err(anyhow::anyhow!(
                "第 {index} 个输入的脚本类型是 {}，本函数只支持 {SCRIPT_TYPE}：\
                 P2PKH 等遗留类型请先把币转到 bc1q… 地址",
                meta.script_type
            ));
        }

        // `ScriptBuf::from(Vec<u8>)` 直接吃解码后的字节；
        // 没有校验脚本是否合法——sighash 计算只把它当字节串用，
        // 而上下文是 SDK 产出的，脚本合法性由 SDK 侧保证。
        let script = ScriptBuf::from(
            hex::decode(strip_0x(meta.script_pubkey.trim())).map_err(|e| {
                anyhow::anyhow!("第 {index} 个输入的 script_pubkey 不是合法十六进制: {e}")
            })?,
        );

        // BIP143：把**本输入的金额**混进摘要，这是它与传统算法的根本差别，
        // 也是「必须要有 context」的唯一原因。
        let sighash = cache
            .p2wpkh_signature_hash(
                index,
                &script,
                Amount::from_sat(meta.value),
                EcdsaSighashType::All,
            )
            .map_err(|e| anyhow::anyhow!("第 {index} 个输入的 BIP143 sighash 计算失败: {e}"))?
            .to_byte_array();

        // 签名：输入是**已经是摘要**的 32 字节，不要再哈希一次。
        let message = Message::from_digest(sighash);
        let mut raw = secp.sign_ecdsa(&message, &secret);
        // 比特币主网要求低 S 规范的 DER 签名（BIP62/146）。`sign_ecdsa` 已默认低 S，
        // 这里再显式归一化一次（幂等、零成本），兜底任何 secp256k1 版本差异。
        raw.normalize_s();
        let sig = raw;

        // 自检：签完立刻用同一把公钥验一遍（防密钥/签名器不匹配、内存被踩）。
        secp.verify_ecdsa(&message, &sig, &public_key)
            .map_err(|e| anyhow::anyhow!("第 {index} 个输入的签名自检失败: {e}"))?;

        ecdsa_sigs.push(sig);
        witness_metas.push((script, Amount::from_sat(meta.value)));
    }

    // 紧凑签名数组（r||s）：仍返回，供调用方对账/调试，与 `signature` 字段一致。
    let signatures: Vec<[u8; COMPACT_SIGNATURE_LEN]> =
        ecdsa_sigs.iter().map(|s| s.serialize_compact()).collect();

    // —— 组装完整可广播交易：把每个输入的签名填进 witness ——
    //
    // 比特币网络要求 witness 里的签名是 **DER 编码 + SIGHASH 字节**（本服务内部为了计算
    // BIP143 sighash 一直用紧凑签名 `r||s`，那是验签/存储友好的形态，但**不能直接进
    // witness**——节点会以 `non-mandatory-script-verify-flag` 拒绝）。这里转成
    // `DER || SIGHASH_ALL`，连同本密钥的压缩公钥，按 P2WPKH 的标准顺序
    // `[签名, 公钥]` 填进对应输入的 witness；重新序列化（自动带上 witness、变成
    // segwit 形态）即得一笔可直接广播的交易，无需 SDK 再拼。
    // `cache` 对 `tx` 的不可变借用止于循环末尾（NLL），下面直接改 `tx.input[..].witness`。
    for (index, sig) in ecdsa_sigs.iter().enumerate() {
        let mut der = sig.serialize_der().to_vec();
        der.push(SIGHASH_ALL_BYTE);
        tx.input[index].witness = Witness::from_slice(&[der.as_slice(), ours.as_slice()]);
    }

    // 组装后自检：装配进 witness 后，重算 BIP143 sighash 验证 DER 签名能验过——
    // 把「witness 填错形态/顺序」这类「本地签名成功、广播才拒」的隐患前移成当场报错。
    verify_btc_witness(&tx, &public_key, &secp, &witness_metas)?;

    // `signature`（单数）保留第一个，让「单签名链」的调用方无需按链分支；
    // BTC 的完整结果请看 `signatures` 与 `signedtxdatahex`。
    let first = *signatures.first().unwrap_or(&[0u8; COMPACT_SIGNATURE_LEN]);
    // 完整可广播交易：witness 已填好的 segwit 交易，带 `0x` 前缀（与 ETH 的 `signedtxdatahex` 同约定）。
    let signedtxdatahex = Some(format!("0x{}", encode::serialize_hex(&tx)));
    // 链上 txid：double-SHA256 反序。`compute_txid()` 已按比特币白皮书的反序规则给出
    // 标准显示序（即区块浏览器里看到的 txid），`Display` 输出小写 hex，再补 `0x` 前缀与全局约定对齐。
    let txhash = Some(format!("0x{}", tx.compute_txid()));

    Ok(SignedResult {
        signature: format!("0x{}", hex::encode(first)),
        signatures: signatures
            .iter()
            .map(|s| format!("0x{}", hex::encode(s)))
            .collect(),
        signedtxdatahex,
        txhash,
        encoding: "hex".to_string(),
        note: Some(
            "BTC 返回逐输入的 64 字节紧凑签名（r||s，按 P2WPKH 的 BIP143 sighash 签出），\
             同时 `signedtxdatahex` 是已填好 witness 的完整可广播交易（紧凑签名转 DER+SIGHASH_ALL 装配）。\
             调用方可直接广播 `signedtxdatahex`，无需自己拼 witness。本路径不支持 P2PKH 等遗留地址类型。\
             `txhash` 为本交易的链上 txid（double-SHA256 反序），可直接用于区块浏览器查询"
                .to_string(),
        ),
    })
}

/// 组装后自检：用同一笔已填好 witness 的交易重算 BIP143 sighash，验证每个输入 witness 里
/// 的 DER 签名都能用本密钥公钥验过——直接锁死「witness 填对了（顺序、DER 形态、SIGHASH 字节）」。
///
/// # 为什么单独成函数
///
/// 这块逻辑原本内联在 `sign_btc` 末尾，但它与「签名循环」职责不同：
/// 签名循环关心「算出 sighash、签出紧凑签名」，本函数关心「装配进 witness 后，
/// DER 形态 + 顺序 + SIGHASH 字节都正确」。拆出来后，`sign_btc` 主流程只剩
/// 「签名 → 装配」一条主线，自检验证作为独立、可单测的纯函数存在，
/// 将来即便要换装配策略也能单独对拍，不必带着整个签名上下文一起改。
///
/// # 入参
///
/// - `tx`：已填好 witness 的**完整 segwit 交易**（不是未签名模板）；
/// - `public_key`：本密钥的**压缩**公钥（33 字节），与签名时同一把；
/// - `secp`：复用的 secp256k1 上下文（`sign_btc` 里 `Secp256k1::new()` 建好的，
///   避免本函数再 `new` 一次；`All` 同时具备签名与验签能力，这里只用验签）；
/// - `witness_metas`：每个输入的 `(scriptCode, 金额)`，来自 `sign_btc` 的签名循环，
///   与 `tx.input` 一一对应——BIP143 sighash 必须用它重算摘要。
///
/// # 失败语义
///
/// 任一输入出现「witness 为空 / DER 尾字节非 SIGHASH_ALL / DER 解码失败 / 验签失败」
/// 任一情况都立即返回 `Err`；调用方据此把「本地签名成功、广播才拒」的隐患前移成当场报错。
fn verify_btc_witness(
    tx: &Transaction,
    public_key: &SecpPublicKey,
    secp: &Secp256k1<All>,
    witness_metas: &[(ScriptBuf, Amount)],
) -> anyhow::Result<()> {
    // `SighashCache::new(&tx)` 对**已填 witness** 的交易重新建立摘要缓存：
    // BIP143 的 sighash 只看本输入的 `scriptCode + 金额`，并不依赖 witness 内容本身，
    // 故填好 witness 后重算出的 sighash 与签名时完全一致。
    let mut cache = SighashCache::new(tx);
    for (index, (script, value)) in witness_metas.iter().enumerate() {
        // 取该输入 witness 的首项——它应是 `DER 签名 || SIGHASH_ALL`；为空说明装配漏了。
        let items = tx.input[index].witness.to_vec();
        let der = match items.first() {
            Some(d) => d,
            None => return Err(anyhow::anyhow!(
                "第 {index} 个输入的 witness 组装后为空：witness 未被正确填入"
            )),
        };
        // witness 首项尾字节必须是 SIGHASH_ALL(0x01)；剥掉它才是纯 DER，才能 `from_der`。
        if der.last().copied() != Some(SIGHASH_ALL_BYTE) {
            return Err(anyhow::anyhow!(
                "第 {index} 个输入的 witness 签名尾字节不是 SIGHASH_ALL(0x01)"
            ));
        }
        let recovered = SecpSignature::from_der(&der[..der.len() - 1])
            .map_err(|e| anyhow::anyhow!("第 {index} 个输入的 DER 签名无法解码: {e}"))?;
        // 重算 BIP143 sighash 并验签：锁死「witness 填对了（顺序、DER 形态、SIGHASH 字节）」。
        let sh = cache
            .p2wpkh_signature_hash(index, script, *value, EcdsaSighashType::All)
            .map_err(|e| anyhow::anyhow!("第 {index} 个输入最终 sighash 失败: {e}"))?;
        secp.verify_ecdsa(&Message::from_digest(sh.to_byte_array()), &recovered, public_key)
            .map_err(|e| anyhow::anyhow!("第 {index} 个输入组装后的 witness 验签失败: {e}"))?;
    }
    Ok(())
}

#[cfg(test)] mod tests;
