// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
    use super::*;

    use std::str::FromStr;

    use bitcoin::{Address, Amount, Network, OutPoint, Sequence, TxIn, TxOut, Txid, Witness};
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use serde_json::json;

    use crate::store::Scheme;

    // ——— 外部真值 ———
    //
    // 私钥 1（`0x…01`）是 BIP173 / BIP143 官方示例用的那把钥匙。它的**压缩公钥**
    // 与对应的**主网 P2WPKH 地址**由 `keys/tests.rs` 里的独立 Python 实现对拍过
    // （secp256k1 点乘 + hash160 + BIP173 bech32），不含本 crate 任何代码。

    /// 私钥 1（裸 32 字节十六进制）。
    const FIXTURE_PRIVKEY: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";
    /// 私钥 1 的**压缩**公钥（33 字节）。
    const FIXTURE_PUBKEY: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// 私钥 1 的主网 P2WPKH 地址（独立 Python 实现算出的真值）。
    const FIXTURE_P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    // —— BIP143 官方测试向量 ——
    //
    // 来源：https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    // 「Native P2WPKH」一节。这是**独立于本工程**的公开向量，用来对拍
    // `p2wpkh_signature_hash` 的**调用方式**：金额的参与、SIGHASH 标志、
    // scriptCode 的取法。任一处传错都不会报错，只会产出广播即失败的签名。

    /// 官方给出的未签名交易（2 输入：第 0 个是 P2PK，第 1 个是 P2WPKH）。
    const BIP143_UNSIGNED_TX: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
    /// 第 1 个输入（P2WPKH）的锁定脚本。
    const BIP143_INPUT_SPK: &str = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
    /// 第 1 个输入的金额：6 BTC。
    const BIP143_INPUT_VALUE: u64 = 600_000_000;
    /// 官方给出的 sighash（对第 1 个输入、nHashType = SIGHASH_ALL）。
    const BIP143_SIGHASH: &str =
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";

    /// 两个占位 outpoint（本地签名不需要它们真实存在）。
    const TXID_A: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    const TXID_B: &str = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098";

    // ——— 夹具 ———

    /// 由**外部真值地址**构造 P2WPKH 锁定脚本（与 context 里的字段相互独立）。
    fn fixture_script() -> ScriptBuf {
        let address = Address::from_str(FIXTURE_P2WPKH)
            .expect("真值地址应能解析")
            .require_network(Network::Bitcoin)
            .expect("真值地址应属主网");
        address.script_pubkey()
    }

    /// 一笔「两输入 + 两输出」的**未签名** P2WPKH 交易模板。
    fn fixture_tx() -> Transaction {
        let script = fixture_script();
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(0),
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: Txid::from_str(TXID_A).unwrap(), vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    // 未签名模板：witness 恒为空。
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint { txid: Txid::from_str(TXID_B).unwrap(), vout: 1 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![
                TxOut { value: Amount::from_sat(120_000), script_pubkey: script.clone() },
                TxOut { value: Amount::from_sat(38_955), script_pubkey: script },
            ],
        }
    }

    /// `sign_btc` 的入参形态：**hex 字符串**，不是字节。
    fn fixture_txdata() -> String {
        encode::serialize_hex(&fixture_tx())
    }

    /// 与 `fixture_tx` 配套的上下文，形态与 SDK `extra.submit_context` 一致。
    fn fixture_context() -> Value {
        let script_hex = hex::encode(fixture_script().as_bytes());
        json!({
            "network": "mainnet",
            "version": 2,
            "locktime": 0,
            "public_key": FIXTURE_PUBKEY,
            "inputs": [
                {
                    "txid": TXID_A, "vout": 0, "sequence": 4294967293u32,
                    "value": 100_000u64, "script_pubkey": script_hex, "script_type": "p2wpkh"
                },
                {
                    "txid": TXID_B, "vout": 1, "sequence": 4294967293u32,
                    "value": 60_000u64, "script_pubkey": script_hex, "script_type": "p2wpkh"
                }
            ],
            "outputs": [
                { "value": 120_000u64, "script_pubkey": script_hex },
                { "value": 38_955u64, "script_pubkey": script_hex }
            ],
            "unsigned_tx_hex": fixture_txdata(),
        })
    }

    fn fixture_key() -> StoredKey {
        let seed: [u8; 32] = hex::decode(FIXTURE_PRIVKEY).unwrap().try_into().unwrap();
        StoredKey { scheme: Scheme::Secp256k1, seed }
    }

    /// 独立算出逐输入的 BIP143 sighash（供验签与对拍）。
    fn bip143_sighashes(tx: &Transaction, ctx: &Value) -> Vec<[u8; 32]> {
        let mut cache = SighashCache::new(tx);
        ctx["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, meta)| {
                let script = ScriptBuf::from(hex::decode(meta["script_pubkey"].as_str().unwrap()).unwrap());
                cache
                    .p2wpkh_signature_hash(
                        index,
                        &script,
                        Amount::from_sat(meta["value"].as_u64().unwrap()),
                        EcdsaSighashType::All,
                    )
                    .unwrap()
                    .to_byte_array()
            })
            .collect()
    }

    /// 用**外部真值公钥**验一个紧凑签名。
    fn verify(sighash: &[u8; 32], compact: &[u8]) -> bool {
        let secp = Secp256k1::new();
        let public_key = SecpPublicKey::from_slice(&hex::decode(FIXTURE_PUBKEY).unwrap()).unwrap();
        let sig = match bitcoin::secp256k1::ecdsa::Signature::from_compact(compact) {
            Ok(s) => s,
            Err(_) => return false,
        };
        secp.verify_ecdsa(&Message::from_digest(*sighash), &sig, &public_key).is_ok()
    }

    /// 把结果的签名数组解成字节。
    fn compact_signatures(result: &SignedResult) -> Vec<Vec<u8>> {
        result.signatures.iter().map(|s| hex::decode(s.strip_prefix("0x").unwrap()).unwrap()).collect()
    }

    // ——— 与官方向量对拍 ———

    /// sighash 必须与 **BIP143 官方向量**逐字节一致。
    ///
    /// 这条钉住的是「调用哪个库函数、传哪些参数」：金额的单位（satoshi 而非 BTC）、
    /// SIGHASH 标志、scriptCode 的取法——BIP143 与传统算法在这三点上全都不同，
    /// 传错不会报错，只会得到广播即失败的无效签名。
    #[test]
    fn bip143_sighash_matches_the_official_test_vector() {
        let tx: Transaction = encode::deserialize_hex(BIP143_UNSIGNED_TX).unwrap();
        let spk = ScriptBuf::from(hex::decode(BIP143_INPUT_SPK).unwrap());

        let mut cache = SighashCache::new(&tx);
        let got = cache
            .p2wpkh_signature_hash(
                1,
                &spk,
                Amount::from_sat(BIP143_INPUT_VALUE),
                EcdsaSighashType::All,
            )
            .unwrap()
            .to_byte_array();

        assert_eq!(hex::encode(got), BIP143_SIGHASH);
    }

    // ——— 端到端 ———

    /// 每个输入各出一个 64 字节紧凑签名，数量与输入数严格相等。
    ///
    /// 「数量相等」最容易被静默破坏：循环若提前结束或过滤了输入，结果照样是 Ok，
    /// 只是少一个签名——直到广播时整笔交易作废。
    #[test]
    fn every_input_gets_its_own_compact_signature() {
        let tx = fixture_tx();
        let result =
            sign_btc(&fixture_txdata(), &fixture_context(), &fixture_key()).expect("夹具应能正常签名");

        assert_eq!(result.signatures.len(), tx.input.len());
        assert!(result.signedtxdatahex.is_some(), "BTC 应返回组装好的完整交易");
        for (index, raw) in compact_signatures(&result).iter().enumerate() {
            assert_eq!(
                raw.len(),
                COMPACT_SIGNATURE_LEN,
                "第 {index} 个签名应为 64 字节紧凑格式"
            );
        }
    }

    /// 每个签名都必须能被**外部真值公钥**对**独立算出的 sighash** 验过。
    ///
    /// 这条是整套测试的地基：公钥来自真值常量、sighash 由测试自己算，
    /// 与生产代码内部的派生路径相互独立。
    #[test]
    fn signatures_verify_against_the_independently_computed_sighash() {
        let tx = fixture_tx();
        let ctx = fixture_context();
        let result = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).expect("夹具应能正常签名");
        let hashes = bip143_sighashes(&tx, &ctx);

        for (index, raw) in compact_signatures(&result).iter().enumerate() {
            assert!(
                verify(&hashes[index], raw),
                "第 {index} 个签名没能用真值公钥验过"
            );
        }
    }

    /// `signedtxdatahex` 必须是一笔**能反序列化、witness 已填、且 DER 签名验得过**的广播交易。
    ///
    /// 这条是「sign 组装 witness」的核心保证：它独立于生产代码，自己重算 BIP143 sighash、
    /// 解出 witness 里的 DER 签名、用真值公钥验签。任何装配错误（DER 形态、SIGHASH 字节、
    /// `[签名, 公钥]` 顺序）都会让它变红——而不是等到广播才暴露。
    #[test]
    fn signedtxdatahex_is_a_broadcastable_transaction() {
        let tx = fixture_tx();
        let ctx = fixture_context();
        let result = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).expect("夹具应能正常签名");
        let signed = result.signedtxdatahex.expect("应返回 signedtxdatahex");

        // 1) 能反序列化为带 witness 的完整交易。
        let signedtxdatahex: Transaction = encode::deserialize_hex(signed.strip_prefix("0x").unwrap())
            .expect("signedtxdatahex 应是合法交易 hex");
        assert_eq!(signedtxdatahex.input.len(), tx.input.len(), "输入数不应变");
        for (index, inp) in signedtxdatahex.input.iter().enumerate() {
            assert!(!inp.witness.is_empty(), "第 {index} 个输入的 witness 必须已填");
            // P2WPKH witness = [DER 签名, 压缩公钥]，恰两项。
            assert_eq!(inp.witness.len(), 2, "第 {index} 个输入的 witness 应恰有 2 项");
        }

        // 3) `txhash` 必须等于这笔已签名交易的链上 txid（独立重算，不依赖生产代码）。
        // `compute_txid()` 对 `signedtxdatahex` 反序列化后的交易直接算 double-SHA256 反序，
        // 与 `sign_btc` 内部调用的同一方法——但这里是测试自己算的，能钉住「返回的 txhash 确为本交易」。
        let expected_txhash = format!("0x{}", signedtxdatahex.compute_txid());
        assert_eq!(
            result.txhash.as_deref(),
            Some(expected_txhash.as_str()),
            "txhash 应等于已签名交易的 txid"
        );
        // 形态：0x + 64 hex 字符。
        let h = result.txhash.as_ref().unwrap();
        assert!(
            h.starts_with("0x") && h.len() == 66,
            "txhash 应为 0x + 64 位 hex，实际: {h}"
        );

        // 2) 每个 witness 里的 DER 签名都能用真值公钥验过独立算出的 BIP143 sighash。
        let secp = Secp256k1::new();
        let public_key = SecpPublicKey::from_slice(&hex::decode(FIXTURE_PUBKEY).unwrap()).unwrap();
        let hashes = bip143_sighashes(&signedtxdatahex, &ctx);
        for (index, _h) in hashes.iter().enumerate() {
            let items = signedtxdatahex.input[index].witness.to_vec();
            // 第一项是 DER 签名（尾部带 SIGHASH_ALL 字节），去掉尾巴再解码。
            let der = items.first().expect("witness 首项为签名");
            assert_eq!(der.last().copied(), Some(0x01), "SIGHASH 字节应为 SIGHASH_ALL(0x01)");
            let sig = SecpSignature::from_der(&der[..der.len() - 1])
                .expect("witness 里的签名应能被 DER 解码");
            assert!(
                secp
                    .verify_ecdsa(&Message::from_digest(hashes[index]), &sig, &public_key)
                    .is_ok(),
                "第 {index} 个 witness 签名没能用真值公钥验过"
            );
        }
    }

    // ——— 只支持 P2WPKH ———

    /// **P2PKH 输入必须被明确拒绝**。
    ///
    /// 传统算法的 sighash 不含金额，与 BIP143 是两个世界。放行它只会产出
    /// 「签得出来、本地验得过、广播必被拒」的签名。
    #[test]
    fn a_p2pkh_input_is_rejected() {
        let mut ctx = fixture_context();
        ctx["inputs"][1]["script_type"] = json!("p2pkh");

        let err = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("p2pkh"), "应点名是哪个脚本类型被拒，实际: {msg}");
        assert!(msg.contains("p2wpkh"), "应说明只支持 p2wpkh，实际: {msg}");
    }

    /// 未知脚本类型（如 P2TR）必须拒绝，而不是按 p2wpkh 兜底。
    #[test]
    fn an_unknown_script_type_is_rejected() {
        let mut ctx = fixture_context();
        ctx["inputs"][0]["script_type"] = json!("p2tr");

        let err = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("p2tr"),
            "应回显收到的类型，实际: {err}"
        );
    }

    // ——— 反证：sighash 的构成 ———

    /// 签名**不能**挪到另一个输入上用。
    ///
    /// SIGHASH_ALL 下每个输入的 sighash 都覆盖全部输入，
    /// 所以第 0 个输入的签名对第 1 个输入无效。
    #[test]
    fn signatures_cannot_be_moved_between_inputs() {
        let tx = fixture_tx();
        let ctx = fixture_context();
        let result = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).expect("夹具应能正常签名");
        let sigs = compact_signatures(&result);
        let hashes = bip143_sighashes(&tx, &ctx);

        // 前提：两个输入的 sighash 确实不同，否则这条测试是空的。
        assert_ne!(hashes[0], hashes[1]);

        assert!(!verify(&hashes[1], &sigs[0]), "第 0 个签名不应验得过第 1 个输入");
        assert!(!verify(&hashes[0], &sigs[1]), "第 1 个签名不应验得过第 0 个输入");
    }

    /// 改动**任何一个输出**，全部签名都必须作废（SIGHASH_ALL 的定义）。
    #[test]
    fn changing_an_output_invalidates_every_signature() {
        let ctx = fixture_context();
        let result = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).expect("夹具应能正常签名");
        let sigs = compact_signatures(&result);

        let mut tampered = fixture_tx();
        tampered.output[0].value = Amount::from_sat(1);
        let hashes = bip143_sighashes(&tampered, &ctx);

        for (index, raw) in sigs.iter().enumerate() {
            assert!(
                !verify(&hashes[index], raw),
                "改了输出后第 {index} 个签名竟然还验得过：sighash 没覆盖全部输出"
            );
        }
    }

    /// **金额参与哈希**：把某个输入的 `value` 改掉，那个输入的签名必须作废。
    ///
    /// 这是 BIP143 与传统算法**最本质**的差别，也是「必须有 context」的唯一原因。
    /// 少了这条，「把金额从哈希里漏掉」的实现也能通过前面的测试。
    ///
    /// 顺带钉住一个容易搞反的细节：金额**只**进入本输入那一条 sighash。
    /// BIP143 的 `hashPrevouts` / `hashSequence` 只覆盖各输入的 outpoint 与
    /// sequence，不含金额——所以改第 1 个输入的金额，第 0 个输入的 sighash 不变。
    #[test]
    fn changing_an_input_value_invalidates_that_inputs_signature() {
        let ctx = fixture_context();
        let result = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).expect("夹具应能正常签名");
        let sigs = compact_signatures(&result);

        let mut tampered_ctx = ctx.clone();
        tampered_ctx["inputs"][1]["value"] = json!(60_001u64);
        let hashes = bip143_sighashes(&fixture_tx(), &tampered_ctx);

        // 被改的那个输入：签名必须作废。
        assert!(
            !verify(&hashes[1], &sigs[1]),
            "改了第 1 个输入的金额，它的签名竟然还验得过：金额没有参与哈希"
        );
        // 另一个输入：金额不会串过去，sighash 不变，签名仍然有效。
        assert!(
            verify(&hashes[0], &sigs[0]),
            "改第 1 个输入的金额不应影响第 0 个输入的 sighash"
        );
    }

    // ——— 上下文校验 ———

    /// 换了另一笔交易的 `txdatahex`（上下文不变）必须被拒绝。
    ///
    /// 没有这条，「第二道」校验可能根本没生效——而「签名落在另一笔交易上」
    /// 正是本模块最想防的事故。
    #[test]
    fn a_mismatched_txdatahex_is_rejected() {
        let mut tx = fixture_tx();
        tx.output[0].value = Amount::from_sat(1);

        let err = sign_btc(&encode::serialize_hex(&tx), &fixture_context(), &fixture_key())
            .unwrap_err();
        assert!(
            err.to_string().contains("不是同一笔交易"),
            "应报「不是同一笔交易」，实际: {err}"
        );
    }

    /// 用另一把钥匙的私钥去签这个上下文必须被拒绝。
    #[test]
    fn signing_with_a_different_key_is_rejected() {
        let other = StoredKey { scheme: Scheme::Secp256k1, seed: [7u8; 32] };
        let err = sign_btc(&fixture_txdata(), &fixture_context(), &other).unwrap_err();
        assert!(
            err.to_string().contains("公钥不一致"),
            "应报「公钥不一致」，实际: {err}"
        );
    }

    /// 非主网上下文必须拒绝（否则跨网签出的签名会被 SDK 的跨网护栏拦下，绕远路）。
    #[test]
    fn a_testnet_context_is_rejected() {
        let mut ctx = fixture_context();
        ctx["network"] = json!("testnet");

        let err = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).unwrap_err();
        assert!(err.to_string().contains("只支持 mainnet"), "实际: {err}");
    }

    /// context 缺字段（比如少 `value`）必须报错，不能按默认值继续。
    ///
    /// 少了 `value` 若被当成 0，sighash 会算出一个**看着正常**的值，
    /// 签名也验得过自己，只有节点会拒——这是最坏的一类失败。
    #[test]
    fn a_context_missing_input_value_is_rejected() {
        let mut ctx = fixture_context();
        ctx["inputs"][0].as_object_mut().unwrap().remove("value");

        let err = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("context 解析失败"),
            "缺字段应报解析失败，实际: {err}"
        );
    }

    /// `inputs` 比交易**少**一条时必须拒绝。
    ///
    /// 循环以 `tx.input` 为准、按 `index` 取 `ctx.inputs`，少一条会在循环里当场报
    /// 「缺第 N 个输入的元数据」，而不是让 `for` 提前结束、**静默少签**。
    #[test]
    fn a_context_with_the_wrong_input_count_is_rejected() {
        let mut ctx = fixture_context();
        ctx["inputs"].as_array_mut().unwrap().pop();

        let err = sign_btc(&fixture_txdata(), &ctx, &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("一一对应"),
            "应报输入数量不一致，实际: {err}"
        );
    }

    /// **另一个方向**：`inputs` **多**一条时不再报错，而是良性忽略。
    ///
    /// 以 `tx.input` 为权威集合后，多出来的条目根本不会被循环取到，所以无害。
    /// 这条把「多一条被误拒」钉死，免得有人又把独立 count 检查加回来。
    #[test]
    fn an_extra_context_input_is_ignored_as_benign() {
        let mut ctx = fixture_context();
        let inputs = ctx["inputs"].as_array_mut().unwrap();
        let extra = inputs[0].clone();
        inputs.push(extra);

        let result = sign_btc(&fixture_txdata(), &ctx, &fixture_key())
            .unwrap_or_else(|e| panic!("多一条 input 应被忽略而非报错，实际: {e}"));
        assert_eq!(
            result.signatures.len(),
            fixture_tx().input.len(),
            "签名数应等于交易的真实输入数"
        );
    }

    /// 已经带见证的输入必须被拒：`txdatahex` 只能是未签名模板。
    #[test]
    fn an_already_signed_input_is_rejected() {
        let mut tx = fixture_tx();
        let mut witness = Witness::new();
        witness.push([0x30u8, 0x44]);
        tx.input[0].witness = witness;
        let txdata = encode::serialize_hex(&tx);

        // 上下文的 `unsigned_tx_hex` 必须同步跟上，否则会先被「不是同一笔交易」
        // 拦下，轮不到见证检查——测试就测不到想测的那条护栏。
        let mut ctx = fixture_context();
        ctx["unsigned_tx_hex"] = json!(txdata);

        let err = sign_btc(&txdata, &ctx, &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("见证非空"),
            "应报见证非空，实际: {err}"
        );
    }

    /// 没有输入的交易必须被拒，而不是返回一个**空签名数组**这种「假成功」。
    #[test]
    fn a_transaction_without_inputs_is_rejected() {
        let mut tx = fixture_tx();
        tx.input.clear();
        let mut ctx = fixture_context();
        ctx["inputs"] = json!([]);
        ctx["unsigned_tx_hex"] = json!(encode::serialize_hex(&tx));

        let err = sign_btc(&encode::serialize_hex(&tx), &ctx, &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("没有输入"),
            "应报没有输入，实际: {err}"
        );
    }

    // ——— 输入格式 ———

    /// 喂一段不是交易的字节必须报错，不能静默产出废签名。
    #[test]
    fn garbage_txdata_is_rejected() {
        let err = sign_btc(&"ab".repeat(32), &fixture_context(), &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("解码失败"),
            "应报解码失败，实际: {err}"
        );
    }

    /// **hex 解码本身**失败时也必须报错，且错误信息要带上「这段字节本该是什么」。
    #[test]
    fn a_non_hex_txdata_is_rejected() {
        let err = sign_btc("0xZZZZ_not_hex", &fixture_context(), &fixture_key()).unwrap_err();
        assert!(
            err.to_string().contains("hex 解码失败"),
            "应报 hex 解码失败，实际: {err}"
        );
        assert!(
            err.to_string().contains("BTC"),
            "错误信息应带链名以便定位，实际: {err}"
        );
    }

    /// `0x` 前缀与首尾空白都必须被容忍（调用方常把 hex 嵌在多行 JSON 里）。
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

    // ——— 密钥 ———

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

    /// 种子不是合法 secp256k1 标量时必须报错，而不是默默产出废签名。
    #[test]
    fn an_invalid_secp256k1_seed_is_rejected() {
        let bad = StoredKey { scheme: Scheme::Secp256k1, seed: [0xffu8; 32] };
        let err = sign_btc(&fixture_txdata(), &fixture_context(), &bad).unwrap_err();
        assert!(
            err.to_string().contains("不是合法 secp256k1 私钥"),
            "实际: {err}"
        );
    }
