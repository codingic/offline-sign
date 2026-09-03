// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
    use super::*;
    use crate::store::Scheme;
    use serde_json::json;

    // 复用 eth.rs 里那条**真实主网向量**：它是唯一一条「只有 sign_eth 能消化」的输入，
    // 因此能把 `eth` 的路由与其它六条链区分开（详见下面第一条测试的说明）。
    use crate::sign::eth::SDK_UNSIGNED_TX_HEX;

    fn secp256k1_key() -> StoredKey {
        StoredKey { scheme: Scheme::Secp256k1, seed: [1u8; 32] }
    }

    fn ed25519_key() -> StoredKey {
        StoredKey { scheme: Scheme::Ed25519, seed: [6u8; 32] }
    }

    /// **`eth` 必须被路由到 `sign_eth`**，而不是某条 ed25519 链。
    ///
    /// # 这条测试在防什么
    ///
    /// 分派表是七行 `match`，写错一行（比如把 `"sol"` 接到 `near::sign_near`）
    /// 在类型上完全合法——两边都是 `anyhow::Result<SignedResult>`，编译器不会吭声。
    /// 而各链自己的测试都是**直接调** `sign_near` / `sign_sol` 的，
    /// 于是分派表错位在本地是全绿的，只有真实调用方会拿到一条解不开的错误。
    /// 这和 APT / NEAR 那两个缺陷是同一类：**没人测过「连线」本身**。
    ///
    /// # 为什么这个判据能证伪
    ///
    /// ETH 的签名是 **65 字节可恢复签名**（`r ‖ s ‖ v`），hex 后是 130 个字符；
    /// 其余六条链里有五条是 ed25519，签名恒为 64 字节 = 128 个字符。
    /// 所以「130 位」这个数字本身就排除了「被路由到任一 ed25519 链」——
    /// 若真路由错了，要么解码直接失败，要么产出 128 位。
    #[tokio::test]
    async fn eth_is_routed_to_the_secp256k1_path() {
        let out = sign("eth", SDK_UNSIGNED_TX_HEX, None, &secp256k1_key())
            .await
            .expect("真实向量走 eth 路由必须成功");

        assert_eq!(
            out.signature.len(),
            2 + 130,
            "ETH 应产出 65 字节可恢复签名（`0x` + 130 hex）；\
             128 位说明被误路由到了某条 ed25519 链，实际: {}",
            out.signature
        );
        // 再钉一次产出形态：裸 EIP-2718（详见 eth.rs 的说明）。
        let raw = out.signed_tx.expect("eth 应产出 signed_tx");
        assert!(
            raw.starts_with("0x02"),
            "分派到 eth 后产出的应是 EIP-1559 信封，实际: {raw}"
        );
    }

    /// **`ton` 必须被路由到「只出签名」那条路**。
    ///
    /// TON 是七条链里唯一「来者不拒」的：它不解析字节结构，对任何输入都签名。
    /// 这个特性正好用来证伪——若 `"ton"` 被接到任何别的链上，
    /// 两个任意字节是解不开的，会直接报错。
    #[tokio::test]
    async fn ton_is_routed_to_the_signature_only_path() {
        // `0x00ff` 不是一个合法交易，但 TON 不解析结构，照签不误。
        let out = sign("ton", "0x00ff", None, &ed25519_key())
            .await
            .expect("ton 对任意字节都应签名成功");

        assert!(
            out.signed_tx.is_none(),
            "ton 只出签名、不组装交易；出现 signed_tx 说明被路由到了别的链"
        );
        let note = out.note.expect("ton 应带说明");
        assert!(note.contains("钱包"), "说明应点明原因，实际: {note}");
        // ed25519 签名 = 64 字节 = 128 hex，与上面的 ETH 判据互为对照。
        assert_eq!(out.signature.len(), 2 + 128, "ton 应是 64 字节签名");
    }

    /// 其余各链**必须拒绝**任意字节——用来防止它们被误接到 `ton` 上。
    ///
    /// 反证的那一半：若 `"sol"` 被接到 `ton::sign_ton`，下面这条会由红转绿吗？
    /// 不会——它会**失败**（`expect` 通过变成 `is_err()` 不成立），正是我们要的。
    #[tokio::test]
    async fn the_structuring_chains_reject_arbitrary_bytes() {
        for chain in ["sol", "near", "apt", "sui"] {
            let err = sign(chain, "0x00ff", None, &ed25519_key())
                .await
                .expect_err("{chain} 不应接受两个任意字节");
            assert!(
                !err.to_string().is_empty(),
                "{chain} 的报错应带原因，便于调用方定位"
            );
        }
    }

    /// **`icp` 必须被路由到「只出签名」那条路**（与 `ton` 同类）。
    ///
    /// ICP 也是「来者不拒」的链：它不解析字节结构，对任何输入都签名。
    /// 这个特性正好用来证伪——若 `"icp"` 被接到任何别的链上，
    /// 两个任意字节是解不开的，会直接报错。
    #[tokio::test]
    async fn icp_is_routed_to_the_signature_only_path() {
        // `0x00ff` 不是一个合法 IC 消息，但 ICP 不解析结构，照签不误。
        let out = sign("icp", "0x00ff", None, &ed25519_key())
            .await
            .expect("icp 对任意字节都应签名成功");

        assert!(
            out.signed_tx.is_none(),
            "icp 只出签名、不组装信封；出现 signed_tx 说明被路由到了别的链"
        );
        let note = out.note.expect("icp 应带说明");
        assert!(note.contains("不组装"), "说明应点明原因，实际: {note}");
        // ed25519 签名 = 64 字节 = 128 hex，与上面的 TON 判据互为对照。
        assert_eq!(out.signature.len(), 2 + 128, "icp 应是 64 字节签名");
    }

    /// BTC 缺 `context` 必须报错，且错误信息要说清**为什么**需要它。
    ///
    /// 这条错误信息是给调用方看的：它要能让人直接去 `build_transfer` 的响应里
    /// 找 `extra.submit_context`，而不是对着「缺少参数」发呆。
    #[tokio::test]
    async fn btc_requires_a_context() {
        let err = sign("btc", "0x00", None, &secp256k1_key())
            .await
            .expect_err("btc 不传 context 必须被拒");
        let msg = err.to_string();
        assert!(msg.contains("context"), "应点名缺的是 context，实际: {msg}");
        assert!(
            msg.contains("金额"),
            "应说清为什么要 context（BIP143 sighash 需要输入金额），实际: {msg}"
        );
    }

    /// 非 BTC 链传了 `context` 必须被拒——**不静默忽略**。
    ///
    /// 静默忽略的坏处：调用方以为传了上下文会有某种效果，
    /// 实际上它没参与任何计算。这种「看起来生效了」的错觉比直接报错难排查得多。
    #[tokio::test]
    async fn non_btc_chains_reject_a_context() {
        let ctx = json!({ "network": "mainnet" });
        let err = sign("sol", "0x00", Some(&ctx), &ed25519_key())
            .await
            .expect_err("非 btc 链不接受 context");
        let msg = err.to_string();
        assert!(msg.contains("只有 btc"), "应点明只有 btc 需要它，实际: {msg}");
    }

    /// 未知链必须报错，且把可选项列全——调用方照着改就行。
    #[tokio::test]
    async fn an_unknown_chain_is_rejected() {
        let err = sign("ckb", "0x00", None, &secp256k1_key())
            .await
            .expect_err("未接入的链必须被拒");
        let msg = err.to_string();
        assert!(msg.contains("不支持的链"), "实际: {msg}");
        for c in ["eth", "btc", "sol", "near", "apt", "sui", "ton", "icp"] {
            assert!(msg.contains(c), "错误信息应列出可选链 {c}，实际: {msg}");
        }
    }

    /// **错误码**必须是 `Unsupported`（HTTP 501），而不是被一刀切成 `INTERNAL`。
    ///
    /// 只断言 message 不够——message 里本来就含「不支持的链」，但 HTTP 状态码
    /// 取决于 `code`。这条把「未知链 → UNSUPPORTED」这个分类契约钉死，
    /// 免得有人把 `sign::sign` 的兜底分类改回全 INTERNAL。
    #[tokio::test]
    async fn an_unknown_chain_is_rejected_with_the_unsupported_code() {
        let err = sign("ckb", "0x00", None, &secp256k1_key())
            .await
            .expect_err("未接入的链必须被拒");
        assert_eq!(
            err.code,
            ErrorCode::Unsupported,
            "未知链应 UNSUPPORTED，实际: {}",
            err.code.as_str()
        );
    }

    /// **错误码**必须是 `InvalidArgument`（HTTP 400），而不是 `INTERNAL`。
    ///
    /// 这正是这次修复要解决的事故：调用方参数错（缺 context / 多传 context）
    /// 之前全被标成 INTERNAL（500），调用方分不清「自己参数错了」还是
    /// 「签名器内部挂了」。两条都覆盖，证明分类器对 BTC / 非 BTC 都生效。
    #[tokio::test]
    async fn caller_parameter_errors_are_invalid_argument() {
        // BTC 缺 context：参数错。
        let err = sign("btc", "0x00", None, &secp256k1_key())
            .await
            .expect_err("btc 不传 context 必须被拒");
        assert_eq!(
            err.code,
            ErrorCode::InvalidArgument,
            "缺 context 应 INVALID_ARGUMENT，实际: {}",
            err.code.as_str()
        );

        // 非 BTC 链多传了 context：参数错。
        let ctx = json!({ "network": "mainnet" });
        let err = sign("sol", "0x00", Some(&ctx), &ed25519_key())
            .await
            .expect_err("非 btc 链不接受 context");
        assert_eq!(
            err.code,
            ErrorCode::InvalidArgument,
            "多传 context 应 INVALID_ARGUMENT，实际: {}",
            err.code.as_str()
        );
    }

    /// `strip_0x` 的三种输入形态：两种拼写的前缀 + 没有前缀。
    ///
    /// # 为什么连 `0X` 都要测
    ///
    /// 大写 `0X` 是合法的 hex 前缀写法（Solidity / Go 里都常见），
    /// 调用方从别处拷贝过来的字符串完全可能带它。只认小写会让这类输入
    /// 在 `hex::decode` 那里报一句「Invalid character 'X'」——
    /// 信息指向错误的位置，排查方向就跑偏了。
    #[test]
    fn strip_0x_handles_both_spellings_and_absence() {
        assert_eq!(strip_0x("0xab"), "ab");
        assert_eq!(strip_0x("0Xab"), "ab", "大写 0X 前缀也要认");
        assert_eq!(strip_0x("ab"), "ab", "无前缀应原样返回");
        // 只剥一层：`0x0xab` 是调用方写错了，这里不该无限剥下去把错误吞掉。
        assert_eq!(strip_0x("0x0xab"), "0xab");
        assert_eq!(strip_0x(""), "");
    }

    /// `decode_txdata` 的报错必须带上调用方传入的那句「这段字节本该是什么」。
    ///
    /// 这是当初把入参从 `&[u8]` 改成 `&str` 的**唯一理由**：
    /// 解码放在各链内部，各链才能给出自己的那句描述。
    /// 若哪天有人把解码收回分派层、统一成一句「需 hex」，这条会红。
    #[test]
    fn decode_txdata_names_the_expected_shape_in_its_error() {
        let err = decode_txdata("0xZZZZ", "SOL 完整交易（bincode Transaction）")
            .expect_err("非 hex 必须被拒");
        let msg = err.to_string();
        assert!(msg.contains("SOL 完整交易"), "报错应带上链的形状描述，实际: {msg}");
        assert!(msg.contains("hex"), "应说明需要的是 hex，实际: {msg}");
        assert!(
            msg.contains('4'),
            "应报出收到的字符数（此处 4 个），便于调用方自查，实际: {msg}"
        );
    }

    /// 三种被接受的写法必须等价：带 `0x`、带 `0X`、带首尾空白。
    #[test]
    fn decode_txdata_accepts_every_spelling_that_callers_actually_send() {
        let plain = decode_txdata("0011ff", "测试").expect("无前缀");
        assert_eq!(plain, vec![0x00, 0x11, 0xff]);

        for spelled in ["0x0011ff", "0X0011ff", "  0x0011ff  ", "0x0011ff\n"] {
            let got = decode_txdata(spelled, "测试")
                .unwrap_or_else(|e| panic!("{spelled:?} 应被接受，实际报错: {e}"));
            assert_eq!(got, plain, "{spelled:?} 应与无前缀写法等价");
        }

        // 前缀剥在 trim **之后**：`" 0xab"` 若先剥前缀会失败（前面有空格）。
        // 这条断言把「顺序即正确性」钉住——两个操作交换一下就会红。
        assert!(decode_txdata(" 0x0011ff", "测试").is_ok());
    }

    /// 奇数长度必须被拒，而不是被 `hex::decode` 之后静默截断。
    #[test]
    fn an_odd_length_hex_string_is_rejected() {
        let err = decode_txdata("0xabc", "测试").expect_err("奇数长度 hex 非法");
        assert!(!err.to_string().is_empty());
    }
