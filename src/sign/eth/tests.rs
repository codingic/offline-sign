// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
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
    fn decodes_the_unsignedtxdatahex_that_the_sdk_actually_emits() {
        // 本 crate 没有 `hexutil`（那是 SDK workspace 的），这里手动剥 `0x`。
        // `trim_start_matches` 会把连续的前缀全去掉，对 `0x…` 而言恰好只去一次。
        let body = SDK_UNSIGNED_TX_HEX.trim_start_matches("0x");
        let bytes = hex::decode(body).expect("向量应是合法 hex");
        let typed = decode_unsignedtxdatahex(&bytes).expect("SDK 产出的未签名交易必须能被解码");

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

    /// **端到端产出**：`signedtxdatahex` 必须是**裸的 EIP-2718 交易**，不能多套一层 RLP。
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
    async fn signedtxdatahex_is_a_bare_eip2718_envelope() {
        use alloy::consensus::{EthereumTxEnvelope, TxEip1559};
        use alloy::eips::eip2718::Decodable2718;

        // 固定种子，让测试可复现（1…1 是合法的 secp256k1 标量）。
        let key = StoredKey { scheme: Scheme::Secp256k1, seed: [1u8; 32] };
        let r = sign_eth(SDK_UNSIGNED_TX_HEX, &key)
            .await
            .expect("真实向量应能签名");
        let raw = r.signedtxdatahex.expect("ETH 必须产出 signedtxdatahex");

        // 主断言：类型字节 0x02 = EIP-1559。
        assert!(
            raw.starts_with("0x02"),
            "signedtxdatahex 应以 EIP-1559 类型字节 0x02 开头，实际: {raw}"
        );
        // 反证：不能带 RLP 字符串头。`b8` 是「长字符串」头，
        // 它出现在开头就说明又套了一层。
        assert!(
            !raw.starts_with("0xb8"),
            "signedtxdatahex 不应带 RLP 长字符串头（说明多套了一层 RLP 封装），实际: {raw}"
        );

        // 往返：解回来后字段必须与原交易一致——只比对前缀挡不住「类型字节对但内容错」。
        let bytes = hex::decode(&raw[2..]).expect("signedtxdatahex 应是合法 hex");
        // txhash 独立校验：keccak256(signed bytes) 必须等于响应里的 txhash，且形态为 0x + 64 hex。
        // `keccak256` 经 `use super::*` 已可见（来自 eth.rs 模块级 import）。
        let expected = format!("0x{}", hex::encode(keccak256(&bytes).as_slice()));
        assert_eq!(
            r.txhash.as_deref(),
            Some(expected.as_str()),
            "txhash 应为 keccak256(signedtxdatahex 字节)"
        );
        let h = r.txhash.as_ref().unwrap();
        assert!(
            h.starts_with("0x") && h.len() == 66,
            "ETH txhash 应为 0x + 64 位 hex，实际: {h}"
        );
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
            decode_unsignedtxdatahex(&hash).is_err(),
            "契约规定输入是完整交易而非单独的待签哈希；喂哈希必须报错，\
             否则调用方传错东西时会静默签出无效签名"
        );
    }

    /// **反向反证（加密正确性）**：`signedtxdatahex` 里的签名必须能恢复出签名者地址，
    /// 且与该 keystore 在 eth 上的地址一致。
    ///
    /// # 为什么这条不能少
    ///
    /// 上面的 `signedtxdatahex_is_a_bare_eip2718_envelope` 只断言「能解回、字段对」——
    /// 那挡不住「签名算错了一个字节、但 RLP 结构仍然合法」的情况：本地解回照样成功，
    /// 只有节点广播时才拒绝。恢复出地址并比对，等于在本地就跑了一遍节点会做的 ECDSA 验签，
    /// 把「签名到底对不对」这件事从「广播后才暴露」提前到「单测里就红」。
    ///
    /// # 语法要点
    ///
    /// `recover_signer()` 走的是与节点完全相同的恢复路径（含 EIP-155 的 y-parity），
    /// 返回 `Result<Address>`；它内部用交易哈希 + 签名反算公钥再派生地址，
    /// 与「先 `sign_transaction` 再 `into_envelope`」正反向闭环。
    #[tokio::test]
    async fn signedtxdatahex_signature_recovers_to_the_signer() {
        use alloy::consensus::{EthereumTxEnvelope, TxEip1559};
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::eips::eip2718::Decodable2718;
        use alloy::primitives::Address;

        let seed = [1u8; 32];
        let key = StoredKey { scheme: Scheme::Secp256k1, seed };
        let r = sign_eth(SDK_UNSIGNED_TX_HEX, &key)
            .await
            .expect("真实向量应能签名");
        let raw = r.signedtxdatahex.expect("ETH 必须产出 signedtxdatahex");

        let bytes = hex::decode(&raw[2..]).expect("signedtxdatahex 应是合法 hex");
        let env: EthereumTxEnvelope<TxEip1559> =
            EthereumTxEnvelope::decode_2718(&mut bytes.as_slice())
                .expect("产出的字节必须能被解回一个信封");
        // `recover_signer` 是 `TypedTxEnvelope` 的方法：用交易哈希 + 签名反算公钥地址。
        let signer: Address = env
            .recover_signer()
            .expect("signedtxdatahex 的签名必须能恢复出签名者");

        let expected = crate::keys::derive("eth", &seed)
            .expect("derive 不应失败")
            .address;
        assert_eq!(
            format!("{signer:#x}"),
            expected,
            "signedtxdatahex 的签名应恢复到本 keystore 在 eth 上的地址（说明签的是这笔交易、且密钥正确）"
        );
    }

    /// ERC20 transfer 走通：构造一笔 `transfer(address,uint256)` 调用的 EIP-1559 交易，
    /// 经 `sign_eth` 签名后，`signedtxdatahex` 仍是裸 EIP-2718、`to` 是 token 合约、
    /// `input` 是合法 calldata，且 `note` 标注出 token/recipient/amount。
    ///
    /// 关键不变量：sign 作为纯离线签名器，**不**因 ERC20 而改变签名行为——
    /// 它签的就是「一笔完整交易」，ERC20 只在 note 里被解析标注，便于对账。
    #[tokio::test]
    async fn signs_an_erc20_transfer_and_annotates_it() {
        use alloy::consensus::{EthereumTxEnvelope, SignableTransaction, TxEip1559};
        use alloy::consensus::Transaction;
        use alloy::eips::eip2718::Decodable2718;
        use alloy::primitives::{address, TxKind};

        // token 合约地址与收款地址（任意有效地址，测试不广播）。
        let token = address!("0x1111111111111111111111111111111111111111");
        let recipient = address!("0x2222222222222222222222222222222222222222");
        let amount = U256::from(1_250_000_000_000u128); // 0.00125 个 token（以 6 位小数为例）

        // 手工拼 `transfer(address,uint256)` 的 ABI calldata。
        let mut data = Vec::new();
        data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // selector = keccak256("transfer(address,uint256)")[..4]
        let mut recipient_word = [0u8; 32];
        recipient_word[12..32].copy_from_slice(recipient.as_slice()); // address 左填充 0 到 32 字节
        data.extend_from_slice(&recipient_word);
        let amount_word: [u8; 32] = amount.to_be_bytes(); // uint256 大端 32 字节
        data.extend_from_slice(&amount_word);

        // 组装一笔 EIP-1559 交易（value=0，因为是代币转账、ETH 不随附）。
        let tx = TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 60_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(token),
            value: U256::ZERO,
            input: data.clone().into(),
            access_list: Default::default(),
        };
        // 取「待签原像」（与 SDK `assemble_unsigned` 同口径），前缀 0x 交给 sign_eth 解。
        let mut buf = Vec::new();
        tx.encode_for_signing(&mut buf);
        let unsigned_hex = format!("0x{}", hex::encode(&buf));

        let key = StoredKey { scheme: Scheme::Secp256k1, seed: [1u8; 32] };
        let r = sign_eth(&unsigned_hex, &key)
            .await
            .expect("ERC20 未签名交易必须能签名");
        let raw = r.signedtxdatahex.expect("ETH 必须产出 signedtxdatahex");

        // 主断言 1：仍是裸 EIP-2718（不能以 RLP 字符串头开头）。
        assert!(raw.starts_with("0x02"), "signedtxdatahex 应以 0x02 开头，实际: {raw}");
        assert!(!raw.starts_with("0xb8"), "不应带 RLP 长字符串头，实际: {raw}");

        // 主断言 2：解回来后 `to` 是 token、`input` 是原始 calldata（证明签的是同一笔 ERC20）。
        let bytes = hex::decode(&raw[2..]).expect("signedtxdatahex 应是合法 hex");
        let decoded: EthereumTxEnvelope<TxEip1559> =
            EthereumTxEnvelope::decode_2718(&mut bytes.as_slice())
                .expect("产出的字节应能被解回信封");
        assert_eq!(decoded.to(), Some(token), "解回的 to 应为 token 合约");
        let expected_input: Bytes = data.into();
        assert_eq!(decoded.input(), &expected_input, "解回的 input 应为 ERC20 calldata");

        // 主断言 3：note 标注出 ERC20 三方（token/recipient/amount），且 txhash 自洽。
        let note = r.note.expect("note 不应为空");
        assert!(note.contains("ERC20"), "note 应标注这是一笔 ERC20 交易，实际: {note}");
        assert!(
            note.contains(&format!("{recipient}")),
            "note 应含收款地址 {recipient}，实际: {note}"
        );
        let expected_hash = format!("0x{}", hex::encode(keccak256(&bytes).as_slice()));
        assert_eq!(
            r.txhash.as_deref(),
            Some(expected_hash.as_str()),
            "txhash 应为 keccak256(signed bytes)"
        );
    }
