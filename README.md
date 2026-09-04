# sign — 本地离线签名服务

`sign` 是一个**离线签名器**：启动时用口令解锁加密 keystore 取出两条私钥（secp256k1 / ed25519 各一），
为各链派生地址并驻留内存，然后对调用方提交的**完整交易序列化字节**签名、组装成可广播交易。

> **位置与构建形态**：本 crate 位于 `allchain-rust-sdk` **之外**
> （`/Users/wangbinmac/Documents/allchainsdk/sign/`，与 `allchain-rust-sdk/` 同级），
> 是**独立 crate**——有自己的 `Cargo.lock` / `target/` / `rust-toolchain.toml`，
> 经相对路径 `../allchain-rust-sdk/core` 依赖 `allchain-core`。
> 因此 `cargo build --workspace` **不会**构建它，须 `cd sign` 单独构建。

- 监听地址：`127.0.0.1:7878`（**回环、无鉴权**，只接受本机信任进程的调用）
- **只有两个私钥**：一条 secp256k1（eth / btc）、一条 ed25519（sol / near / apt / sui / ton）。
  同一条私钥在不同链上派生出的地址天然不同，所以不必每条链各存一份。
  > **同一颗 secp256k1 种子在 eth 与 btc 上必须用不同的公钥编码**：eth 用**非压缩** 65 字节
  > （`04 ‖ X ‖ Y`）取 keccak256，btc 用**压缩** 33 字节（`02/03 ‖ X`）做 P2WPKH。
  > 两者不是同一串字节，地址也完全不同——有测试专门钉住这一点（反证：同一种子下
  > eth 地址不得等于 btc 地址，且公钥长度必须不同）。
- **私钥加密落盘**：两个 keystore 文件用口令派生的密钥（Argon2id）经 AES-256-GCM 加密后存在
  `~/.allchain-sign/`。磁盘上永不出现明文私钥；口令无法找回。
- 延后链（暂未实现）：`ckb` / `fil`（secp256k1）、`ar`（RSA）。

---

## 1. 构建与运行

```bash
cd /Users/wangbinmac/Documents/allchainsdk/sign
export PATH="/Users/wangbinmac/.cargo/bin:$PATH"
cargo build --release          # 产物 ./target/release/sign
# 或直接运行（debug）
cargo run
```

启动时会**先在终端问口令**（回显关闭），解锁后才开端口：

```
首次运行：将在 /Users/wangbinmac/.allchain-sign 创建两个加密 keystore 文件。
  - keystore-secp256k1.json   (eth / btc)
  - keystore-ed25519.json     (sol / near / apt / sui / ton)

口令用于加密这两个文件，**无法找回**——丢失即永久失去私钥。

新口令（至少 8 字符，无法找回）:
再输一次以确认:
口令来源: 终端输入
  已创建: /Users/wangbinmac/.allchain-sign/keystore-secp256k1.json (secp256k1)
  已创建: /Users/wangbinmac/.allchain-sign/keystore-ed25519.json (ed25519)
  新建 2 个 / 复用 0 个：新建的那条是全新私钥，它对应链上的地址与以往任何一次启动都不同。

本 keystore 在各链上的地址：
  eth   0x...
  btc   bc1q...
  sol   ...
  near  ed25519:...
  apt   0x...
  sui   0x...
  ton   0x...
```

### 私钥只创建一次，之后永远复用

两个 keystore 文件**都在**时，启动只是解开它们，**不会**重新生成私钥。日志会明确写出：

```
keystore 目录: /Users/wangbinmac/.allchain-sign
口令来源: 终端输入
  已解锁: /Users/wangbinmac/.allchain-sign/keystore-secp256k1.json (secp256k1)
  已解锁: /Users/wangbinmac/.allchain-sign/keystore-ed25519.json (ed25519)
  复用已有私钥，未重新生成：各链地址与上次启动一致。
```

判定标准是**文件字节一字未变**（而不是「地址相同」）：keystore 的 salt 与 nonce
每次加密都随机，只要真走过一次「生成新私钥并写盘」，字节必然改变。

| 目录里有什么 | 启动做什么 | 日志关键字 |
|---|---|---|
| 两个文件都在 | 解开两个，**不新建任何私钥** | `复用已有私钥，未重新生成` |
| 只有一个 | 解开已有的，补建缺失的那个 | `⚠️ 只找到一个 keystore 文件` |
| 都没有 | 新建两个（设新口令，需二次确认） | `首次运行` |
| 有但口令错 | 报错退出，**绝不重建** | `口令错误`（最多 3 次） |

> **只找到一个文件时请先停一下**：补齐的那条是一把**全新私钥**，
> 与它对应链上（eth 或 ed25519 那五条链）以往的任何地址都无关。
> 如果是误删，先从备份恢复文件再启动——否则那些地址里的资产将无人控制。

| 参数 | 默认 | 说明 |
|---|---|---|
| `--host` | `127.0.0.1` | 监听地址，建议保持回环 |
| `--port` | `7878` | 监听端口 |
| `--keystore-dir` | `~/.allchain-sign` | keystore 目录。**换目录等于换一套密钥**，别随手改 |

口令输错最多重试 3 次；第 4 次直接退出（不给本机进程无限的离线试口令机会）。

### 无终端环境（systemd / nohup / CI）

没有 TTY 时无法交互输入，改用环境变量（程序会自动识别）：

```bash
export SIGN_PASSWORD='你的口令'
./target/release/sign
```

> 注意：Linux 上同一用户的其它进程可经 `/proc/<pid>/environ` 读到环境变量，
> 所以这只适用于「机器本身可信」的场景。

> 工具链已由本目录的 `rust-toolchain.toml` 钉为 `1.93.0`，**无需**再加 `+1.93.0`。
> 该文件必要：`rust-toolchain.toml` 只从 CWD 向上查找，本 crate 在 `allchain-rust-sdk` 之外，
> 读不到 SDK 那份，否则会回落到系统默认工具链。

---

## 2. keystore 文件格式

`~/.allchain-sign/keystore-<curve>.json`，明文 JSON，**不含私钥**：

```json
{
  "version": 1,
  "scheme": "secp256k1",
  "kdf": { "name": "argon2id", "salt": "<b64>", "m_cost": 19456, "t_cost": 2, "p_cost": 1, "output_len": 64 },
  "cipher": { "name": "aes-256-gcm", "nonce": "<b64>" },
  "verifier": "<b64>",
  "ciphertext": "<b64，密文 ‖ GCM tag>"
}
```

派生链路：`Argon2id(口令, salt) → 64 字节主密钥` → 前 32 字节作 AES-256-GCM 密钥，
后 32 字节算 `verifier`。文件权限 `0600`。

**为什么要 `verifier`**：AES-GCM 自身已能认证，但认证失败无法区分「口令错」还是
「文件被改坏」——两者的处置方式完全相反（重试 vs 恢复备份）。`verifier` 只依赖
「口令 + 盐 + KDF 参数」、**刻意不绑定密文**，于是：

| 现象 | 判定 | 处置 |
|---|---|---|
| `verifier` 不匹配 | 口令错 | 重试（文件是好的） |
| `verifier` 通过、GCM 失败 | 文件被改坏 | 恢复备份，重试无意义 |
| 文件读不出 / 字段缺失 | 环境问题 | 检查路径与权限 |

`version` 与 `scheme` 还作为 **AAD** 参与 AEAD 认证：把 `"scheme": "ed25519"` 改成
`"secp256k1"` 会导致解密失败，而不是「解密成功但把种子按错误曲线解释」——
后者不会报错，只会签出永远无效的交易。

---

## 3. 端点

所有响应复用 `allchain-core` 的统一信封 `Envelope<T>`（`{chain, network, took_ms, data/error, code}`），与 `acli` 的 CLI / HTTP / MCP 三形态保持一致。

### 3.1 `POST /v1/signtx`

请求体：

```json
{
  "chaintype": "btc",
  "txdatahex": "0x<完整交易序列化后的字节，hex 可带 0x 前缀>",
  "fromaddress": "<GET /v1/chains 返回的地址>",
  "context": { ... }
}
```

`context`：**只有 BTC 需要**，其余链必须省略（传了会报错，不静默忽略）。
内容是把 SDK `build_transfer` 下发的 `extra.submit_context` **原样**搬过来，见 [§4.1](#41-btc-的两个特殊之处)。

行为：

1. 按 `chaintype` 分派到对应链的函数，**`txdatahex` 以 hex 字符串原样传进去**
   （不在 HTTP 层统一解码，理由见下）；
2. 按 `fromaddress` 从内存库取种子（不在库中 → `InvalidArgument`）；
3. 各链函数自己把 hex 解成字节，再按链重建签名器、对完整交易签名；
4. 多签名链（BTC）逐输入签名；其余链把签名装配回交易；
5. 返回 `signature` / `signatures` 与 `signed_tx`。

> **为什么不在 HTTP 层统一 hex 解码**
> 解码失败时，各链能说出「这段字节本该是什么」——
> `BTC 未签名交易（序列化的未签名交易）的 hex 解码失败…`、
> `SOL 完整交易（bincode Transaction）的 hex 解码失败…`。
> 统一解码后再传字节下去，只能得到一句链无关的「hex 解码失败」，
> 定位成本立刻高一个数量级。代价是每个链函数多一行 `decode_txdata`，可接受。
>
> 三种输入形态都被接受：`0x` 前缀 / `0X` 前缀 / 无前缀，首尾空白会先 `trim`。
> 出参一律是 `0x` + hex（签名、公钥、`signed_tx` 都是）。

> `fromaddress` 必须是**本 keystore 派生的地址**（启动时日志已列出，或 `GET /v1/chains` 查询）。
> 内存库在启动时已预热好全部 7 条链的地址，直接用 `/v1/chains` 列出的地址即可。

成功响应 `data`：

```json
{
  "chain": "eth",
  "from_address": "0x...",
  "scheme": "ed25519",
  "signature": "0x<签名字节>",
  "signatures": ["0x<签名字节>"],
  "signature_count": 1,
  "signed_tx": "0x<完整签名交易，可直接广播>",
  "encoding": "hex",
  "note": null
}
```

- `signature`：第一个签名（单签名链即全部）。
- `signatures`：**全部**签名，顺序按各链定义（BTC 为「按输入下标」）。
  单签名链只有一项。留两个字段是为了让调用方既能统一遍历，又不必为单签名场景多解一层。
- `encoding`：`hex` 或 `base64`（见下表）。
- `signed_tx`：TON 与 BTC 为 `null`（**只出签名，不组装**）。
  TON 的完整 external message 需钱包 code/state-init；
  BTC 按用户约定的分工，由 SDK 的 `submit_tx` 组装。

### 3.2 `GET /v1/chains`

返回能力清单。每条链包含 `scheme`、`address`、`public_key`、`signed_tx_encoding`、
`assembles_full_tx`、`needs_context`。

| 字段 | 含义 |
|---|---|
| `public_key` | 该链所用编码的公钥 hex（btc 为**压缩** 33 字节；eth 为**非压缩** 65 字节） |
| `assembles_full_tx` | 本服务是否直接产出可广播交易。TON、BTC、ICP 为 `false` |
| `needs_context` | 签名时是否必须带 `context`。只有 BTC 为 `true` |

集成方可以据此判断流程：拿到 `needs_context: true` 的链，就得把
`build_transfer` 的 `extra.submit_context` 一起带过来。

### 3.3 `GET /v1/keystore`

返回 keystore 目录、两个文件的路径与是否存在。只报存在性，不报内容。

### 3.4 `GET /`

简短服务说明。

---

## 4. 各链 `txdatahex` 契约（完整交易的序列化格式）

**统一契约**：`txdatahex` 恒为**完整交易序列化后的 hex**（可带 `0x` 前缀）。

这里「完整」指**结构完整、只差签名**：nonce / gas / fee / 接收方 / 金额 / 指令等字段都已填好并参与了序列化，
由调用方（实际是 allchain SDK 的 `build_transfer`）产出。

两个必须排掉的误解：

- **不是**单独一个待签哈希——收到的是交易本体，不是 `sha256(tx)` 之类的摘要；
  内部要不要先哈希是各链自己的事，与输入形态无关。
- **不是**部分字段——`signtx` 不拼字段、不补 nonce、不算 fee。

`signtx` 只做两件事：**签名** + **把签名装配回交易**；构造出那笔完整交易是调用方的责任。

| 链 | `txdatahex` = 完整交易的序列化字节 | 解析方式 | `signed_tx` 编码 | 组装产物 |
|----|--------------------------------------|----------|------------------|----------|
| `btc` | **未签名交易**的序列化字节（`unsigned_tx_hex`），SegWit 版本 + 输入（空 witness）+ 输出 | `bitcoin::consensus::encode::deserialize` | —（只出签名） | 由 **SDK 的 `submit_tx`** 组装 |
| `eth` | EIP-2718 类型化交易（**无签名段**）的 RLP：`0x02` ‖ RLP(\[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList\]) | `alloy::consensus::TypedTransaction::decode_unsigned` | hex | **裸** `EthereumTxEnvelope`（EIP-2718）可直接 `eth_sendRawTransaction` |
| `sol` | `solana_sdk::transaction::Transaction` 的 **bincode** 字节（签名槽留空） | `bincode::deserialize` | base64 | 填好 `signatures[0]` 的 `Transaction` 可直接 `sendTransaction` |
| `near` | `near_primitives::transaction::Transaction` 的 **Borsh** 字节（签名 = None） | `borsh::BorshDeserialize::try_from_slice` | hex | `SignedTransaction`（Borsh）可直接 `broadcast_tx_commit` |
| `apt` | `aptos_sdk::transaction::types::RawTransaction` 的 **BCS** 字节 | `bcs::from_bytes` | hex | `SignedTransaction`（BCS）可直接 `submit` |
| `sui` | `sui_sdk_types::Transaction` 的 **BCS** 字节 | `bcs::from_bytes` | base64 | `SignedTransaction`（BCS）可直接 `sui_executeTransactionBlock` |
| `ton` | external message 的**完整序列化字节** | 直接 `sk.sign(txdata)`（内部不额外哈希） | —（返回 `signature`，`signed_tx=null`） | 仅 ed25519 签名；完整 cell 需钱包 code/state-init |

> **ETH 的 `signed_tx` 必须是「裸」的 EIP-2718 字节**
> 正确写法是 `envelope.encoded_2718()`，**不能**用 `alloy::rlp::encode(&envelope)`。
> 后者会在 2718 字节外面**再套一层 RLP 字符串头**：实测产出 `0xb87502f872…`，
> 头两字节 `b8 75` 是「长字符串，117 字节」的 RLP 头。
> 节点期望的是以类型字节开头（`02` = EIP-1559）的裸交易，
> 收到多一层封装的字节会直接拒绝。
>
> 这个缺陷属于**最贵的一类**：本地签名、验签、序列化全都正常，
> 只有广播时才失败，而节点返回的错误通常语焉不详。
> 它曾在 62 项全绿的测试里藏了很久——因为本文件当时只有**解码**测试，
> 没有任何一条断言过**签名产出的字节长什么样**。
> 现在由 `signed_tx_is_a_bare_eip2718_envelope` 钉住（并配了变异测试验证它真会红）。

> **各链的「待签字节」≠「交易字节」**（这张表是三个真实缺陷换来的）
>
> 除 BTC 外，每条链在签名前都会把交易字节**再变换一次**，节点验签时验的是变换后的结果。
> 写错时**本地签名与验签全部正常**，只有节点会拒——和上面 ETH 那类缺陷一样贵。
>
> | 链 | 待签字节 | 判据来源 |
> |----|----------|----------|
> | `apt` | `sha3_256("APTOS::RawTransaction")` ‖ `BCS(RawTransaction)` —— 多出 **32 字节域分离盐** | `aptos-sdk-0.4.1/src/transaction/types.rs` 的 `signing_message()` |
> | `near` | `sha256(borsh(Transaction))` —— 32 字节**哈希**，不是 Borsh 字节本身 | 节点侧 `ValidatedTransaction::new` 调 `signature.verify(tx.get_hash(), …)` |
> | `sui` | `[0,0,0]`（intent：scope / version / app_id）‖ `BCS(Transaction)` | `sui-sdk-types-0.0.7/src/hash.rs` 的 `Transaction::signing_digest()` |
> | `sol` | `Message::serialize()` —— 只签 message，不含签名段 | 官方 `Transaction::try_partial_sign` 内部的 `message_data()` |
> | `eth` | `keccak256(0x02 ‖ RLP(...))`，由 alloy 签名器算 | EIP-2718 / EIP-1559 |
> | `btc` | 每个输入各自的 sighash（**P2WPKH 走 BIP143，含金额**） | BIP143，见 §4.1 |
> | `ton` | 收到的**原始字节**，内部**不**额外哈希 | 刻意与其余各链统一口径 |
>
> 实现上守三条纪律：
>
> 1. **直接调官方函数**（APT 的 `signing_message()`、NEAR 的 `get_hash_and_size()`），
>    不按公式自己拼一遍——自己拼等于自证，官方哪天改口径也发现不了。
> 2. **期望值必须来自另一个代码库**：官方 SDK、dalek 验签、或节点侧的验签代码。
> 3. 每条都配一条**反证测试**（证明「不这么做就会验签失败」），
>    否则断言可能恒真——比如「intent 是三个 0」若不为真，那条测试就是空的。

> **地址格式（各链 `fromaddress` 的取值）**
> - `eth`：`0x` + 40 hex（小写）＝ `keccak256(非压缩公钥[1:])[12:]`
> - `btc`：`bc1q…` ＝ bech32(`bc`, `[0] ‖ convertbits(ripemd160(sha256(压缩公钥)), 8, 5)`)，**主网 P2WPKH**
> - `apt` ：`0x` + 64 hex ＝ `sha3-256(公钥 ‖ 0x00)`
> - `sui` ：`0x` + 64 hex ＝ `blake2b-256(0x00 ‖ 公钥)`
> - `sol` ：base58 公钥
> - `near`：`ed25519:<base58>`
> - `ton` ：`0x` + 64 hex（原始 ed25519 公钥；真实地址需钱包合约）
>
> Aptos 与 Sui 极易写反：**哈希不同，标志字节的位置也相反**。两者都用真实向量钉住了测试。

### 4.1 BTC 的两个特殊之处

#### 1) N 个输入 → N 个签名

BTC 是 UTXO 模型，一笔交易的每个输入都要各签一次：N 个输入 → N 个 sighash → N 个签名，
按索引与 `tx.input` 一一对应。**改动任何一个输入，其它所有输入的签名全部作废**。

#### 2) 只支持 P2WPKH，因此必须带 `context`

同一个公钥在 BTC 上能派生两类地址，对应两套**互不相通**的签名规则：

| 类型 | 地址 | 锁定脚本 | 签名落在 | sighash 算法 | 需要输入金额 |
|---|---|---|---|---|---|
| **P2WPKH** | `bc1q…` | `OP_0 <h160>` | `witness` | **BIP143** | **需要** |
| P2PKH | `1…` | `OP_DUP OP_HASH160 <h160> … OP_CHECKSIG` | `scriptSig` | 传统算法 | 不需要 |

P2WPKH（2017 年 SegWit）是当前主流：见证数据享 75% 权重折扣，手续费比 P2PKH 低三到四成；
签名挪出 txid 的计算范围，顺带修掉了交易延展性。主流钱包的默认接收地址都是 `bc1q…`。

代价是 BIP143 的定义要求把**本输入的金额**混进摘要——这正是它比传统算法更安全的地方
（堵住「硬件钱包被隐瞒真实输入金额 → 少找零」的攻击）。
但金额**不在交易字节里**（`TxIn` 只有 `txid ‖ vout ‖ sequence`），
所以必须由 `context` 提供。这就是 BTC 成为唯一需要额外入参那条链的原因。

**P2PKH 输入会被明确拒绝**：`context` 里的 `script_type` 字段给出了明确信号，不需要靠猜。
传统算法虽然不要金额、只凭 `txdatahex` 就能签，但同时支持两套会把「地址类型必须与
签名算法配套」这条约束变成调用方的心智负担——宁可只支持一种、并把另一种拒绝得清清楚楚。

```json
{
  "network": "mainnet",
  "public_key": "02…（压缩，33 字节 hex）",
  "inputs": [
    { "txid": "…", "vout": 0, "value": 100000, "script_pubkey": "0014…", "script_type": "p2wpkh" }
  ],
  "outputs": [{ "value": 120000, "script_pubkey": "0014…" }],
  "unsigned_tx_hex": "02000000…"
}
```

**签名前会过四道校验**，任何一道不过就直接拒绝，绝不「带病签名」：

| # | 校验 | 挡住的事故 |
|---|---|---|
| 1 | `network == "mainnet"` | 跨网签名（地址前缀不同，签名最终无效） |
| 2 | `txdatahex` 重新序列化后 == `context.unsigned_tx_hex` | **金额来自 A 交易、结构来自 B 交易** → 签在另一笔交易上 |
| 3 | `context.public_key` == 本 keystore 派生的公钥 | 钥匙与交易不是一套，SDK 侧必然验签失败 |
| 4 | 每个输入的 `script_type == "p2wpkh"`，且 `witness` 为空 | P2PKH 等遗留类型；以及传入的不是未签名模板 |

> **为什么自己重算 sighash，而不是直接用 `signing_payloads[].sighash`**
> SDK 已经把每个 sighash 算好放在 `extra.signing_payloads` 里了，直接拿去签最省事。
> 但那样是**盲信**：一旦上下文与交易字节不匹配（例如调用方混用了两次 `build_transfer` 的产物），
> 签名器会老老实实地对一笔它从未见过的摘要签出**完全有效**的签名——格式合法、能过本地验签，
> 只有广播到全网时才会被拒，而报错（`non-mandatory-script-verify-flag`）不会告诉你哪里错了。
> 这里改为**从 `txdatahex` + `context` 重算**，把「盲信」变成「先验再用」。

**产出**：每个输入一个 **64 字节紧凑签名** `r(32) ‖ s(32)`（**不是 DER**）。
DER 长度可变（70–73 字节），两种都收就得靠长度猜，容易出错，所以只认定长。

**分工**：本服务**只签名**。DER 编码、低 S 归一化（BIP62）、填见证、
逐输入验签并拼装，全部由 SDK 完成。

---

## 5. 调用示例（curl）

```bash
# 0) 先在终端启动（会问口令）；无终端时用 SIGN_PASSWORD 环境变量
export SIGN_PASSWORD='至少8位的口令'
./target/release/sign &

# 1) 查看本 keystore 在各链上的地址
curl "http://127.0.0.1:7878/v1/chains"

# 2) 对一条完整 SOL 交易签名（txdatahex 换成真实 bincode 字节的 hex；fromaddress 用上一步 /v1/chains 列出的地址）
curl -X POST "http://127.0.0.1:7878/v1/signtx" \
  -H 'Content-Type: application/json' \
  -d '{"chaintype":"sol","txdatahex":"0x...","fromaddress":"<上一步的 address>"}'
# => {"data":{"signature":"0x...","signed_tx":"<base64 完整交易>","encoding":"base64",...}}

# 3) BTC：必须带 context，且只返回签名（交易由 SDK 组装）
#    下面三个值都来自 SDK `build_transfer` 的响应：
#      txdatahex          <- data.unsigned_tx_hex
#      context            <- data.extra.submit_context（原样搬过来）
#      fromaddress        <- data.from（或 /v1/chains 里的 btc 地址，形如 bc1q...）
curl -X POST "http://127.0.0.1:7878/v1/signtx" \
  -H 'Content-Type: application/json' \
  -d '{"chaintype":"btc","txdatahex":"02000000...","fromaddress":"bc1q...","context":{"network":"mainnet","public_key":"02...","inputs":[...],"outputs":[...],"unsigned_tx_hex":"02000000..."}}'
# => {"data":{"signature":"0x<64B>","signatures":["0x<64B>","0x<64B>"],"signature_count":2,"signed_tx":null,...}}
#    随后把 signatures 与同一个 submit_context 交给 SDK 的 submit_tx。
```

> **幂等性**：重启服务、用同一口令解锁，`/v1/chains` 返回的地址**与上次完全相同**。
> 这是刻意保证的——若每次启动都重新生成，用户上次收到的地址会永久失联。
> 进程级验证见 [`scripts/verify-keystore-reuse.sh`](scripts/README.md)：
> 它比对两次启动之间 keystore 文件的**字节与 mtime**（不是只比地址）。

---

## 6. 开发验证

```bash
cargo test                              # 加解密原语、地址派生、open_or_fill 返回值
cargo clippy --all-targets              # 要求零警告
scripts/verify-keystore-reuse.sh        # 进程级：keystore 存在时不重建私钥
scripts/verify-partial-refill.sh        # 进程级：只存在一个文件时的补齐行为
```

后两个是真的把服务起起来、看磁盘上发生了什么，与 `cargo test` 不重复——
详见 [`scripts/README.md`](scripts/README.md)。

---

## 7. 安全模型

- **口令即唯一防线**：keystore 文件可被拷走离线暴破，所以口令强度直接等于私钥强度。
  用 Argon2id（`m=19MiB, t=2, p=1`），并强制最少 8 字符。
- **口令无法找回**：没有后门、没有助记词、没有找回流程。忘了就是永久失去这两个私钥。
- **磁盘无明文**：私钥只以 AES-256-GCM 密文形式存在；文件权限 `0600`。
- **无鉴权 + 回环**：仅绑定 `127.0.0.1`，不可对外暴露；任何能访问该端口的本地进程都能取私钥与签名。
- **口令不落日志**：启动日志只打印「来源（终端/环境变量）」与「已创建/已解锁」，绝不打印口令与私钥；
  `Vault` 的 `Debug` 实现也刻意屏蔽了种子内容。
- **任何持有种子的结构都要手写 `Debug`**：判据是「里面有没有不能外泄的字节」，
  而不是「这个结构平时会不会被打印」。`Vault` 与进程内传递的 `StoredKey` 都手写
  了只打印长度的 `Debug`——默认的 `derive(Debug)` 会把 32 字节种子原样打出来，
  将来只要有一行 `println!("{:?}", key)` 或一次 panic 回溯捎上它，私钥就进了日志。
  两者都有测试钉住（`store::tests::debug_never_leaks_the_seed` 同时查 hex 与十进制两种形态，
  因为 `derive` 打印 `[u8; 32]` 用的是十进制，只查 hex 会漏）。
- **重试上限 3 次**：不给本机进程无限的离线试口令机会。
- **延后链**：`ckb` / `fil`（secp256k1，需 UTXO / 地址脚本语义）与 `ar`（RSA）尚未实现，调用返回 `Unsupported`。
- **环境变量口令的代价**：Linux 下同一用户可经 `/proc/<pid>/environ` 读到，仅适用于机器本身可信的场景。

### 备份

要备份的是**两个 keystore 文件 + 口令**，缺一不可：

```bash
cp ~/.allchain-sign/keystore-*.json /path/to/safe/backup/
```

---

## 8. 测试

```bash
cd /Users/wangbinmac/Documents/allchainsdk/sign
cargo test          # 113 项
cargo clippy --all-targets
```

测试覆盖分五类：

**① 外部真值对拍**（期望值来自独立实现，非本实现自产）

| 项目 | 对拍对象 |
|---|---|
| Argon2id 派生 | Python `argon2-cffi`（官方 C 参考实现 libargon2） |
| AES-256-GCM | Python `cryptography`（OpenSSL 后端） |
| blake2b 校验值 | Python `hashlib` |
| ETH 地址 | secp256k1 私钥 = 1 的公开常量 |
| APT / SUI / SOL / NEAR 地址 | `aptos init` 的真实输出（私钥→公钥→地址三元组） |
| BTC 地址（P2WPKH） | Python 独立实现：`cryptography` 做点乘 + `hashlib` 的 sha256/ripemd160 + **手写** BIP173 bech32 |
| BTC sighash（BIP143） | 官方 **BIP143 测试向量**（`c37af311…`，独立公开常量） |

> 这些向量由 `/tmp/gen_vectors.py` 与独立 Python 脚本算出。
> **别用本实现自己算的值当期望值**——那叫自证，实现错了测试也跟着错，永远绿。

**② 行为保证**

keystore 幂等（同口令二次打开解出同种��）、口令错不改动文件、密文篡改报 `Corrupt` 而非
`WrongPassword`、AAD 绑定 `scheme`、两文件盐/nonce 独立、文件权限 0600、磁盘无明文种子、
`Debug` 不泄露私钥、secp256k1 种子是合法标量、部分缺失时只补缺的那个。

**③ 跨 crate 端到端对拍**（BTC，一次性验证，未固化为测试）

sign 产出的两个紧凑签名被直接喂进 SDK 的 `assemble_signed`——该函数会**逐输入验签**
再填见证并拼装。实测通过，产出完整可广播交易：

```
txid 878edc8a6b54b54851e245208c18f5a281241e705fe14563bd590c7608bc57c8
```

这一步的意义在于它证明了**两侧 `bitcoin` crate 版本一致**：sighash 是签名的输入，
一旦两侧版本漂移，本地签名与验签全都正常，只有节点会拒——是广播前不会报任何错的那类缺陷。
（夹具与签名用临时测试导出后即删除；两个 crate 互不依赖，无法做成常驻测试。）

**④ 「连线」本身：分派层与进程内密钥库**（`src/sign.rs` / `src/store.rs`）

这两个文件此前**测试数为 0**——和 APT / NEAR 那两个缺陷能活下来是同一个原因：
各链的测试都是**直接调** `sign_near` / `sign_sol` 的，分派表错位在本地永远全绿。

分派表的错位在类型上完全合法（两边都是 `anyhow::Result<SignedResult>`），编译器不会吭声，
所以每条链都要有**能证伪**的判据：

| 判据 | 能排除什么 |
|---|---|
| ETH 真实向量产出 **65 字节可恢复签名**（130 位 hex） | 被误接到任一 ed25519 链（那些只会产出 128 位） |
| TON 对任意字节都签名、`signed_tx` 恒 `None` | `ton` 被接到任何别的链（那些会拒绝垃圾字节） |
| sol / near / apt / sui **必须拒绝**两个任意字节 | 任何一条被误接到 `ton`（它来者不拒） |

密钥库一侧钉住的是：`StoredKey` 的 `Debug` 不含种子（hex 与十进制两种形态都查）、
`Scheme::as_str()` 与磁盘 serde 拼写一致（两者漂移会导致能写入但读不回来）、
`Scheme::ALL` 的装载顺序、`get` 返回副本、同地址覆盖。

**⑤ 变异测试**（`cargo test` 之外单跑）

```bash
python /tmp/mutate_sign_vault.py     # keystore / 地址部分，25 个变异体
python /tmp/mutate_btc.py            # BTC 部分，8 个变异体
python /tmp/mutate_hex_input.py      # hex 入参层，4 个变异体
python /tmp/mutate_signing_message.py    # 各链「待签字节」，8 个变异体
python /tmp/mutate_dispatch_store.py     # 分派层 + 进程内密钥库，13 个变异体
```

逐个把实现改坏，确认测试**会红**。四个脚本都已加**基线预检**——先确认目标测试在
干净状态下是绿的，否则「变异后变红」可能只是它本来就在红，会被误判成已捕获。

> **变异脚本自身的两个陷阱（都踩过，各浪费一轮）**
>
> 1. **还原时必须刷新 mtime**。`shutil.copy` / `shutil.move` 走 `copy2`，会连 mtime 一起保留；
>    于是还原后的文件与「编译变异版时的文件」时间戳相同，cargo 认为没变过、**不重新编译**，
>    继续跑变异版的二进制。后果是后续判定全被上一个变异体污染，且脚本跑完后
>    手工 `cargo test` 会莫名发红。现在统一走 `copyfile` + `os.utime(path, None)`。
> 2. **编译失败 ≠ 测试变红**。两者 returncode 都非 0，混为一谈会把「变异体写错了」
>    误报成「测试抓住了缺陷」。现在四个脚本都把 `error[E` / `could not compile`
>    单独判成「无效变异」，不计入杀死数。

vault 部分 25 个变异体（换 KDF 算法、改盐、去 AAD、把 `0600` 改成 `0644`、
把「已存在就解开」改成「重新生成」、丢掉 Aptos 的 `0x00`、挪动 Sui 的标志字节……），
当前 **24/25 被杀死**，唯一存活的是已登记的等价变异体
（`ct_eq` 换成 `==`——返回值恒等，只改时序特性，黑盒不可观测）。

BTC 部分 3 个变异体（改为「只支持 P2WPKH」后重新实测），**3/3 被杀死**：

| 变异 | 被哪条测试杀死 |
|---|---|
| 去掉「只接受 `p2wpkh`」校验 | `a_p2pkh_input_is_rejected` / `an_unknown_script_type_is_rejected` |
| 把输入金额恒置为 0（不参与哈希） | `signatures_verify_against_the_independently_computed_sighash` |
| `SIGHASH_ALL` 改成 `SIGHASH_NONE` | `changing_an_input_value_invalidates_that_inputs_signature` |

> 第二个变异同时红了「改输入金额后签名应作废」那条，这条测试还钉住一个
> 容易搞反的细节：**金额只进入本输入那一条 sighash**。
> BIP143 的 `hashPrevouts` / `hashSequence` 只覆盖各输入的 outpoint 与 sequence，
> 不含金额——所以改第 1 个输入的金额，第 0 个输入的 sighash 不变。

hex 入参层 4 个变异体，**4/4 被杀死**：去掉 `strip_0x`+`trim`、只去掉 `trim`、
只去掉 `strip_0x`、以及把解码错误吞掉改成返回空字节。

**各链「待签字节」8 个变异体，8/8 被杀死**——这一组里三条就是真实缺陷本身：

| 变异 | 被哪条测试杀死 |
|---|---|
| APT 漏掉 `sha3_256("APTOS::RawTransaction")` 盐前缀（**原始缺陷**） | `signature_verifies_against_the_official_signing_message` |
| NEAR 签裸 borsh 字节而不是 sha256 摘要（**原始缺陷**） | `signed_tx_passes_the_nodes_own_signature_check` |
| SUI 丢掉 3 字节 intent 前缀 | `signature_verifies_against_the_intent_prefixed_message` |
| SUI 的 `UserSignature` 把公钥放到签名前面 | `user_signature_is_flag_then_signature_then_pubkey` |
| SOL 签整个 tx 的 bincode 而不是 message 线格式 | `sign_sol_fills_slot_zero_and_verifies` |
| SOL 把签名追加到末尾而不是填进槽 0 | `sign_sol_fills_slot_zero_and_verifies` |
| TON 好心加一步 sha256（节点验的是原文） | `signs_the_raw_bytes_without_an_extra_hash` |
| ETH 的 `signed_tx` 多套一层 RLP（**原始缺陷**） | `signed_tx_is_a_bare_eip2718_envelope` |

分派层 + 密钥库 13 个变异体，**13/13 被杀死**：把 `eth` 接到 `ton`、把 `ton` 接到 `sol`、
把 `sol` 接到 `ton`、BTC 不再需要 `context`、非 BTC 链的 `context` 被静默忽略、
`strip_0x` 只认小写 `0x`、`decode_txdata` 去掉 `trim`、剥前缀与 `trim` 顺序颠倒、
报错丢掉调用方传入的形状描述、`StoredKey` 的 `Debug` 把种子原样打出、
`Scheme::as_str` 与磁盘拼写漂移、`Scheme::ALL` 顺序调换、`insert` 不再覆盖同地址旧值。

> 这套流程抓出过七个真实盲区：Aptos 丢掉 `0x00` 后缀、Sui 标志字节挪位置
> （在「两个地址不相等」那种弱断言下都**存活**了，是真实向量把它们抓住的），
> 以及 BTC 的 `recomputed_sighashes_match_the_sdk_output` —— 该测试在测试代码里
> **重算**了一遍哈希，所以把 `sign_btc` 的脚本类型分派改坏时它**仍然是绿的**。
> 它的教训被固化了下来：现在的 `signatures_verify_against_the_independently_computed_sighash`
> 用**外部真值公钥常量**验签，sighash 也由测试自己算，
> 而不是复述生产代码的派生逻辑——「生产怎么写、测试就怎么抄」正是那次盲区的根因。
> 此外 BIP143 的 sighash 直接对拍**官方向量**常量，不依赖本工程任何一行代码。
>
> 第四个盲区是另一种形态：ETH 的 `signed_tx` 多套了一层 RLP（`0xb87502f872…`），
> 它能藏在 62 项全绿里，是因为当时 eth.rs **只有解码测试、没有任何一条断言过产出**。
> 教训是通用的：**只测输入解析不测输出形态，等于没测**。
> 这条缺陷最后是靠活体冒烟里一句 `starts_with("0x02")` 抓出来的。
>
> 顺着这条教训把其余六链的「待签字节」也审了一遍，又抓到两个**同等级的**缺陷：
>
> - **APT**：漏掉了 32 字节的 `sha3_256("APTOS::RawTransaction")` 域分离盐，签的是裸 BCS。
>   本地验签、序列化全绿，只有节点会拒。
> - **NEAR**：签的是 `borsh(tx)` 而不是 `sha256(borsh(tx))`。节点验签用的是
>   `tx.get_hash()`，于是结果恒为 `InvalidSignature`。
>
> 两者此前**一条直接测试都没有**（`near` / `apt` / `sui` / `ton` 四个文件的测试数是 0），
> 这也是它们能一直留到现在的原因。现在每个文件都有了端到端验签 + 反证测试。
>
> 最后一个盲区是**分布性的**：查一遍「每个文件各有多少条测试」，发现
> `sign.rs`（七条链的分派表）与 `store.rs`（进程内密钥库）**都是 0**。
> 分派表错位在类型上完全合法（两边都返回 `anyhow::Result<SignedResult>`），
> 编译器不会吭声；而各链的测试都是**直接调** `sign_xxx` 的，
> 于是「连线」本身从头到尾没被任何人断言过。
>
> 同一轮还修掉一个潜伏问题：`StoredKey` 持有 32 字节种子却用了 `derive(Debug)`，
> 与 `Vault` 的手写打码口径不一致（见 §7）。目前没人打印它，所以现在改代价最小。
>
> 倒数第二个盲区最隐蔽：**变异测试的结论本身也可能是假的**。
> 上面那两个脚本陷阱（mtime 不刷新、编译失败当杀死）都会让「8/8 全绿」变成假象，
> 而且方向是**偏向乐观**——这正是最危险的方向。
> 结论可信的前提是：基线预检通过 + 每个变异体确实编译过。
