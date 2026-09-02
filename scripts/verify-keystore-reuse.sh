#!/usr/bin/env bash
#
# 验证：keystore 两个文件都在时，启动只是解开它们，**不会重新生成私钥**。
#
# 判定为什么用「文件字节」而不是「地址相同」：
#   keystore 的 salt 与 nonce 每次加密都是随机的，所以只要真的走过一次
#   「生成新种子 → 加密 → 写盘」，文件字节必然改变。
#   反过来说，**字节一字未变 ⟺ 一次加密都没发生过**。
#   而「地址相同」证明不了这一点——把旧种子重新加密一遍，地址照样相同。
#
# 用法：
#   scripts/verify-keystore-reuse.sh              # 自动找 target/release/sign
#   scripts/verify-keystore-reuse.sh path/to/sign # 或显式指定
#
# 退出码：0 = 全部通过；1 = 有断言失败。
#
set -uo pipefail

# 解析 sign 二进制路径：优先用参数，其次按本脚本位置推 target/release/sign。
SIGN="${1:-}"
if [ -z "$SIGN" ]; then
  HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  SIGN="$HERE/../target/release/sign"
fi
if [ ! -x "$SIGN" ]; then
  echo "找不到可执行的 sign 二进制: $SIGN" >&2
  echo "先跑 cargo build --release，或用参数指定路径。" >&2
  exit 1
fi

DIR="$(mktemp -d "${TMPDIR:-/tmp}/sign-verify-reuse-XXXXXX")"
PORT=17897
PW='verify-only-password-1234'
fail=0

# 退出时清理临时目录与残留进程。
cleanup() { rm -rf "$DIR"; }
trap cleanup EXIT

# 起一次服务，等它解锁并监听，然后杀掉。
# 不能一启动就杀：解锁（Argon2id）要花几百毫秒，杀早了日志里什么都没有。
run_once() {
  local log="$1"
  SIGN_PASSWORD="$PW" "$SIGN" --keystore-dir "$DIR" --port "$PORT" >"$log" 2>&1 &
  local pid=$!
  local i
  for ((i = 0; i < 120; i++)); do
    grep -q "listening on" "$log" 2>/dev/null && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
}

check() {
  if [ "$1" = "0" ]; then
    echo "  ✅ $2"
  else
    echo "  ❌ $2"
    fail=1
  fi
}

echo "sign 二进制: $SIGN"
echo "临时目录:   $DIR"
echo

echo "── 第 1 次启动（全新，应创建两个文件）"
run_once "$DIR/run1.log"
sed -n '1,20p' "$DIR/run1.log"
echo

if [ ! -f "$DIR/keystore-secp256k1.json" ] || [ ! -f "$DIR/keystore-ed25519.json" ]; then
  echo "❌ 第 1 次启动没有创建出两个 keystore 文件"
  exit 1
fi

# 记录「之前」的指纹：内容哈希 + mtime。
# 两个都要比：哈希看内容，mtime 看有没有被重写过（哪怕重写成了同样的字节）。
HASH1="$(shasum -a 256 "$DIR/keystore-secp256k1.json" "$DIR/keystore-ed25519.json" | awk '{print $1}' | tr '\n' ' ')"
MTIME1="$(stat -f '%m' "$DIR/keystore-secp256k1.json" "$DIR/keystore-ed25519.json" | tr '\n' ' ')"

echo "── 第 2 次启动（两个文件都在，应只解锁不重建）"
run_once "$DIR/run2.log"
sed -n '1,20p' "$DIR/run2.log"
echo

HASH2="$(shasum -a 256 "$DIR/keystore-secp256k1.json" "$DIR/keystore-ed25519.json" | awk '{print $1}' | tr '\n' ' ')"
MTIME2="$(stat -f '%m' "$DIR/keystore-secp256k1.json" "$DIR/keystore-ed25519.json" | tr '\n' ' ')"

echo "── 断言"
[ "$HASH1" = "$HASH2" ]; check $? "两个 keystore 文件的字节完全未变"
[ "$MTIME1" = "$MTIME2" ]; check $? "两个 keystore 文件未被重写（mtime 未变）"
grep -q "已创建" "$DIR/run2.log"; [ $? -ne 0 ]; check $? "第 2 次启动日志里没有出现「已创建」"
grep -q "复用已有私钥" "$DIR/run2.log"; check $? "第 2 次启动日志明确说了「复用已有私钥」"

# 七条链：eth / btc 同源（secp256k1，但公钥编码不同），其余五条同源（ed25519）。
# 把 btc 加进这个集合是有意的——只比 eth 会漏掉「btc 侧地址派生不确定」的缺陷。
ADDR1="$(grep -oE '^  (eth|btc|sol|near|apt|sui|ton) +[^ ]+' "$DIR/run1.log" | tr -d ' ' | tr '\n' ' ')"
ADDR2="$(grep -oE '^  (eth|btc|sol|near|apt|sui|ton) +[^ ]+' "$DIR/run2.log" | tr -d ' ' | tr '\n' ' ')"
[ -n "$ADDR1" ] && [ "$ADDR1" = "$ADDR2" ]; check $? "两次启动派生出的七条链地址完全一致"

# 地址条数必须是 7：少了说明某条链派生失败被跳过，多了说明混进了无关输出。
COUNT="$(grep -cE '^  (eth|btc|sol|near|apt|sui|ton) +[^ ]+' "$DIR/run1.log")"
[ "$COUNT" -eq 7 ]; check $? "启动日志恰好列出 7 条链的地址（实到 $COUNT 条）"

echo
if [ "$fail" -eq 0 ]; then
  echo "全部通过：keystore 存在时不会重新生成私钥。"
else
  echo "有断言失败——说明存在「重新生成私钥」的路径，这是丢币级缺陷。"
fi
exit "$fail"
