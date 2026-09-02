#!/usr/bin/env bash
#
# 验证：目录里**只有一个** keystore 文件时会发生什么。
#
# 这个场景是 sign 里唯一「会在已有 keystore 的前提下新建私钥」的路径，
# 因此它值得单独一个脚本——钉住两件事：
#   1. 已有的那个文件必须一字不动（不能被顺便重建）；
#   2. 补齐的那个确实是一把**全新**私钥（对应链的地址会变），
#      且启动前给了明确警告。
#
# 为什么第 2 点必须钉住：补出来的新钥匙与用户此前（可能已收过款的）地址毫无关系。
# 如果是误删导致走到这里，那些地址里的资产将无人控制。
#
# 用法：
#   scripts/verify-partial-refill.sh              # 自动找 target/release/sign
#   scripts/verify-partial-refill.sh path/to/sign # 或显式指定
#
# 退出码：0 = 全部通过；1 = 有断言失败。
#
set -uo pipefail

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

DIR="$(mktemp -d "${TMPDIR:-/tmp}/sign-verify-partial-XXXXXX")"
PORT=17896
PW='verify-only-password-1234'
fail=0

cleanup() { rm -rf "$DIR"; }
trap cleanup EXIT

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

echo "── 第 1 次启动（全新，创建两个文件）"
run_once "$DIR/run1.log"
if [ ! -f "$DIR/keystore-secp256k1.json" ] || [ ! -f "$DIR/keystore-ed25519.json" ]; then
  echo "❌ 第 1 次启动没有创建出两个 keystore 文件"
  exit 1
fi
echo "  已创建两个文件"

# 保留 ed25519，删掉 secp256k1，制造 Partial。
ED_BEFORE="$(shasum -a 256 "$DIR/keystore-ed25519.json" | awk '{print $1}')"
rm "$DIR/keystore-secp256k1.json"

echo "── 第 2 次启动（Partial：只有 ed25519）"
run_once "$DIR/run2.log"
sed -n '1,22p' "$DIR/run2.log"
echo

ED_AFTER="$(shasum -a 256 "$DIR/keystore-ed25519.json" | awk '{print $1}')"

# ed25519 覆盖五条链；secp256k1 覆盖 **eth 与 btc**（同一颗种子、两种公钥编码）。
# 删掉 secp256k1 文件后补齐的是全新私钥，所以 **两条链的地址都必须变**——
# 只看 eth 会漏掉「有人把 btc 的编码换错」这类缺陷（例如误用非压缩公钥）。
ED_ADDR1="$(grep -oE '^  (sol|near|apt|sui|ton) +[^ ]+' "$DIR/run1.log" | tr -d ' ' | tr '\n' ' ')"
ED_ADDR2="$(grep -oE '^  (sol|near|apt|sui|ton) +[^ ]+' "$DIR/run2.log" | tr -d ' ' | tr '\n' ' ')"
ETH1="$(grep -oE '^  eth +[^ ]+' "$DIR/run1.log" | awk '{print $2}')"
ETH2="$(grep -oE '^  eth +[^ ]+' "$DIR/run2.log" | awk '{print $2}')"
BTC1="$(grep -oE '^  btc +[^ ]+' "$DIR/run1.log" | awk '{print $2}')"
BTC2="$(grep -oE '^  btc +[^ ]+' "$DIR/run2.log" | awk '{print $2}')"

echo "── 断言"
grep -q "只找到一个 keystore 文件" "$DIR/run2.log"; check $? "启动前给出了 Partial 警告"
[ "$ED_BEFORE" = "$ED_AFTER" ]; check $? "已存在的 ed25519 文件字节未变（没有被重建）"
[ -f "$DIR/keystore-secp256k1.json" ]; check $? "缺失的 secp256k1 文件已补齐"
[ -n "$ED_ADDR1" ] && [ "$ED_ADDR1" = "$ED_ADDR2" ]; check $? "ed25519 五条链（sol/near/apt/sui/ton）地址保持一致"
[ -n "$ETH1" ] && [ -n "$ETH2" ] && [ "$ETH1" != "$ETH2" ]; check $? "eth 地址已变（补出来的是全新私钥，符合预期）"
[ -n "$BTC1" ] && [ -n "$BTC2" ] && [ "$BTC1" != "$BTC2" ]; check $? "btc 地址也已变（与 eth 同源，同一颗种子）"
# 反证：btc 地址必须始终是主网 P2WPKH。若有人误把网络改了或用了非压缩公钥，
# 这里能立刻看出来，而不必等链上打款才发现。
[ -n "$BTC2" ] && case "$BTC2" in bc1q*) true;; *) false;; esac; check $? "btc 地址是主网 P2WPKH（bc1q 前缀）"

echo
echo "  eth 旧地址: $ETH1"
echo "  eth 新地址: $ETH2"
echo "  btc 旧地址: $BTC1"
echo "  btc 新地址: $BTC2"
echo
if [ "$fail" -eq 0 ]; then
  echo "全部通过：Partial 时只补齐缺失的那个，已有的不动。"
  echo "注意 eth / btc 地址已变——补出来的是全新私钥，这正是警告想让人注意的事。"
else
  echo "有断言失败。"
fi
exit "$fail"
