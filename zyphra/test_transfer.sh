#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# Two-node transfer test
# ──────────────────────────────────────────────────────────────────
set -euo pipefail
BIN="./target/debug/kademlia-crypto-node"
LOG_R="/tmp/receiver.log"
LOG_S="/tmp/sender.log"

# Clean up on exit
cleanup() {
    kill "$RECEIVER_PID" "$SENDER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Kill any stale node processes first
pkill -9 -f kademlia-crypto-node 2>/dev/null || true
sleep 1

echo "╔═══════════════════════════════════════════╗"
echo "║   Two-Node Transfer Integration Test      ║"
echo "╚═══════════════════════════════════════════╝"

# ── Build ────────────────────────────────────────────────────────
echo "[1/6] Building..."
cargo build 2>&1 | tail -3

# ── Start receiver ───────────────────────────────────────────────
echo "[2/6] Starting receiver on 0.0.0.0:9000..."
RUST_LOG=info "$BIN" --listen /ip4/0.0.0.0/tcp/9000 --balance 5000 \
    </dev/null >"$LOG_R" 2>&1 &
RECEIVER_PID=$!
sleep 2

# Extract receiver's wallet address and PeerId
RECEIVER_WALLET=$(grep "Wallet address" "$LOG_R" | head -1 | awk '{print $NF}')
RECEIVER_PEERID=$(grep "Peer ID" "$LOG_R" | head -1 | awk '{print $NF}')
echo "   Receiver wallet : $RECEIVER_WALLET"
echo "   Receiver PeerID : $RECEIVER_PEERID"

if [ -z "$RECEIVER_PEERID" ]; then
    echo "FAIL: Could not extract receiver PeerId"
    cat "$LOG_R"
    exit 1
fi

# ── Start sender ────────────────────────────────────────────────
echo "[3/6] Starting sender on 0.0.0.0:9001, connecting to receiver..."

# Use a subshell pipe: sleep to let connection establish, then send command,
# then keep stdin open (sleep 60) so the process doesn't exit on EOF.
(
    sleep 5
    echo "send $RECEIVER_WALLET 250"
    sleep 2
    echo "balance"
    sleep 60
) | RUST_LOG=info "$BIN" \
    --listen /ip4/0.0.0.0/tcp/9001 \
    --peer "/ip4/127.0.0.1/tcp/9000/p2p/$RECEIVER_PEERID" \
    --balance 8000 \
    >"$LOG_S" 2>&1 &
SENDER_PID=$!

# Wait for connection + command execution
echo "[4/6] Waiting for connection and transfer..."
sleep 12

# ── Check results ───────────────────────────────────────────────
echo "[5/6] Checking logs..."
echo ""
echo "════════════════ SENDER LOG ════════════════"
cat "$LOG_S"
echo ""
echo "════════════════ RECEIVER LOG ══════════════"
tail -30 "$LOG_R"
echo ""

# ── Verify transfer ────────────────────────────────────────────
echo "[6/6] Verifying..."
PASS=0
FAIL=0

if grep -q "Transaction sent\|✓ Sent 250" "$LOG_S" 2>/dev/null; then
    echo "✅ SENDER: Transaction submitted successfully"
    PASS=$((PASS+1))
else
    echo "❌ SENDER: Transaction NOT submitted"
    FAIL=$((FAIL+1))
fi

if grep -q "Transfer confirmed" "$LOG_S" 2>/dev/null; then
    echo "✅ SENDER: Received confirmation from receiver"
    PASS=$((PASS+1))
else
    echo "❌ SENDER: No confirmation received"
    FAIL=$((FAIL+1))
fi

if grep -q "Accepted direct transfer\|Received.*250" "$LOG_R" 2>/dev/null; then
    echo "✅ RECEIVER: Transaction received and credited"
    PASS=$((PASS+1))
else
    echo "❌ RECEIVER: Transaction NOT received"
    FAIL=$((FAIL+1))
fi

if grep -q "Balance: 7750" "$LOG_S" 2>/dev/null; then
    echo "✅ SENDER: Balance correctly debited (8000 → 7750)"
    PASS=$((PASS+1))
else
    echo "❌ SENDER: Balance not correctly debited"
    FAIL=$((FAIL+1))
fi

echo ""
echo "═══════════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -eq 0 ]; then
    echo "🎉 ALL CHECKS PASSED"
else
    echo "⚠️  SOME CHECKS FAILED"
    exit 1
fi
