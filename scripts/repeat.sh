#!/usr/bin/env bash
# Five repetitions of the two racy scenarios (concurrent replay, flood) on all
# three verifiers. Other scenarios are run with tiny sizes and ignored here.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release --quiet
mkdir -p results/repeat
for i in 1 2 3 4 5; do
  ./target/release/dsa-bench --n 10 --per-offset 1 --nonce-n 1 --stale-wait 0 --throughput 100 \
    --concurrent 200 --threads 16 --flood 150000 --csv "results/repeat/run-$i.csv" > /dev/null 2>&1
done
echo "sut,scenario,runs,accepted_per_run"
for sc in replay_concurrent flood_replay_old flood_honest_after flood_replay_new; do
  for sut in dpop-auth-0.1.3 skyauth-0.3.9 reference; do
    vals=$(grep -h "^$sut,$sc," results/repeat/run-*.csv | cut -d, -f5 | paste -sd' ')
    echo "$sut,$sc,5,$vals"
  done
done
