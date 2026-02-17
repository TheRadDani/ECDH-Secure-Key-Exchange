#!/usr/bin/env bash
#
# Runs all tests and collects code coverage

set -euo pipefail

# Ensure we run from repository root (script is in zyphra/scripts)
cd "$(dirname "$0")/.."

if ! command -v grcov >/dev/null 2>&1; then
    echo "Error: grcov not found. Install with: cargo install grcov"
    exit 1
fi

# Prefer a local ./cargo wrapper if present, otherwise use system cargo
if [[ -x ./cargo ]]; then
  cargo="$(readlink -f "./cargo")"
else
  cargo="$(command -v cargo || true)"
fi

: "${CI_COMMIT:=${GITHUB_SHA:-local}}"
reportName="lcov-${CI_COMMIT:0:9}"

coverageFlags=()
# Verify rustc supports the required instrumentation flag
if ! rustc -Z help 2>&1 | grep -q instrument-coverage; then
  echo "rustc does not advertise 'instrument-coverage' support on this toolchain."
  echo "Install a recent Rust nightly or install 'cargo-llvm-cov' and re-run this script."
  echo "To install cargo-llvm-cov: cargo install cargo-llvm-cov"
  # If cargo-llvm-cov is present we'll prefer it later; otherwise fail early
  if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    exit 1
  fi
fi
# Use modern instrumentation flag for nightly compilers
coverageFlags+=(-Zinstrument-coverage) # Enable code coverage instrumentation
coverageFlags+=("-A" "incomplete_features") # Suppress warning about incomplete features
if [[ $(uname) != Darwin ]]; then # macOS skipped due to https://github.com/rust-lang/rust/issues/63047
    coverageFlags+=("-Clink-dead-code")    # Dead code should appear red in the report
fi
coverageFlags+=("-Ccodegen-units=1") # Disable code generation paralllelism which is unsupported under -Zprofile
coverageFlags+=("-Cinline-threshold=0") # Disable inlining, which complicates control flow.
coverageFlags+=("-Copt-level=0")
coverageFlags+=("-Coverflow-check=off") # Disable overflow checks, which create unnecessary branches

export RUSTFLAGS="${coverageFlags[*]} ${RUSTFLAGS:-}"
export CARGO_INCREMENTAL=0
export RUST_BACKTRACE=1
export RUST_MIN_STACK=8388608

# Where rustc will write LLVM profile data
export LLVM_PROFILE_FILE="target/cov/coverage-%p-%m.profraw"

echo "--- remove old coverage results"
if [[ -d target/cov ]]; then
  find target/cov -type f -name '*.gcda' -delete
fi

rm -rf target/cov/$reportName
mkdir -p target/cov

# Mark the base time for a clean room dir
touch target/cov/before-test

# Ensure packages array is defined (accepts optional package args)
declare -a packages=("${@}")
#shellcheck source=ci/common/limit-threads.sh
source ci/common/limit-threads.sh

# If `cargo-llvm-cov` is installed prefer it (more robust across toolchains)
if command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "--- cargo-llvm-cov detected; running coverage via cargo llvm-cov"
  # generate lcov and html report under target/cov
  mkdir -p target/cov/$reportName
  # Ensure we don't pass incompatible RUSTFLAGS to cargo-llvm-cov
  OLD_RUSTFLAGS="${RUSTFLAGS:-}"
  unset RUSTFLAGS || true
  # Run tests and collect profile data without generating report
  "$cargo" +nightly llvm-cov --workspace --no-report --jobs "$JOBS" || {
    RUSTFLAGS="${OLD_RUSTFLAGS:-}"; export RUSTFLAGS; exit $?
  }
  # Generate lcov report
  "$cargo" +nightly llvm-cov report --lcov --output-path target/cov/lcov.info || {
    RUSTFLAGS="${OLD_RUSTFLAGS:-}"; export RUSTFLAGS; exit $?
  }
  # Generate html report (separate invocation to avoid incompatible flags)
  "$cargo" +nightly llvm-cov report --html --output-dir target/cov/$reportName || {
    RUSTFLAGS="${OLD_RUSTFLAGS:-}"; export RUSTFLAGS; exit $?
  }
  RUSTFLAGS="${OLD_RUSTFLAGS:-}"; export RUSTFLAGS || true
  ln -sfT "$reportName" target/cov/LATEST || true
  exit 0
fi

# Force rebuild of possibly-cached proc macro crates and build.rs because
# we always want stable coverage for them
# Don't support odd file names in our repo ever
# Use safe expansions so `set -u` doesn't fail when variables are unset
if [[ -n "${CI:-}" || -z "${1:-}" ]]; then
  # Collect candidate files safely and touch only when non-empty
  build_files=$(git ls-files :**/build.rs 2>/dev/null || true)
  proc_files=$(git grep -l "proc-macro.*true" :**/Cargo.toml 2>/dev/null | sed 's|Cargo.toml|src/lib.rs|' || true)

  files_to_touch=$(printf "%s
%s
" "$build_files" "$proc_files" | sed '/^$/d')
  if [[ -n "$files_to_touch" ]]; then
    IFS=$'\n' read -r -d '' -a arr <<<"${files_to_touch}\0" || true
    if ((${#arr[@]})); then
      touch "${arr[@]}"
    fi
  fi
fi

#shellcheck source=ci/common/limit-threads.sh

source ci/common/limit-threads.sh

# Build tests without running to generate instrumentation
"$cargo" +nightly test --jobs "$JOBS" --target-dir target/cov --no-run "${packages[@]}"

# most verbose log level (trace) is enabled for all solana code to make log!
# macro code green always
if RUST_LOG=solana=trace "$cargo" +nightly test --jobs "$JOBS" --target-dir target/cov "${packages[@]}" -- --nocapture; then
  test_status=0
else
  test_status=$?
  echo "Failed: $test_status"
  echo "^^^ +++"
  if [[ -n "${CI:-}" ]]; then
    exit $test_status
  fi
fi
touch target/cov/after-test

echo "--- grcov"

# Create a clean room dir only with updated gcda/gcno files for this run,
# because our cached target dir is full of other builds' coverage files
rm -rf target/cov/tmp
mkdir -p target/cov/tmp

find target/cov -type f -name '*.gcda' -newer target/cov/before-test ! -newer target/cov/after-test -print0 | 
    (while IFS= read -r -d '' gcda_file; do
        gcno_file="${gcda_file%.gcda}.gcno"
        ln -sf "../../../$gcda_file" "target/cov/tmp/$(basename "$gcda_file")"
        ln -sf "../../../$gcno_file" "target/cov/tmp/$(basename "$gcno_file")"
    done)

(
  grcov_args=(
    target/cov/tmp
    --llvm
    --ignore \*.cargo\*
    --ignore \*build.rs
    --ignore bench-tps\*
    --ignore upload-perf\*
    --ignore bench-streamer\*
    --ignore local-cluster\*
  )

  set -x
  grcov "${grcov_args[@]}" -t html -o target/cov/$reportName
  grcov "${grcov_args[@]}" -t lcov -o target/cov/lcov.info

  cd target/cov
  tar zcf report.tar.gz $reportName
)

ls -l target/cov/$reportName/index.html
ln -sfT $reportName target/cov/LATEST

exit $test_status