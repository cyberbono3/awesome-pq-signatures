#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/results}"
FORMAT="${FORMAT:-both}"
PARAM_SETS="${PARAM_SETS:-SPHINCS-256f,SPHINCS-256s}"
MSG_SIZES="${MSG_SIZES:-32,256,1024,4096}"
ITERATIONS="${ITERATIONS:-100}"
WARMUP_RUNS="${WARMUP_RUNS:-3}"
RUNS="${RUNS:-5}"
OPERATIONS="${OPERATIONS:-keygen,sign,verify}"
ALG_NAME="${ALG_NAME:-SPHINCS (original)}"
LIB_NAME="${LIB_NAME:-gravity-rs}"
LIB_COMMIT="${LIB_COMMIT:-unknown}"
RNG_SOURCE="${RNG_SOURCE:-unknown}"
BENCH_CMD="${BENCH_CMD:-}"
COMPILER_NAME="${COMPILER_NAME:-rustc}"
COMPILER_FLAGS="${COMPILER_FLAGS:-${RUSTFLAGS:-}}"
PRINT_SUMMARY="${PRINT_SUMMARY:-0}"

usage() {
  cat <<'EOF'
Usage: run.sh [--bench-cmd "cmd"] [--out-dir path] [--format json|csv|both]
             [--param-sets list] [--msg-sizes list] [--iterations n]
             [--runs n] [--warmups n] [--operations list]

Required:
  --bench-cmd or BENCH_CMD env var.
  The command must read these env vars: OPERATION, PARAM_SET, MSG_SIZE, ITERATIONS.

Optional env vars:
  LIB_NAME, LIB_COMMIT, ALG_NAME, RNG_SOURCE, TURBO_STATE,
  COMPILER_NAME, COMPILER_VERSION, COMPILER_FLAGS, RUN_ID,
  PRINT_SUMMARY=1.

Example:
  BENCH_CMD='cargo run --release --bin sphincs_bench --' \
    ./bench/run.sh --msg-sizes 32,1024 --iterations 1000
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bench-cmd)
      BENCH_CMD="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --format)
      FORMAT="$2"
      shift 2
      ;;
    --param-sets)
      PARAM_SETS="$2"
      shift 2
      ;;
    --msg-sizes)
      MSG_SIZES="$2"
      shift 2
      ;;
    --iterations)
      ITERATIONS="$2"
      shift 2
      ;;
    --runs)
      RUNS="$2"
      shift 2
      ;;
    --warmups)
      WARMUP_RUNS="$2"
      shift 2
      ;;
    --operations)
      OPERATIONS="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$BENCH_CMD" ]]; then
  echo "BENCH_CMD is required." >&2
  usage >&2
  exit 1
fi

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]]; then
  echo "ITERATIONS must be an integer." >&2
  exit 1
fi
if ! [[ "$RUNS" =~ ^[0-9]+$ ]]; then
  echo "RUNS must be an integer." >&2
  exit 1
fi
if ! [[ "$WARMUP_RUNS" =~ ^[0-9]+$ ]]; then
  echo "WARMUP_RUNS must be an integer." >&2
  exit 1
fi

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

csv_escape() {
  local s="$1"
  if [[ "$s" == *','* || "$s" == *'"'* || "$s" == *$'\n'* ]]; then
    s="${s//\"/\"\"}"
    printf '"%s"' "$s"
  else
    printf '%s' "$s"
  fi
}

NOW_NS_METHOD="date"
if command -v python3 >/dev/null 2>&1; then
  NOW_NS_METHOD="python"
elif command -v perl >/dev/null 2>&1; then
  NOW_NS_METHOD="perl"
fi

now_ns() {
  case "$NOW_NS_METHOD" in
    python)
      python3 - <<'PY'
import time
print(int(time.time() * 1_000_000_000))
PY
      ;;
    perl)
      perl -MTime::HiRes -e 'printf "%d\n", Time::HiRes::time()*1_000_000_000'
      ;;
    *)
      printf "%s000000000\n" "$(date +%s)"
      ;;
  esac
}

calc_avg_ns() {
  awk -v it="$1" -v ns="$2" 'BEGIN { if (it == 0) { print 0 } else { printf "%.0f", ns / it } }'
}

calc_throughput() {
  awk -v it="$1" -v ns="$2" 'BEGIN { if (ns == 0) { print 0 } else { printf "%.3f", (it * 1000000000) / ns } }'
}

declare -a param_sets=()
declare -a msg_sizes=()
declare -a operations=()

IFS=',' read -r -a param_sets_raw <<< "$PARAM_SETS"
for item in "${param_sets_raw[@]}"; do
  item="$(trim "$item")"
  [[ -n "$item" ]] && param_sets+=("$item")
done

IFS=',' read -r -a msg_sizes_raw <<< "$MSG_SIZES"
for item in "${msg_sizes_raw[@]}"; do
  item="$(trim "$item")"
  [[ -n "$item" ]] && msg_sizes+=("$item")
done

IFS=',' read -r -a operations_raw <<< "$OPERATIONS"
for item in "${operations_raw[@]}"; do
  item="$(trim "$item")"
  [[ -n "$item" ]] && operations+=("$item")
done

if [[ ${#param_sets[@]} -eq 0 || ${#msg_sizes[@]} -eq 0 || ${#operations[@]} -eq 0 ]]; then
  echo "PARAM_SETS, MSG_SIZES, and OPERATIONS must be non-empty." >&2
  exit 1
fi
for item in "${msg_sizes[@]}"; do
  if ! [[ "$item" =~ ^[0-9]+$ ]]; then
    echo "MSG_SIZES must be a comma-separated list of integers." >&2
    exit 1
  fi
done

mkdir -p "$OUT_DIR"

run_id="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")-$$}"
timestamp_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
host="$(uname -n 2>/dev/null || echo unknown)"
os_kernel="$(uname -srmo 2>/dev/null || uname -sr 2>/dev/null || echo unknown)"

cpu_model="unknown"
if command -v lscpu >/dev/null 2>&1; then
  cpu_model="$(lscpu | awk -F: '/Model name/ {sub(/^[ \t]+/, "", $2); print $2; exit}')"
elif [[ -f /proc/cpuinfo ]]; then
  cpu_model="$(awk -F: '/model name/ {sub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo)"
elif command -v sysctl >/dev/null 2>&1; then
  cpu_model="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
fi
[[ -n "$cpu_model" ]] || cpu_model="unknown"

cpu_microcode="unknown"
if [[ -f /proc/cpuinfo ]]; then
  cpu_microcode="$(awk -F: '/microcode/ {sub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo)"
elif command -v sysctl >/dev/null 2>&1; then
  cpu_microcode="$(sysctl -n machdep.cpu.microcode_version 2>/dev/null || true)"
fi
[[ -n "$cpu_microcode" ]] || cpu_microcode="unknown"

ram_bytes="unknown"
if [[ -f /proc/meminfo ]]; then
  mem_kb="$(awk '/MemTotal/ {print $2; exit}' /proc/meminfo)"
  if [[ -n "$mem_kb" ]]; then
    ram_bytes="$((mem_kb * 1024))"
  fi
elif command -v sysctl >/dev/null 2>&1; then
  ram_bytes="$(sysctl -n hw.memsize 2>/dev/null || true)"
fi
[[ -n "$ram_bytes" ]] || ram_bytes="unknown"
ram_bytes_json="$ram_bytes"
if ! [[ "$ram_bytes" =~ ^[0-9]+$ ]]; then
  ram_bytes_json="\"$(json_escape "$ram_bytes")\""
fi

turbo_state="${TURBO_STATE:-}"
if [[ -z "$turbo_state" ]]; then
  if [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
    if [[ "$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)" == "1" ]]; then
      turbo_state="off"
    else
      turbo_state="on"
    fi
  elif [[ -f /sys/devices/system/cpu/cpufreq/boost ]]; then
    if [[ "$(cat /sys/devices/system/cpu/cpufreq/boost)" == "1" ]]; then
      turbo_state="on"
    else
      turbo_state="off"
    fi
  fi
fi
[[ -n "$turbo_state" ]] || turbo_state="unknown"

compiler_version="${COMPILER_VERSION:-}"
if [[ -z "$compiler_version" ]] && command -v rustc >/dev/null 2>&1; then
  compiler_version="$(rustc -Vv 2>/dev/null | awk 'NR==1 {print $0}')"
fi
[[ -n "$compiler_version" ]] || compiler_version="unknown"
[[ -n "$COMPILER_FLAGS" ]] || COMPILER_FLAGS="none"

workspace_commit="unknown"
if command -v git >/dev/null 2>&1; then
  if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    workspace_commit="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || true)"
  fi
fi
[[ -n "$workspace_commit" ]] || workspace_commit="unknown"

json_enabled=false
csv_enabled=false
case "$FORMAT" in
  json)
    json_enabled=true
    ;;
  csv)
    csv_enabled=true
    ;;
  both)
    json_enabled=true
    csv_enabled=true
    ;;
  *)
    echo "Unknown format: $FORMAT" >&2
    exit 1
    ;;
esac

json_tmp=""
json_file=""
csv_file=""

if $json_enabled; then
  json_tmp="$(mktemp "${OUT_DIR}/measurements.XXXXXX")"
  json_file="${OUT_DIR}/run-${run_id}.json"
fi
if $csv_enabled; then
  csv_file="${OUT_DIR}/run-${run_id}.csv"
  printf "%s\n" \
    "run_id,timestamp_utc,host,os_kernel,cpu_model,cpu_microcode,ram_bytes,compiler_name,compiler_version,compiler_flags,library_name,library_commit,algorithm_name,turbo_scaling,rng_source,workspace_commit,bench_command,iterations,warmup_runs,measurement_runs,operation,param_set,message_size,run_index,total_ns,avg_ns,throughput_ops_per_s" \
    > "$csv_file"
fi

cleanup() {
  [[ -n "$json_tmp" && -f "$json_tmp" ]] && rm -f "$json_tmp"
}
trap cleanup EXIT

append_measurement_json() {
  local param_set="$1"
  local msg_size="$2"
  local operation="$3"
  local run_index="$4"
  local total_ns="$5"
  local avg_ns="$6"
  local throughput="$7"
  local entry

  entry=$(
    cat <<EOF
    {
      "param_set": "$(json_escape "$param_set")",
      "message_size": $msg_size,
      "operation": "$(json_escape "$operation")",
      "run_index": $run_index,
      "iterations": $ITERATIONS,
      "total_ns": $total_ns,
      "avg_ns": $avg_ns,
      "throughput_ops_per_s": $throughput
    }
EOF
  )

  if [[ ! -s "$json_tmp" ]]; then
    printf "%s\n" "$entry" >> "$json_tmp"
  else
    printf ",\n%s\n" "$entry" >> "$json_tmp"
  fi
}

append_measurement_csv() {
  local param_set="$1"
  local msg_size="$2"
  local operation="$3"
  local run_index="$4"
  local total_ns="$5"
  local avg_ns="$6"
  local throughput="$7"

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$(csv_escape "$run_id")" \
    "$(csv_escape "$timestamp_utc")" \
    "$(csv_escape "$host")" \
    "$(csv_escape "$os_kernel")" \
    "$(csv_escape "$cpu_model")" \
    "$(csv_escape "$cpu_microcode")" \
    "$(csv_escape "$ram_bytes")" \
    "$(csv_escape "$COMPILER_NAME")" \
    "$(csv_escape "$compiler_version")" \
    "$(csv_escape "$COMPILER_FLAGS")" \
    "$(csv_escape "$LIB_NAME")" \
    "$(csv_escape "$LIB_COMMIT")" \
    "$(csv_escape "$ALG_NAME")" \
    "$(csv_escape "$turbo_state")" \
    "$(csv_escape "$RNG_SOURCE")" \
    "$(csv_escape "$workspace_commit")" \
    "$(csv_escape "$BENCH_CMD")" \
    "$(csv_escape "$ITERATIONS")" \
    "$(csv_escape "$WARMUP_RUNS")" \
    "$(csv_escape "$RUNS")" \
    "$(csv_escape "$operation")" \
    "$(csv_escape "$param_set")" \
    "$(csv_escape "$msg_size")" \
    "$(csv_escape "$run_index")" \
    "$(csv_escape "$total_ns")" \
    "$(csv_escape "$avg_ns")" \
    "$(csv_escape "$throughput")" \
    >> "$csv_file"
}

json_string_array() {
  local out=""
  local item=""
  for item in "$@"; do
    item="$(json_escape "$item")"
    out="${out}${out:+, }\"${item}\""
  done
  printf "[%s]" "$out"
}

json_number_array() {
  local out=""
  local item=""
  for item in "$@"; do
    item="$(trim "$item")"
    out="${out}${out:+, }${item}"
  done
  printf "[%s]" "$out"
}

param_sets_json="$(json_string_array "${param_sets[@]}")"
msg_sizes_json="$(json_number_array "${msg_sizes[@]}")"
operations_json="$(json_string_array "${operations[@]}")"

run_bench() {
  local operation="$1"
  local param_set="$2"
  local msg_size="$3"
  OPERATION="$operation" \
    PARAM_SET="$param_set" \
    MSG_SIZE="$msg_size" \
    MESSAGE_SIZE="$msg_size" \
    ITERATIONS="$ITERATIONS" \
    ALG_NAME="$ALG_NAME" \
    LIB_NAME="$LIB_NAME" \
    bash -c "$BENCH_CMD"
}

for param_set in "${param_sets[@]}"; do
  for msg_size in "${msg_sizes[@]}"; do
    for operation in "${operations[@]}"; do
      if [[ "$WARMUP_RUNS" -gt 0 ]]; then
        for ((warm=1; warm<=WARMUP_RUNS; warm++)); do
          run_bench "$operation" "$param_set" "$msg_size" >/dev/null
        done
      fi

      for ((run=1; run<=RUNS; run++)); do
        echo "Running ${operation} ${param_set} msg=${msg_size} run=${run}/${RUNS}..."
        start_ns="$(now_ns)"
        run_bench "$operation" "$param_set" "$msg_size"
        end_ns="$(now_ns)"
        total_ns="$((end_ns - start_ns))"
        avg_ns="$(calc_avg_ns "$ITERATIONS" "$total_ns")"
        throughput="$(calc_throughput "$ITERATIONS" "$total_ns")"

        if $json_enabled; then
          append_measurement_json "$param_set" "$msg_size" "$operation" "$run" "$total_ns" "$avg_ns" "$throughput"
        fi
        if $csv_enabled; then
          append_measurement_csv "$param_set" "$msg_size" "$operation" "$run" "$total_ns" "$avg_ns" "$throughput"
        fi
      done
    done
  done
done

if $json_enabled; then
  cat > "$json_file" <<EOF
{
  "schema_version": "1.0",
  "metadata": {
    "run_id": "$(json_escape "$run_id")",
    "timestamp_utc": "$(json_escape "$timestamp_utc")",
    "host": "$(json_escape "$host")",
    "os_kernel": "$(json_escape "$os_kernel")",
    "cpu": {
      "model": "$(json_escape "$cpu_model")",
      "microcode": "$(json_escape "$cpu_microcode")"
    },
    "ram_bytes": $ram_bytes_json,
    "compiler": {
      "name": "$(json_escape "$COMPILER_NAME")",
      "version": "$(json_escape "$compiler_version")",
      "flags": "$(json_escape "$COMPILER_FLAGS")"
    },
    "library": {
      "name": "$(json_escape "$LIB_NAME")",
      "commit": "$(json_escape "$LIB_COMMIT")"
    },
    "algorithm": {
      "name": "$(json_escape "$ALG_NAME")",
      "param_sets": $param_sets_json
    },
    "workload": {
      "message_sizes": $msg_sizes_json,
      "iterations": $ITERATIONS,
      "operations": $operations_json,
      "warmup_runs": $WARMUP_RUNS,
      "measurement_runs": $RUNS
    },
    "environment": {
      "turbo_scaling": "$(json_escape "$turbo_state")",
      "rng_source": "$(json_escape "$RNG_SOURCE")",
      "bench_command": "$(json_escape "$BENCH_CMD")"
    },
    "workspace_commit": "$(json_escape "$workspace_commit")"
  },
  "measurements": [
$(cat "$json_tmp")
  ]
}
EOF
  echo "Wrote JSON results to $json_file"
fi

if $csv_enabled; then
  echo "Wrote CSV results to $csv_file"
fi

print_summary=false
case "${PRINT_SUMMARY}" in
  1|true|TRUE|yes|YES)
    print_summary=true
    ;;
esac

if $print_summary; then
  if $csv_enabled; then
    if command -v python3 >/dev/null 2>&1; then
      python3 - "$csv_file" <<'PY'
import csv
import sys
from collections import defaultdict

path = sys.argv[1]
groups = defaultdict(lambda: {"count": 0, "avg_ns_sum": 0.0, "thr_sum": 0.0})

with open(path, newline="") as handle:
    reader = csv.DictReader(handle)
    for row in reader:
        key = (row["operation"], row["param_set"], row["message_size"])
        groups[key]["count"] += 1
        groups[key]["avg_ns_sum"] += float(row["avg_ns"])
        groups[key]["thr_sum"] += float(row["throughput_ops_per_s"])

print("\nSummary (avg across runs)")
print(f"{'operation':<10} {'param_set':<12} {'msg_size':>8} {'avg_ns':>12} {'throughput':>12} {'runs':>4}")
for (operation, param_set, msg_size) in sorted(groups.keys()):
    data = groups[(operation, param_set, msg_size)]
    count = data["count"]
    avg_ns = data["avg_ns_sum"] / count if count else 0.0
    thr = data["thr_sum"] / count if count else 0.0
    print(f"{operation:<10} {param_set:<12} {int(msg_size):>8} {avg_ns:>12.0f} {thr:>12.3f} {count:>4}")
PY
    else
      awk -F',' 'NR==1 {next} {key=$21 FS $22 FS $23; avg[key]+=$26; thr[key]+=$27; cnt[key]++}
      END {
        printf "\nSummary (avg across runs)\n";
        printf "%-10s %-12s %8s %12s %12s %4s\n", "operation", "param_set", "msg_size", "avg_ns", "throughput", "runs";
        for (k in cnt) {
          split(k, parts, FS);
          printf "%-10s %-12s %8s %12.0f %12.3f %4d\n", parts[1], parts[2], parts[3], avg[k]/cnt[k], thr[k]/cnt[k], cnt[k];
        }
      }' "$csv_file"
    fi
  else
    echo "PRINT_SUMMARY=1 requested but CSV output is disabled." >&2
  fi
fi
