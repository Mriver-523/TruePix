#!/usr/bin/env bash
# ============================================================
# SD-scale (constraint=1350) average costs for ops under TruePix + Orion:
#   gray, mask, crop, inv
#
# Two configs per op. Orion uses OMP_NUM_THREADS=1 and is not pinned
# unless TRUEPIX_CPU is set. cpu1 is set to the performance governor when
# the guest can write cpufreq. Video mode decodes each op once.
#   1) --no-zk   plain GKR + Orion_nonzk
#   2) --zk      GKR product-mask + Orion_zk
#
# Reported means (from TruePix.sh / run_truepix_*.py logs):
#   TOTAL Signing Time (s)
#   Signing Max Memory (MB)
#   TOTAL Prove Time (s)
#   Total Proof Size (bytes) =
#       Input Commit Size (recommit) + VOLE(Prover) + Circuit + Input(PCS)
#   Prover Max Memory (MB)
#   TOTAL Verify Time (s)
#   Verifier Max Memory (MB)
#
# Time and memory: failed runs are dropped, then outliers are removed
# with a two-sided MAD rule (k=3.5) before the mean. Proof sizes are
# not trimmed; the reported figure is the median, and Min!=Max is
# flagged. Warmup runs are always discarded.
#
# Usage (from TruePix-main/):
#   ./bench_orion_sd_ops_avg.sh
#   RUNS=5 ./bench_orion_sd_ops_avg.sh
#   OPS="gray mask" RUNS=1 WARMUP=0 ./bench_orion_sd_ops_avg.sh
#   ./bench_orion_sd_ops_avg.sh --summarize-only bench_orion_sd_ops_avg_YYYYMMDD_HHMMSS
#   DRY_RUN=1 ./bench_orion_sd_ops_avg.sh
#
# Env:
#   RUNS=50             # formal repeats per (op, config) (default 50)
#   WARMUP=1            # interleaved warmup rounds, discarded (default 1)
#   SLEEP_BETWEEN=15    # idle between runs so cpu1 can leave the throttled clock
#   CONSTRAINT=1350     # SD macroblock count (720×480 / 16)
#   MODE=random         # random | video
#   INPUT=input.mp4     # used when MODE=video
#   CROP="0.2 0.8 0.2 0.8"
#   OPS="gray mask crop inv"
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SUMMARIZE_ONLY=""
if [ "${1:-}" = "--summarize-only" ]; then
  SUMMARIZE_ONLY="${2:?usage: $0 --summarize-only <outdir>}"
fi

RUNS="${RUNS:-50}"
WARMUP="${WARMUP:-1}"
SLEEP_BETWEEN="${SLEEP_BETWEEN:-15}"
CONSTRAINT="${CONSTRAINT:-1350}"
MODE="${MODE:-random}"
INPUT="${INPUT:-input.mp4}"
CROP="${CROP:-0.2 0.8 0.2 0.8}"
BOX="${BOX:-0.2 0.8 0.2 0.8}"
DRY_RUN="${DRY_RUN:-0}"

# shellcheck disable=SC2206
OPS=(${OPS:-gray mask crop inv})

# Hold cpu1 at the performance governor when the guest can write cpufreq.
# for the whole bench when the guest exposes cpufreq.
set_pinned_core_performance() {
  local gov_path="" candidate
  for candidate in \
    /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor \
    /sys/devices/system/cpu/cpufreq/policy1/scaling_governor
  do
    if [ -e "$candidate" ]; then
      gov_path="$candidate"
      break
    fi
  done
  if [ -z "$gov_path" ]; then
    echo "CPU governor: cpu1 cpufreq not exposed; clock stays under the hypervisor"
    return 0
  fi
  local before
  before="$(cat "$gov_path" 2>/dev/null || true)"
  if [ -w "$gov_path" ] && echo performance >"$gov_path" 2>/dev/null; then
    echo "CPU governor: cpu1 ${before:-unknown} -> performance ($gov_path)"
    return 0
  fi
  echo "CPU governor: cpu1 is '${before:-unknown}' and not writable."
  echo "  To pin it before a long run: echo performance | sudo tee $gov_path"
}

op_of_tag() {
  local tag="$1"
  if [[ "$tag" == *_nozk ]]; then
    echo "${tag%_nozk}"
  elif [[ "$tag" == *_zk ]]; then
    echo "${tag%_zk}"
  else
    echo "$tag"
  fi
}

# tag | zk_flag | label written into the summary
CONFIGS=(
  "nozk|--no-zk|nozk"
  "zk|--zk|zk"
)

cleanup_before_run() {
  rm -f vole_prover_*.json vole_verifier_*.json vole_ext_prover_*.json vole_ext_verifier_*.json
  rm -f input.txt output.txt output.mp4
  rm -f orion_commit.json orion_mask_seed.txt orion_open_result.json
  rm -f orion_proof.bin orion_proof_masked.bin orion_proof_mask.bin
  rm -f transmitted_data.txt transmitted_data_mask.txt transmitted_data_masked.txt
  rm -f gkr_point_*.json gkr_point_*.txt gkr_point.json gkr_point.txt
  rm -f public_key.pem signature.bin
  rm -f circuitproof hyraxproof log.txt log_fftgkr.txt 2>/dev/null || true
}

args_for() {
  local op="$1"
  local zk_flag="$2"
  local reuse="${3:-0}"
  local base=()

  if [ "$MODE" = "video" ]; then
    base+=(--input "$INPUT")
    if [ "$reuse" = "1" ]; then
      local n
      n="$(cat "$OUTDIR/prepared/$op/constraint")"
      base+=(--reuse-io --constraint "$n")
    fi
  else
    base+=(--random --constraint "$CONSTRAINT")
  fi

  case "$op" in
    gray|mask|inv)
      base+=(--operation "$op")
      ;;
    crop)
      base+=(--operation crop)
      if [ "$MODE" = "video" ]; then
        # shellcheck disable=SC2206
        local crop_a=($CROP)
        base+=(--crop "${crop_a[@]}")
      fi
      ;;
    box)
      base+=(--operation box)
      if [ "$MODE" = "video" ]; then
        # shellcheck disable=SC2206
        local box_a=($BOX)
        base+=(--box "${box_a[@]}")
      fi
      ;;
    *)
      echo "unknown op: $op" >&2
      exit 1
      ;;
  esac

  base+=("$zk_flag")
  printf '%q ' "${base[@]}"
}

run_one() {
  local tag="$1"
  local args_quoted="$2"
  local logfile="$3"
  local zk_label="$4"

  cleanup_before_run
  if [ "$MODE" = "video" ]; then
    local op src
    op="$(op_of_tag "$tag")"
    src="$OUTDIR/prepared/$op"
    if [ -f "$src/input.txt" ] && [ -f "$src/output.txt" ]; then
      cp -f "$src/input.txt" "$src/output.txt" .
    fi
  fi
  local start end wall exit_code
  start=$(date +%s.%N)
  if [ "$DRY_RUN" = "1" ]; then
    echo "DRY_RUN: ./TruePix.sh $args_quoted"
    exit_code=0
    wall=0
    echo "(dry-run placeholder log)" >"$logfile"
    {
      echo "exit_code=$exit_code"
      echo "wall_time=$wall"
      echo "args=$args_quoted"
      echo "zk_label=$zk_label"
      echo "constraint=$CONSTRAINT"
      echo "dry_run=1"
    } >"${logfile%.log}.meta"
    echo "  -> $tag DRY_RUN"
    return 0
  fi

  # shellcheck disable=SC2086
  eval "./TruePix.sh $args_quoted" >"$logfile" 2>&1
  exit_code=$?
  end=$(date +%s.%N)
  wall=$(awk -v s="$start" -v e="$end" 'BEGIN { printf "%.6f", e - s }')
  {
    echo "exit_code=$exit_code"
    echo "wall_time=$wall"
    echo "args=$args_quoted"
    echo "zk_label=$zk_label"
    echo "constraint=$CONSTRAINT"
  } >"${logfile%.log}.meta"
  echo "  -> $tag exit=$exit_code wall=${wall}s"
  return "$exit_code"
}

summarize_dir() {
  local outdir="$1"
  python3 - "$outdir" <<'PY'
import csv, re, statistics, sys
from pathlib import Path

outdir = Path(sys.argv[1])

PATTERNS = {
    "TOTAL Signing Time (s)": r"TOTAL Signing Time\s*:\s*([0-9.]+)",
    "TOTAL Prove Time (s)": r"TOTAL Prove Time\s*:\s*([0-9.]+)",
    "TOTAL Verify Time (s)": r"TOTAL Verify Time\s*:\s*([0-9.]+)",
    "Circuit Proof Size (bytes)": r"Circuit Proof Size\s*:\s*([0-9,]+)",
    "VOLE Relations Bytes (Prover)": r"VOLE Relations Bytes \(Prover\)\s*:\s*([0-9,]+)",
    "Input Proof Size (bytes)": r"Input Proof Size\s*:\s*([0-9,]+)",
    "Input Commit Size (bytes)": r"Input Commit Size\s*:\s*([0-9,]+)",
    "Total Proof Size (bytes)": r"Total Proof Size\s*:\s*([0-9,]+)",
    "Constraint Size": r"Using constraint size:\s*(\d+)",
}

MEM_PATTERN = re.compile(r"Max Memory Usage\s*:\s*([0-9.]+)\s*MB")
SIGN_MARK = "===            signature Performance             ==="
PROVER_MARK = "=== Running Fennel Prover ==="
VERIFY_MARK = "=== Running Fennel Verifier ==="

FOCUS = [
    "TOTAL Signing Time (s)",
    "Signing Max Memory (MB)",
    "TOTAL Prove Time (s)",
    "Total Proof Size (bytes)",
    "Prover Max Memory (MB)",
    "TOTAL Verify Time (s)",
    "Verifier Max Memory (MB)",
]


def split_sections(text: str):
    signing = prover = verifier = ""
    if SIGN_MARK in text:
        signing = text.split(SIGN_MARK, 1)[1]
        if PROVER_MARK in signing:
            signing = signing.split(PROVER_MARK, 1)[0]
    if PROVER_MARK in text:
        prover = text.split(PROVER_MARK, 1)[1]
        if VERIFY_MARK in prover:
            prover = prover.split(VERIFY_MARK, 1)[0]
    if VERIFY_MARK in text:
        verifier = text.split(VERIFY_MARK, 1)[1]
    return signing, prover, verifier


def last_mem(section: str):
    mems = MEM_PATTERN.findall(section)
    return float(mems[-1]) if mems else None


def parse_log(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    result = {}
    for name, pat in PATTERNS.items():
        m = re.search(pat, text, re.M)
        if not m:
            continue
        raw = m.group(1).strip().replace(",", "")
        try:
            result[name] = float(raw)
        except ValueError:
            pass

    signing, prover, verifier = split_sections(text)
    sm, pm, vm = last_mem(signing), last_mem(prover), last_mem(verifier)
    if sm is not None:
        result["Signing Max Memory (MB)"] = sm
    if pm is not None:
        result["Prover Max Memory (MB)"] = pm
    if vm is not None:
        result["Verifier Max Memory (MB)"] = vm

    circuit = result.get("Circuit Proof Size (bytes)", 0.0) or 0.0
    vole = result.get("VOLE Relations Bytes (Prover)", 0.0) or 0.0
    pcs = result.get("Input Proof Size (bytes)", 0.0) or 0.0
    commit = result.get("Input Commit Size (bytes)", 0.0) or 0.0
    # Prefer the prover-printed Total Proof Size when present; otherwise assemble.
    printed_total = result.get("Total Proof Size (bytes)")
    if any(k in result for k in (
        "Circuit Proof Size (bytes)",
        "VOLE Relations Bytes (Prover)",
        "Input Proof Size (bytes)",
        "Input Commit Size (bytes)",
        "Total Proof Size (bytes)",
    )):
        if printed_total is None:
            result["Total Proof Size (bytes)"] = commit + vole + circuit + pcs
        result["Circuit Proof Size (bytes)"] = circuit
        result["VOLE Relations Bytes (Prover)"] = vole
        result["Input Proof Size (bytes)"] = pcs
        result["Input Commit Size (bytes)"] = commit

    meta = path.with_suffix(".meta")
    if meta.is_file():
        for line in meta.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("wall_time="):
                try:
                    result["Wall Time (s)"] = float(line.split("=", 1)[1])
                except ValueError:
                    pass
            elif line.startswith("exit_code="):
                try:
                    result["Exit Code"] = float(line.split("=", 1)[1])
                except ValueError:
                    pass
            elif line.startswith("zk_label="):
                result["ZK Label"] = line.split("=", 1)[1].strip()
            elif line.startswith("protocol="):
                result["Protocol"] = line.split("=", 1)[1].strip()
            elif line.startswith("constraint="):
                try:
                    result["Constraint Size"] = float(line.split("=", 1)[1])
                except ValueError:
                    pass
    return result


SIZE_METRICS = {
    "Circuit Proof Size (bytes)",
    "VOLE Relations Bytes (Prover)",
    "Input Proof Size (bytes)",
    "Input Commit Size (bytes)",
    "Total Proof Size (bytes)",
}


def drop_outliers(metric, vals):
    """Return (kept, dropped, note).

    Proof sizes are never trimmed. Time and memory use a two-sided
    median/MAD rule once there are at least 3 samples. If fewer than 2
    points would remain, keep every sample and say so.
    """
    if metric in SIZE_METRICS or len(vals) < 3:
        return list(vals), [], ""
    med = statistics.median(vals)
    mad = statistics.median([abs(x - med) for x in vals])
    if mad > 0:
        limit = 3.5 * 1.4826 * mad
    else:
        floor = 5.0 if "Memory" in metric else (0.05 if "Time" in metric or metric.endswith("(s)") else 0.0)
        limit = max(0.20 * abs(med), floor)
    kept = [x for x in vals if abs(x - med) <= limit]
    dropped = [x for x in vals if abs(x - med) > limit]
    if len(kept) < 2:
        return list(vals), [], "kept-all"
    return kept, dropped, ""


def fmt(x):
    if x is None or x == "":
        return ""
    if isinstance(x, float):
        if abs(x - round(x)) < 1e-9 and abs(x) >= 100:
            return f"{int(round(x)):,}"
        return f"{x:.6f}".rstrip("0").rstrip(".")
    return str(x)


cases = sorted(
    [p for p in outdir.iterdir() if p.is_dir() and list(p.glob("run_*.log"))],
    key=lambda p: p.name,
)
if not cases:
    print("[ERROR] no case dirs with run_*.log under", outdir)
    sys.exit(1)

all_rows = []
wide = {}
case_meta = {}
any_numeric = False

for case_dir in cases:
    name = case_dir.name
    # "gray_nozk" / "crop_zk"
    if name.endswith("_nozk"):
        op, zk_tag = name[: -len("_nozk")], "nozk"
    elif name.endswith("_zk"):
        op, zk_tag = name[: -len("_zk")], "zk"
    else:
        op, zk_tag = name, "?"
    case_meta[name] = {
        "Operation": op,
        "ZK": zk_tag,
    }

    logs = sorted(case_dir.glob("run_*.log"))
    bucket = {}
    ok_runs = 0
    for log in logs:
        data = parse_log(log)
        if data.get("Exit Code", 0) != 0:
            continue
        ok_runs += 1
        for k, v in data.items():
            if k in ("Exit Code", "ZK Label", "Protocol"):
                continue
            if isinstance(v, (int, float)):
                bucket.setdefault(k, []).append(float(v))

    print(f"[{name}] runs={len(logs)} ok={ok_runs}")

    wide[name] = {}
    for metric, vals in sorted(bucket.items()):
        any_numeric = True
        kept, dropped, note = drop_outliers(metric, vals)
        median = statistics.median(vals)
        if metric in SIZE_METRICS:
            reported = median
            if min(vals) != max(vals):
                note = "inconsistent"
            stdev = statistics.stdev(vals) if len(vals) > 1 else 0.0
            n_used = len(vals)
            dropped = []
        else:
            reported = statistics.mean(kept)
            stdev = statistics.stdev(kept) if len(kept) > 1 else 0.0
            n_used = len(kept)
        row = {
            "Case": name,
            "Operation": case_meta[name]["Operation"],
            "ZK": case_meta[name]["ZK"],
            "Metric": metric,
            "N": len(vals),
            "N_used": n_used,
            "Mean": round(reported, 6),
            "Median": round(median, 6),
            "Stdev": round(stdev, 6),
            "Min": round(min(vals), 6),
            "Max": round(max(vals), 6),
            "Dropped": ";".join(f"{x:.6f}" for x in dropped),
            "Note": note,
        }
        all_rows.append(row)
        wide[name][metric] = row["Mean"]

if not any_numeric:
    print("[WARN] no numeric metrics extracted (dry-run or failed logs); writing empty summaries")

focus_rows = [r for r in all_rows if r["Metric"] in FOCUS]
focus_order = {m: i for i, m in enumerate(FOCUS)}
focus_rows.sort(key=lambda r: (r["Operation"], r["ZK"], focus_order.get(r["Metric"], 99)))

csv_path = outdir / "summary_avg.csv"
fieldnames = ["Case", "Operation", "ZK", "Metric", "N", "N_used", "Mean", "Median", "Stdev", "Min", "Max", "Dropped", "Note"]
with csv_path.open("w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(all_rows)

focus_csv = outdir / "summary_focus.csv"
with focus_csv.open("w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(focus_rows)

case_names = [p.name for p in cases]
pivot_path = outdir / "summary_focus_pivot.csv"
with pivot_path.open("w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    header = ["Metric"]
    for c in case_names:
        m = case_meta[c]
        header.append(f"{m['Operation']}/{m['ZK']}")
    w.writerow(header)
    for metric in FOCUS:
        w.writerow([metric] + [wide.get(c, {}).get(metric, "") for c in case_names])

md_path = outdir / "summary_focus.md"
with md_path.open("w", encoding="utf-8") as fh:
    fh.write("# TruePix + Orion SD ops average\n\n")
    fh.write(f"Directory: `{outdir.name}`\n\n")
    fh.write("Orion runs with OMP_NUM_THREADS=1 and is not pinned to a CPU. ")
    fh.write("Input Proof Size is the tensor-IOP sum, not the NIZK blob size.\n\n")
    fh.write("Total Proof Size = Input Commit Size (recommit) + VOLE Relations Bytes (Prover) + Circuit Proof Size + Input Proof Size.\n\n")
    fh.write("Time and memory means drop two-sided MAD outliers (k=3.5) after discarding failed runs. ")
    fh.write("Proof-size cells are medians; `inconsistent` means Min and Max differ.\n\n")
    fh.write("## Focus means\n\n")
    ops = []
    for c in case_names:
        op = case_meta[c]["Operation"]
        if op not in ops:
            ops.append(op)
    for op in ops:
        fh.write(f"### {op}\n\n")
        op_cases = [c for c in case_names if case_meta[c]["Operation"] == op]
        fh.write("| Metric | " + " | ".join(case_meta[c]["ZK"] for c in op_cases) + " |\n")
        fh.write("|---|" + "|".join(["---:" for _ in op_cases]) + "|\n")
        for metric in FOCUS:
            cells = [fmt(wide.get(c, {}).get(metric)) for c in op_cases]
            fh.write(f"| {metric} | " + " | ".join(cells) + " |\n")
        fh.write("\n")

print(f"Wrote {csv_path}")
print(f"Wrote {focus_csv}")
print(f"Wrote {pivot_path}")
print(f"Wrote {md_path}")
PY
}

if [ -n "$SUMMARIZE_ONLY" ]; then
  summarize_dir "$SUMMARIZE_ONLY"
  exit 0
fi

OUTDIR="${OUTDIR:-bench_orion_sd_ops_avg_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"

{
  echo "pcs=orion"
  echo "constraint=$CONSTRAINT"
  echo "mode=$MODE"
  echo "input=$INPUT"
  echo "cores=unpinned"
  echo "omp_threads=1"
  echo "runs=$RUNS"
  echo "warmup=$WARMUP"
  echo "sleep_between=$SLEEP_BETWEEN"
  echo "ops=${OPS[*]}"
} >"$OUTDIR/bench_meta.txt"

prepare_video_io() {
  local op="$1"
  local dest="$OUTDIR/prepared/$op"
  mkdir -p "$dest"
  echo "Preparing $op video inputs (decode once)"
  rm -f input.txt output.txt output.mp4
  local args
  args="$(args_for "$op" "--no-zk" 0)"
  if [ "$DRY_RUN" = "1" ]; then
    echo "DRY_RUN: ./TruePix.sh $args --edit-only"
    echo "$CONSTRAINT" >"$dest/constraint"
    return 0
  fi
  # shellcheck disable=SC2086
  eval "./TruePix.sh $args --edit-only"
  cp -f input.txt output.txt "$dest/"
  wc -l <input.txt | tr -d '[:space:]' >"$dest/constraint"
  echo "  $op constraint=$(cat "$dest/constraint")"
}

run_case() {
  local op="$1"
  local cfg="$2"
  local kind="$3"
  local idx="$4"
  local total="$5"
  IFS='|' read -r tag zk_flag zk_label <<<"$cfg"
  local case_dir="$OUTDIR/${op}_${tag}"
  mkdir -p "$case_dir"
  local reuse=0
  if [ "$MODE" = "video" ]; then
    reuse=1
  fi
  local args logfile
  args="$(args_for "$op" "$zk_flag" "$reuse")"
  if [ "$kind" = "warmup" ]; then
    logfile="$case_dir/warmup_${idx}.log"
    echo "[${op}_${tag}] warmup $idx/$total"
    run_one "${op}_${tag}" "$args" "$logfile" "$zk_label" || true
  else
    logfile="$case_dir/run_${idx}.log"
    echo "[${op}_${tag}] run $idx/$total"
    if ! run_one "${op}_${tag}" "$args" "$logfile" "$zk_label"; then
      FAILED=$((FAILED + 1))
    fi
  fi
  sleep "$SLEEP_BETWEEN"
}

echo "============================================================"
echo "Orion SD ops average (TruePix)"
echo "Output:     $OUTDIR"
echo "Constraint: $CONSTRAINT (SD, random mode; video uses the edited line count)"
echo "Mode:       $MODE"
echo "Ops:        ${OPS[*]}"
echo "Configs:    nozk, zk   (OMP_NUM_THREADS=1, no taskset)"
echo "Runs:       $RUNS  Warmup: $WARMUP   (rounds interleave ops)"
echo "Idle:       ${SLEEP_BETWEEN}s between runs"
echo "============================================================"
set_pinned_core_performance

if [ "$MODE" = "video" ]; then
  for op in "${OPS[@]}"; do
    prepare_video_io "$op"
  done
fi

FAILED=0
if [ "$WARMUP" -gt 0 ]; then
  for w in $(seq 1 "$WARMUP"); do
    echo ""
    echo "---------- warmup round $w/$WARMUP ----------"
    for op in "${OPS[@]}"; do
      for cfg in "${CONFIGS[@]}"; do
        run_case "$op" "$cfg" warmup "$w" "$WARMUP"
      done
    done
  done
fi

for i in $(seq 1 "$RUNS"); do
  echo ""
  echo "---------- round $i/$RUNS ----------"
  for op in "${OPS[@]}"; do
    for cfg in "${CONFIGS[@]}"; do
      run_case "$op" "$cfg" run "$i" "$RUNS"
    done
  done
done

echo ""
echo "Summarizing..."
summarize_dir "$OUTDIR"

echo ""
echo "Done. Results in: $OUTDIR"
echo "  summary_focus.csv / summary_focus_pivot.csv / summary_focus.md"
echo "  summary_avg.csv (all extracted metrics)"
if [ "$FAILED" -ne 0 ]; then
  echo "[WARN] $FAILED formal run(s) returned non-zero exit code"
  exit 1
fi
