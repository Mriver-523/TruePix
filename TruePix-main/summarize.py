#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TruePix Benchmark Summary (with outlier removal)

功能：
1. 自动寻找最新的 benchmark_* 目录，或使用 --dir 指定；
2. 从每组 run_*.log 中提取所有关键指标；
3. 按阶段正确提取 Signing / Prover / Verifier 的 Max Memory；
4. 使用稳健异常检测（Median + MAD）剔除异常值；
5. 输出 summary.csv 和 summary.md。
"""

import os
import re
import csv
import glob
import statistics
import argparse


# ============================================================
# 配置
# ============================================================

CASES = [
    "A1_gray_nozk",
    "A2_gray_zk",
    "B1_invert_nozk",
    "B2_invert_zk",
    "C1_mask_nozk",
    "C2_mask_zk",
    "D1_crop_nozk",
    "D2_crop_zk",
]

PATTERNS = {
    "Processing Speed (frame/s)": r"Processing \w+:.*?([0-9.]+)frame/s",
    "Constraint Size": r"Using constraint size:\s*(\d+)",
    "Input Commit Size (bytes)": r"Input Commit Size\s*:\s*(\d+)",
    "Input Commit Time (s)": r"Input Commit Time\s*:\s*([0-9.]+)",
    "Input Signed Message Size (bytes)": r"Input Signed Message Size\s*:\s*(\d+)",
    "Input Signature Size (bytes)": r"Input Signature Size\s*:\s*(\d+)",
    "Input Signing Time (s)": r"Input Signing Time\s*:\s*([0-9.]+)",
    "TOTAL Signing Time (s)": r"TOTAL Signing Time\s*:\s*([0-9.]+)",
    "GKR Sumcheck Time (s)": r"GKR Sumcheck Time:\s*([0-9.]+)",
    "Circuit Proof Size (bytes)": r"Circuit Proof Size\s*:\s*([0-9,]+)",
    "Circuit Prove Time (s)": r"Circuit Prove Time\s*:\s*([0-9.]+)",
    "VOLE Relations Used (Prover)": r"VOLE Relations Used \(Prover\)\s*:\s*([0-9,]+)",
    "VOLE Relations Bytes (Prover)": r"VOLE Relations Bytes \(Prover\)\s*:\s*([0-9,]+)",
    "Input Proof Size (bytes)": r"Input Proof Size\s*:\s*([0-9,]+)",
    "Input Prove Time (s)": r"Input Prove Time\s*:\s*([0-9.]+)",
    "EC(y1) Code-Switch Time (s)": r"EC\(y1\) Code-Switch Time\s*:\s*([0-9.]+)",
    "EC(y1) Prover Time (s)": r"EC\(y1\) Prover Time\s*:\s*([0-9.]+)",
    "EC(y1) Verifier Time (s)": r"EC\(y1\) Verifier Time\s*:\s*([0-9.]+)",
    "TOTAL Prove Time (s)": r"TOTAL Prove Time\s*:\s*([0-9.]+)",
    "Circuit Verify Time (s)": r"Circuit Verify Time\s*:\s*([0-9.]+)",
    "VOLE Relations Used (Verifier)": r"VOLE Relations Used \(Verifier\)\s*:\s*([0-9,]+)",
    "VOLE Relations Bytes (Verifier)": r"VOLE Relations Bytes \(Verifier\)\s*:\s*([0-9,]+)",
    "Input Verify Time (s)": r"Input Verify Time\s*:\s*([0-9.]+)",
    "Signature Verify Time (s)": r"Signature Verify Time\s*:\s*([0-9.]+)",
    "TOTAL Verify Time (s)": r"TOTAL Verify Time\s*:\s*([0-9.]+)",
}

MEM_PATTERN = r"Max Memory Usage\s*:\s*([0-9.]+)\s*MB"

DEFAULT_MAD_K = 3.5
MAD_FALLBACK_RATIO = 0.20
MAD_FALLBACK_STDEV = 3.0


# ============================================================
# 日志解析
# ============================================================

def extract_last_memory(section_text):
    mems = re.findall(MEM_PATTERN, section_text)
    if not mems:
        return None
    return float(mems[-1])


def split_sections(text):
    signing_marker = "===            signature Performance             ==="
    prover_marker = "=== Running TruePix Prover ==="
    verifier_marker = "=== Running TruePix Verifier ==="

    signing_section = ""
    prover_section = ""
    verifier_section = ""

    if signing_marker in text:
        signing_section = text.split(signing_marker, 1)[1]
        if prover_marker in signing_section:
            signing_section = signing_section.split(prover_marker, 1)[0]

    if prover_marker in text:
        prover_section = text.split(prover_marker, 1)[1]
        if verifier_marker in prover_section:
            prover_section = prover_section.split(verifier_marker, 1)[0]

    if verifier_marker in text:
        verifier_section = text.split(verifier_marker, 1)[1]

    return signing_section, prover_section, verifier_section


def parse_log(path):
    text = open(path, encoding="utf-8", errors="ignore").read()
    result = {}

    for name, pat in PATTERNS.items():
        m = re.search(pat, text)
        if m:
            val = m.group(1).replace(",", "")
            try:
                result[name] = float(val)
            except ValueError:
                result[name] = val
        else:
            result[name] = None

    signing_section, prover_section, verifier_section = split_sections(text)

    result["Signing Max Memory (MB)"] = extract_last_memory(signing_section)
    result["Prover Max Memory (MB)"] = extract_last_memory(prover_section)
    result["Verifier Max Memory (MB)"] = extract_last_memory(verifier_section)

    return result


# ============================================================
# 异常值剔除
# ============================================================

def median_abs_deviation(values):
    if not values:
        return 0.0
    med = statistics.median(values)
    abs_devs = [abs(x - med) for x in values]
    return statistics.median(abs_devs)


def remove_outliers(values, k=DEFAULT_MAD_K,
                    fallback_ratio=MAD_FALLBACK_RATIO,
                    fallback_stdev=MAD_FALLBACK_STDEV):
    """
    使用 Median + MAD 剔除异常值。
    返回 (clean_values, outliers)。
    """
    if len(values) < 4:
        return list(values), []

    med = statistics.median(values)
    mad = median_abs_deviation(values)

    outliers = []
    clean = []

    if mad > 0:
        threshold = k * mad
        for x in values:
            if abs(x - med) > threshold:
                outliers.append(x)
            else:
                clean.append(x)
    else:
        stdev = statistics.stdev(values) if len(values) > 1 else 0.0
        for x in values:
            too_far_ratio = abs(x - med) > fallback_ratio * abs(med) if med != 0 else False
            too_far_stdev = abs(x - med) > fallback_stdev * stdev if stdev > 0 else False
            if too_far_ratio or too_far_stdev:
                outliers.append(x)
            else:
                clean.append(x)

    if not clean:
        return list(values), []

    return clean, outliers


# ============================================================
# 统计
# ============================================================

def safe_mean(values):
    return round(statistics.mean(values), 6) if values else None


def safe_stdev(values):
    if len(values) > 1:
        return round(statistics.stdev(values), 6)
    return 0.0


def summarize_case(case_dir, case_name, mad_k=DEFAULT_MAD_K):
    logs = sorted(glob.glob(os.path.join(case_dir, "run_*.log")))
    if not logs:
        print(f"[WARN] no logs for {case_name}")
        return []

    case_data = {}
    for log in logs:
        data = parse_log(log)
        for k, v in data.items():
            if v is None:
                continue
            case_data.setdefault(k, []).append(v)

    rows = []
    for metric, values in case_data.items():
        numeric = [v for v in values if isinstance(v, (int, float))]
        if not numeric:
            continue

        clean, outliers = remove_outliers(numeric, k=mad_k)

        rows.append({
            "Case": case_name,
            "Metric": metric,
            "N_raw": len(numeric),
            "N": len(clean),
            "Outliers": len(outliers),
            "Mean": safe_mean(clean),
            "Stdev": safe_stdev(clean),
            "Min": round(min(clean), 6) if clean else None,
            "Max": round(max(clean), 6) if clean else None,
        })
    return rows


# ============================================================
# 输出
# ============================================================

def write_csv(rows, path):
    fieldnames = [
        "Case", "Metric", "N_raw", "N", "Outliers",
        "Mean", "Stdev", "Min", "Max"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Summary CSV written to: {path}")


def write_markdown(rows, path, mad_k=DEFAULT_MAD_K):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# TruePix Benchmark Summary (Outliers Removed)\n\n")
        f.write(
            f"> 异常值剔除规则：Median + MAD，K = {mad_k}；"
            "MAD = 0 时退化为 20% 中位数或 3 倍标准差。\n\n"
        )
        for case in CASES:
            case_rows = [r for r in rows if r["Case"] == case]
            if not case_rows:
                continue
            f.write(f"## {case}\n\n")
            f.write(
                "| Metric | N_raw | N | Outliers | Mean | Stdev | Min | Max |\n"
            )
            f.write("|---|---:|---:|---:|---:|---:|---:|---:|\n")
            for r in case_rows:
                f.write(
                    f"| {r['Metric']} | {r['N_raw']} | {r['N']} | {r['Outliers']} | "
                    f"{r['Mean']} | {r['Stdev']} | {r['Min']} | {r['Max']} |\n"
                )
            f.write("\n")
    print(f"Summary Markdown written to: {path}")


# ============================================================
# 主函数
# ============================================================

def find_latest_benchmark_dir():
    dirs = sorted(glob.glob("benchmark_*"))
    if not dirs:
        return None
    return dirs[-1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dir",
        type=str,
        default=None,
        help="benchmark 输出目录，默认自动选择最新的 benchmark_*"
    )
    parser.add_argument(
        "--k",
        type=float,
        default=DEFAULT_MAD_K,
        help=f"MAD 异常检测阈值，默认 {DEFAULT_MAD_K}"
    )
    args = parser.parse_args()

    mad_k = args.k

    if args.dir:
        outdir = args.dir
    else:
        outdir = find_latest_benchmark_dir()

    if not outdir or not os.path.isdir(outdir):
        print("[ERROR] 找不到 benchmark 目录，请用 --dir 指定")
        return

    print(f"Using benchmark dir: {outdir}")
    print(f"Outlier rule: Median + MAD, K = {mad_k}")

    all_rows = []
    for case in CASES:
        case_dir = os.path.join(outdir, case)
        if not os.path.isdir(case_dir):
            print(f"[WARN] missing case dir: {case_dir}")
            continue
        rows = summarize_case(case_dir, case, mad_k=mad_k)
        all_rows.extend(rows)

    if not all_rows:
        print("[ERROR] 没有提取到任何指标")
        return

    csv_path = os.path.join(outdir, "summary.csv")
    md_path = os.path.join(outdir, "summary.md")

    write_csv(all_rows, csv_path)
    write_markdown(all_rows, md_path, mad_k=mad_k)


if __name__ == "__main__":
    main()
