#!/usr/bin/env python3
"""
REFEREE research aggregator — reproducible charts + tables for the talk/paper.

Consumes one or more DeepScan JSON reports (per-host) and/or a fleet JSON, and
regenerates every figure and summary table deterministically. No network, no
hidden state: point it at the report dir, get the same outputs every time.

Usage:
    python3 analyze.py --reports ../auditor/out --out ./figures
    python3 analyze.py --reports host1.json host2.json --out ./figures

Outputs (in --out):
    reachability_funnel.csv / .png   total -> flagged -> reachable -> low-tier
    category_risk.csv / .png         avg 3-axis score + reachable count per category
    axis_breakdown.csv               per-driver three-axis scores (full dataset)
    gap_matrix.csv                   capability x catalog quadrant counts
    summary.md                       headline numbers for the slides

matplotlib is optional; without it, CSV/MD still generate and PNGs are skipped.
"""
import argparse, json, glob, os, sys, csv
from collections import defaultdict, Counter

def load_reports(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += glob.glob(os.path.join(p, "*deepscan-*.json"))
        else:
            files.append(p)
    reports = []
    for f in sorted(set(files)):
        try:
            with open(f, encoding="utf-8-sig") as fh:
                reports.append(json.load(fh))
        except Exception as e:
            print(f"  skip {f}: {e}", file=sys.stderr)
    return reports

def write_csv(path, rows, header):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(header)
        for r in rows: w.writerow(r)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", nargs="+", required=True)
    ap.add_argument("--out", default="./figures")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    reps = load_reports(args.reports)
    if not reps:
        print("No DeepScan reports found.", file=sys.stderr); sys.exit(1)
    print(f"Loaded {len(reps)} report(s)")

    # Flatten all findings, tagged by host
    findings = []
    for r in reps:
        for f in r.get("findings", []):
            f = dict(f); f["_host"] = r.get("host"); findings.append(f)

    # ---- Reachability funnel (aggregate across hosts) ----
    total = sum(r.get("total_drivers", 0) for r in reps)
    flagged = len(findings)
    reachable = sum(1 for f in findings if f.get("acl_status") == "USER_REACHABLE")
    low_tier = sum(1 for f in findings if f.get("reach_tier") == "LOW")
    funnel = [("Total drivers", total), ("Flagged (signals)", flagged),
              ("User-reachable", reachable), ("LOW-tier (sandbox)", low_tier)]
    write_csv(os.path.join(args.out, "reachability_funnel.csv"),
              funnel, ["stage", "count"])

    # ---- Category risk ----
    by_cat = defaultdict(list)
    for f in findings: by_cat[f.get("category", "?")].append(f)
    cat_rows = []
    for cat, fs in by_cat.items():
        avg = round(sum(x.get("total_score", 0) for x in fs) / len(fs), 1)
        reach = sum(1 for x in fs if x.get("acl_status") == "USER_REACHABLE")
        cat_rows.append((cat, len(fs), avg, reach))
    cat_rows.sort(key=lambda x: x[2], reverse=True)
    write_csv(os.path.join(args.out, "category_risk.csv"),
              cat_rows, ["category", "count", "avg_score", "user_reachable"])

    # ---- Full axis breakdown ----
    axis_rows = [(f.get("_host"), f.get("driver"), f.get("category"),
                  f.get("cap_score"), f.get("reach_score"), f.get("vuln_score"),
                  f.get("total_score"), f.get("exposure_score"),
                  f.get("acl_status"), f.get("reach_tier"), f.get("risk_level"),
                  f.get("lol_match")) for f in findings]
    write_csv(os.path.join(args.out, "axis_breakdown.csv"), axis_rows,
              ["host","driver","category","cap","reach","vuln","total",
               "exposure","reachable","tier","risk","lol"])

    # ---- Gap matrix (capability x catalog) ----
    def hc(f): return (f.get("cap_score", 0) or 0) >= 10
    def rch(f): return f.get("acl_status") == "USER_REACHABLE"
    def lol(f): return bool(f.get("lol_match"))
    gap        = sum(1 for f in findings if rch(f) and hc(f) and not lol(f))
    overlap    = sum(1 for f in findings if rch(f) and lol(f))
    cat_restr  = sum(1 for f in findings if lol(f) and not rch(f))
    write_csv(os.path.join(args.out, "gap_matrix.csv"),
              [("reachable_highcap_uncatalogued", gap),
               ("reachable_catalogued", overlap),
               ("catalogued_restricted", cat_restr)],
              ["quadrant", "count"])

    # ---- Summary.md ----
    risk_counts = Counter(f.get("risk_level") for f in findings)
    with open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write("# REFEREE Research Summary\n\n")
        fh.write(f"- Hosts analyzed: **{len(reps)}** "
                 f"({', '.join(r.get('host','?') for r in reps)})\n")
        fh.write(f"- Total drivers scanned: **{total}**\n")
        fh.write(f"- Flagged (risk signals): **{flagged}**\n")
        fh.write(f"- User-reachable: **{reachable}** "
                 f"({reachable*100//max(flagged,1)}% of flagged)\n")
        fh.write(f"- LOW-tier (sandbox-reachable): **{low_tier}**\n")
        fh.write(f"- CRITICAL/HIGH: **{risk_counts.get('CRITICAL',0)+risk_counts.get('HIGH',0)}**\n\n")
        fh.write("## Gap analysis (REFEREE's unique value)\n")
        fh.write(f"- Reachable + high-cap + **uncatalogued**: **{gap}**\n")
        fh.write(f"- Reachable + catalogued (known): {overlap}\n")
        fh.write(f"- Catalogued but restricted (catalog over-triage): {cat_restr}\n\n")
        fh.write("## Riskiest categories (by avg 3-axis score)\n\n")
        fh.write("| Category | Count | Avg | Reachable |\n|---|---|---|---|\n")
        for cat, n, avg, reach in cat_rows[:10]:
            fh.write(f"| {cat} | {n} | {avg} | {reach} |\n")

    # ---- Charts (optional) ----
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        C = {"bg":"#0b0e14","fg":"#e6edf6","accent":"#4da3ff","crit":"#ff4d5e"}

        # Funnel
        fig, ax = plt.subplots(figsize=(7,4), facecolor=C["bg"])
        ax.set_facecolor(C["bg"])
        labels=[x[0] for x in funnel]; vals=[x[1] for x in funnel]
        bars=ax.barh(range(len(vals)), vals, color=[C["accent"],C["accent"],C["crit"],C["crit"]])
        ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, color=C["fg"])
        ax.invert_yaxis()
        for b,v in zip(bars,vals): ax.text(v, b.get_y()+b.get_height()/2, f" {v}", va="center", color=C["fg"])
        ax.set_title("Reachability funnel", color=C["fg"])
        ax.tick_params(colors=C["fg"]); [s.set_color("#232c3d") for s in ax.spines.values()]
        fig.tight_layout(); fig.savefig(os.path.join(args.out,"reachability_funnel.png"), dpi=140, facecolor=C["bg"])

        # Category risk
        fig, ax = plt.subplots(figsize=(8,5), facecolor=C["bg"])
        ax.set_facecolor(C["bg"])
        top=cat_rows[:10]
        ax.barh([c[0] for c in top], [c[2] for c in top], color=C["accent"])
        ax.invert_yaxis(); ax.set_xlabel("avg 3-axis score", color=C["fg"])
        ax.set_title("Risk by driver category", color=C["fg"])
        ax.tick_params(colors=C["fg"]); [s.set_color("#232c3d") for s in ax.spines.values()]
        fig.tight_layout(); fig.savefig(os.path.join(args.out,"category_risk.png"), dpi=140, facecolor=C["bg"])
        print("Charts written (matplotlib).")
    except ImportError:
        print("matplotlib not installed — CSV/MD only (pip install matplotlib for PNGs).")

    print(f"Done. Outputs in {args.out}")

if __name__ == "__main__":
    main()
