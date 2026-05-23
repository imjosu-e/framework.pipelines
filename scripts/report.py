#!/usr/bin/env python3
"""
Consolidates multiple SARIF files into a single Markdown report and JSON.
Usage: python report.py <directory-containing-sarifs>
"""
import sys
import json
import glob
import os
from datetime import datetime, timezone
from collections import defaultdict

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def extract_findings(sarif_path):
    findings = []
    with open(sarif_path) as f:
        data = json.load(f)
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid, {})
            # severity logic same as gate.py
            cvss = rule.get("properties", {}).get("security-severity")
            if cvss:
                v = float(cvss)
                sev = "CRITICAL" if v >= 9 else "HIGH" if v >= 7 else "MEDIUM" if v >= 4 else "LOW"
            else:
                level = res.get("level", "warning")
                sev = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "MEDIUM")
            # location
            locs = res.get("locations", [])
            location = ""
            if locs:
                pl = locs[0].get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                line = pl.get("region", {}).get("startLine", "")
                location = f"{uri}:{line}" if line else uri
            findings.append({
                "tool": tool,
                "rule": rid,
                "severity": sev,
                "message": res.get("message", {}).get("text", "")[:200],
                "location": location[:120],
            })
    return findings

def main():
    search_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    sarif_files = glob.glob(f"{search_dir}/**/*.sarif", recursive=True)
    all_findings = []
    for sf in sarif_files:
        all_findings.extend(extract_findings(sf))

    # deduplicate by (tool, rule, location)
    unique = {}
    for f in all_findings:
        key = (f["tool"], f["rule"], f["location"])
        if key not in unique:
            unique[key] = f
    findings = list(unique.values())
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))

    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    gate_pass = counts["CRITICAL"] == 0 and counts["HIGH"] == 0
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    run_url = f"https://github.com/{os.getenv('GITHUB_REPOSITORY','')}/actions/runs/{os.getenv('GITHUB_RUN_ID','')}"

    # Markdown report
    md_lines = [
        f"## {'✅' if gate_pass else '❌'} Security Report – {ts}",
        "",
        "| | |",
        "|---|---|",
        f"| Commit | `{os.getenv('GITHUB_SHA','')[:8]}` |",
        f"| Gate | {'PASSED' if gate_pass else 'FAILED — CRITICAL/HIGH findings present'} |",
        f"| Run | [View]({run_url}) |",
        "",
        "### Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| 🔴 CRITICAL | {counts.get('CRITICAL',0)} |",
        f"| 🟠 HIGH | {counts.get('HIGH',0)} |",
        f"| 🟡 MEDIUM | {counts.get('MEDIUM',0)} |",
        f"| 🔵 LOW | {counts.get('LOW',0)} |",
        "",
        "### Top 25 Findings",
        "",
        "| Sev | Tool | Rule | Location | Message |",
        "|---|---|---|---|---|",
    ]
    icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}
    for f in findings[:25]:
        md_lines.append(f"| {icons.get(f['severity'],'')} {f['severity']} | {f['tool']} | `{f['rule']}` | `{f['location']}` | {f['message'][:80]} |")
    if len(findings) > 25:
        md_lines.append(f"\n_...and {len(findings)-25} more – see report.json_")
    md_lines.append("\n> 📥 Download the **consolidated-security-report** artifact for full JSON.")

    with open("report.md", "w") as f:
        f.write("\n".join(md_lines))

    with open("report.json", "w") as f:
        json.dump({
            "scanned_at": ts,
            "gate_passed": gate_pass,
            "summary": dict(counts),
            "findings": findings
        }, f, indent=2)

    print(f"✅ Report generated: {len(findings)} findings. Gate: {'PASS' if gate_pass else 'FAIL'}")
    sys.exit(0)

if __name__ == "__main__":
    main()