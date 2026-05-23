#!/usr/bin/env python3
import sys, json, glob

def severity(result, rules):
    rid = result.get("ruleId","")
    cvss = rules.get(rid,{}).get("properties",{}).get("security-severity")
    if cvss:
        v = float(cvss)
        return "CRITICAL" if v>=9 else "HIGH" if v>=7 else "MEDIUM" if v>=4 else "LOW"
    level = result.get("level","warning")
    return {"error":"HIGH","warning":"MEDIUM","note":"LOW"}.get(level,"MEDIUM")

def main():
    fail = False
    for pattern in sys.argv[1:]:
        for path in glob.glob(pattern, recursive=True):
            with open(path) as f:
                data = json.load(f)
            for run in data.get("runs",[]):
                rules = {r["id"]:r for r in run.get("tool",{}).get("driver",{}).get("rules",[])}
                for res in run.get("results",[]):
                    sev = severity(res, rules)
                    if sev in ("CRITICAL","HIGH"):
                        print(f"❌ {sev}: {res.get('ruleId')} - {res.get('message',{}).get('text','')[:100]}")
                        fail = True
    sys.exit(1 if fail else 0)

if __name__ == "__main__":
    main()