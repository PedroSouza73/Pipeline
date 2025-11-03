#!/usr/bin/env python3
import json, os
from datetime import datetime

def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None

def count_issues_semgrep(data):
    if not data:
        return {}
    levels = {"INFO":0,"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}
    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "INFO").upper()
        if sev in levels:
            levels[sev] += 1
    return levels

def count_issues_bandit(data):
    if not data:
        return {}
    levels = {"LOW":0,"MEDIUM":0,"HIGH":0}
    for r in data.get("results", []):
        sev = r.get("issue_severity", "LOW").upper()
        if sev in levels:
            levels[sev] += 1
    return levels

def count_issues_zap(data):
    if not data:
        return {}
    levels = {"Informational":0,"Low":0,"Medium":0,"High":0}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            sev = a.get("risk", "Informational").capitalize()
            if sev in levels:
                levels[sev] += 1
    return levels

def to_markdown(title, table_dict):
    rows = "\n".join([f"| {k} | {v} |" for k, v in table_dict.items()])
    return f"### {title}\n| Severidade | Ocorrências |\n|-------------|-------------|\n{rows}\n"

def main():
    semgrep = load_json("semgrep.json")
    bandit = load_json("bandit.json")
    zap = load_json("zap_report.json")

    semgrep_count = count_issues_semgrep(semgrep)
    bandit_count = count_issues_bandit(bandit)
    zap_count = count_issues_zap(zap)

    md = f"# 🛡️ Security Scan Summary\n_Gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n\n"
    md += to_markdown("Semgrep (SAST)", semgrep_count)
    md += "\n"
    md += to_markdown("Bandit (SAST)", bandit_count)
    md += "\n"
    md += to_markdown("OWASP ZAP (DAST)", zap_count)
    md += "\n\n✅ **Análise concluída com sucesso.** Verifique os arquivos `.json` e `.html` para detalhes.\n"

    with open("sast_summary.md", "w", encoding="utf-8") as f:
        f.write(md)

    html = md.replace("\n", "<br>").replace("|", "&nbsp;|&nbsp;")
    with open("sast_summary.html", "w", encoding="utf-8") as f:
        f.write(f"<html><body><pre>{html}</pre></body></html>")

if __name__ == "__main__":
    main()
