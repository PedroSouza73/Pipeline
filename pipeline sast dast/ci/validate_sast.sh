#!/usr/bin/env bash
set -euo pipefail

SEMGREP_JSON=${1:-semgrep.json}
BANDIT_JSON=${2:-bandit.json}
FAIL_SEVERITY=${3:-HIGH}

severity_value() {
  case "$(echo "$1" | tr '[:lower:]' '[:upper:]')" in
    INFO|LOW) echo 1 ;;
    MEDIUM) echo 2 ;;
    HIGH) echo 3 ;;
    CRITICAL) echo 4 ;;
    *) echo 0 ;;
  esac
}

threshold_value=$(severity_value "$FAIL_SEVERITY")

semgrep_max=$(jq -r '.results[].extra.severity' "$SEMGREP_JSON" 2>/dev/null |   awk 'BEGIN{max=0} { v=($0=="CRITICAL"?4:($0=="HIGH"?3:($0=="MEDIUM"?2:($0=="LOW"?1:0)))); if(v>max){max=v} } END{print max}')

bandit_max=$(jq -r '.results[].issue_severity' "$BANDIT_JSON" 2>/dev/null |   awk 'BEGIN{max=0} { v=($0=="HIGH"?3:($0=="MEDIUM"?2:($0=="LOW"?1:0))); if(v>max){max=v} } END{print max}')

semgrep_max=${semgrep_max:-0}
bandit_max=${bandit_max:-0}

max_found=$(( semgrep_max > bandit_max ? semgrep_max : bandit_max ))

echo "Semgrep max severity: $semgrep_max"
echo "Bandit max severity: $bandit_max"
echo "Fail threshold (numeric): $threshold_value"

if [ "$max_found" -ge "$threshold_value" ]; then
  echo "❌ Vulnerability severity ≥ $FAIL_SEVERITY detected. Failing pipeline."
  exit 1
else
  echo "✅ SAST OK — No vulnerabilities above $FAIL_SEVERITY."
fi
