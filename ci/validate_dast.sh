#!/usr/bin/env bash
set -euo pipefail

ZAP_JSON=${1:-zap_report.json}
FAIL_RISK=${2:-2}

risk_to_val() {
  case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
    high) echo 3 ;;
    medium) echo 2 ;;
    low) echo 1 ;;
    informational) echo 0 ;;
    *) echo 0 ;;
  esac
}

maxrisk=0
if [ -f "$ZAP_JSON" ]; then
  jq -r '.site[].alerts[].risk' "$ZAP_JSON" 2>/dev/null | while read -r risk; do
    val=$(risk_to_val "$risk")
    [ "$val" -gt "$maxrisk" ] && maxrisk=$val
  done
fi

echo "Max DAST risk: $maxrisk"
echo "Fail threshold: $FAIL_RISK"

if [ "$maxrisk" -ge "$FAIL_RISK" ]; then
  echo "❌ Found DAST risk ≥ threshold ($FAIL_RISK). Failing pipeline."
  exit 1
else
  echo "✅ DAST OK — No risks above threshold."
fi
