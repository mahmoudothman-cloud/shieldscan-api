#!/bin/bash
# ShieldScan Version Verification
# Run BEFORE any installation to confirm pinned versions are still current
# Usage: ./scripts/verify-versions.sh

set -e
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BOLD}ShieldScan Version Verification${NC}"
echo "==============================="
echo ""

# Helper: fetch latest GitHub release tag
gh_latest() {
    curl -s "https://api.github.com/repos/$1/releases/latest" | grep -Po '"tag_name": "\K[^"]+' || echo "unknown"
}

# Helper: compare versions and print result
compare() {
    local name=$1
    local pinned=$2
    local latest=$3

    if [ "$pinned" = "$latest" ]; then
        echo -e "  ${GREEN}✓${NC} $name: $pinned (current)"
    else
        echo -e "  ${YELLOW}!${NC} $name: pinned=$pinned, latest=$latest ${YELLOW}(review)${NC}"
    fi
}

echo "Checking core languages..."
PY_LATEST=$(curl -s 'https://www.python.org/api/v2/downloads/release/?is_published=true' | python3 -c "
import json, re, sys
data = json.load(sys.stdin)
# Keep only stable 3.13.x releases (exclude alphas, betas, rcs)
stable = [r for r in data if re.fullmatch(r'Python 3\.13\.\d+', r.get('name', ''))]
# Sort by release_date descending; pick newest
stable.sort(key=lambda r: r.get('release_date', ''), reverse=True)
print(stable[0]['name'].replace('Python ', '') if stable else 'unknown')
" 2>/dev/null || echo "unknown")
compare "Python" "3.13.13" "$PY_LATEST"

GO_LATEST=$(curl -s "https://go.dev/VERSION?m=text" | head -1 | sed 's/go//')
compare "Go" "1.26.10" "$GO_LATEST"

PG_LATEST=$(curl -s https://www.postgresql.org/versions.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
# Find the supported major line matching our pin (18.x), report full major.minor
match = next((e for e in data if e.get('supported') and e.get('major') == '18'), None)
print(f\"{match['major']}.{match['latestMinor']}\" if match else 'unknown')
" 2>/dev/null || echo "unknown")
compare "PostgreSQL" "18.3" "$PG_LATEST"

echo ""
echo "Checking security scanning tools..."

NUCLEI_LATEST=$(gh_latest "projectdiscovery/nuclei")
compare "Nuclei" "v3.7.1" "$NUCLEI_LATEST"

SUBFINDER_LATEST=$(gh_latest "projectdiscovery/subfinder")
compare "Subfinder" "v2.6.7" "$SUBFINDER_LATEST"

HTTPX_LATEST=$(gh_latest "projectdiscovery/httpx")
compare "httpx" "v1.6.10" "$HTTPX_LATEST"

GITLEAKS_LATEST=$(gh_latest "gitleaks/gitleaks")
compare "Gitleaks" "v8.21.2" "$GITLEAKS_LATEST"

MOBSF_LATEST=$(gh_latest "MobSF/Mobile-Security-Framework-MobSF")
compare "MobSF" "v4.4.6" "$MOBSF_LATEST"

TRIVY_LATEST=$(gh_latest "aquasecurity/trivy")
compare "Trivy" "v0.58.0" "$TRIVY_LATEST"

ZAP_LATEST=$(gh_latest "zaproxy/zaproxy")
compare "ZAP" "2.16.0" "$ZAP_LATEST"

echo ""
echo "Checking Python packages (PyPI)..."

check_pypi() {
    local name=$1
    local pinned=$2
    local latest=$(curl -s "https://pypi.org/pypi/$name/json" | python3 -c "import json,sys; print(json.load(sys.stdin)['info']['version'])" 2>/dev/null || echo "unknown")
    compare "$name" "$pinned" "$latest"
}

check_pypi "fastapi" "0.135.0"
check_pypi "sqlalchemy" "2.0.36"
check_pypi "pydantic" "2.9.0"
check_pypi "anthropic" "0.40.0"
check_pypi "semgrep" "1.95.0"
check_pypi "sslyze" "6.1.0"
check_pypi "checkov" "3.2.340"
check_pypi "wapiti3" "3.2.4"

echo ""
echo -e "${BOLD}Legend:${NC}"
echo -e "  ${GREEN}✓${NC} Version current — proceed with installation"
echo -e "  ${YELLOW}!${NC} Newer version available — see §4 Upgrade Decision Matrix in VERSIONS.md"
echo ""
echo "If any tool shows YELLOW, check the changelog before upgrading."
echo "Security patches in pinned versions should ALWAYS be applied."
