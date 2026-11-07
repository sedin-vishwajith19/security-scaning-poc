#!/usr/bin/env bash
# scan-all-repos.sh
# Clones GitHub repos over SSH and scans their full git history with gitleaks.
#
# Repo list - choose ONE:
#   GH (recommended): run "gh auth login" once, then:
#        ./scan-all-repos.sh                 -> all repos you can access
#        ./scan-all-repos.sh my-org          -> only repos of "my-org"
#   A) Token (only used to LIST repos; cloning still uses your SSH key):
#        GITHUB_TOKEN=ghp_xxx ./scan-all-repos.sh            -> all repos you can access
#        GITHUB_TOKEN=ghp_xxx ./scan-all-repos.sh my-org     -> only repos of "my-org"
#   B) No token - your own list file (one "owner/repo" per line):
#        REPO_LIST=~/repos.txt ./scan-all-repos.sh

set -uo pipefail

ORG_FILTER="${1:-}"
WORKDIR="$HOME/gitleaks-scan"
CLONES="$WORKDIR/clones"
OUT="$WORKDIR/report-$(date +%Y%m%d-%H%M)"
RAW="$OUT/raw"
mkdir -p "$RAW" "$CLONES"
shopt -s nullglob

# Never hang waiting for a password/passphrase prompt inside the loop
export GIT_SSH_COMMAND="ssh -o BatchMode=yes"

# --- Pre-checks -------------------------------------------------------------
for cmd in git gitleaks jq curl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing tool: $cmd  ->  brew install $cmd"; exit 1; }
done

# --- Get repo list ----------------------------------------------------------
: > "$OUT/repos.tmp"
if [ -n "${REPO_LIST:-}" ]; then
  [ -f "$REPO_LIST" ] || { echo "REPO_LIST file not found: $REPO_LIST"; exit 1; }
  grep -Ev '^[[:space:]]*(#|$)' "$REPO_LIST" | tr -d ' \r' > "$OUT/repos.tmp"
elif [ -n "${GITHUB_TOKEN:-}" ]; then
  echo "Fetching repo list from GitHub API..."
  page=1
  while :; do
    resp=$(curl -fsS \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/user/repos?affiliation=owner,collaborator,organization_member&per_page=100&page=$page") \
      || { echo "GitHub API call failed - check the token"; exit 1; }
    [ "$(echo "$resp" | jq 'length')" -eq 0 ] && break
    echo "$resp" | jq -r '.[].full_name' >> "$OUT/repos.tmp"
    page=$((page + 1))
  done
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  echo "Fetching repo list with gh..."
  gh api --paginate "/user/repos?affiliation=owner,collaborator,organization_member&per_page=100" \
    --jq '.[].full_name' > "$OUT/repos.tmp" \
    || { echo "gh API call failed - run: gh auth status"; exit 1; }
else
  echo "No repo source found. Use one of:"
  echo "  gh auth login                      (recommended)"
  echo "  REPO_LIST=path/to/file ./scan-all-repos.sh"
  echo "  GITHUB_TOKEN=... ./scan-all-repos.sh"
  exit 1
fi

sort -u "$OUT/repos.tmp" > "$OUT/repos.txt"
rm -f "$OUT/repos.tmp"

if [ -n "$ORG_FILTER" ]; then
  grep -i "^$ORG_FILTER/" "$OUT/repos.txt" > "$OUT/repos.tmp" || true
  mv "$OUT/repos.tmp" "$OUT/repos.txt"
fi

TOTAL=$(wc -l < "$OUT/repos.txt" | tr -d ' ')
[ "$TOTAL" -eq 0 ] && { echo "No repos found."; exit 0; }
echo "Repos to scan: $TOTAL"

: > "$OUT/failed.txt"
: > "$OUT/counts.txt"

# --- Clone/update (SSH) + scan each repo -----------------------------------
i=0
while IFS= read -r repo <&3; do
  i=$((i + 1))
  name="${repo//\//__}"
  dir="$CLONES/$name"
  report="$RAW/$name.json"
  echo "[$i/$TOTAL] $repo"

  if [ -d "$dir/.git" ]; then
    git -C "$dir" fetch --quiet --all --prune 2>/dev/null \
      || { echo "$repo  (fetch failed)" >> "$OUT/failed.txt"; continue; }
  else
    # --no-checkout: full history, but no working files on disk (faster, smaller)
    git clone --quiet --no-checkout "git@github.com:$repo.git" "$dir" 2>/dev/null \
      || { echo "$repo  (clone failed - no access or wrong name)" >> "$OUT/failed.txt"; continue; }
  fi

  if gitleaks git "$dir" --redact --no-banner --exit-code 0 \
       --report-format json --report-path "$report" >/dev/null 2>&1; then
    n=$(jq 'length' "$report" 2>/dev/null || echo 0)
    [ "$n" -gt 0 ] && echo "$n $repo" >> "$OUT/counts.txt"
  else
    echo "$repo  (scan failed - maybe empty repo)" >> "$OUT/failed.txt"
  fi
done 3< "$OUT/repos.txt"

# --- Build findings.csv -----------------------------------------------------
CSV="$OUT/findings.csv"
echo "Repo,Rule,File,Line,Commit,Author,Date,Link,Fingerprint" > "$CSV"
for f in "$RAW"/*.json; do
  repo=$(basename "$f" .json | sed 's/__/\//')
  jq -r --arg repo "$repo" '.[] | [
      $repo, .RuleID, .File, .StartLine, .Commit[0:8], .Author, .Date[0:10],
      "https://github.com/\($repo)/blob/\(.Commit)/\(.File)#L\(.StartLine)",
      .Fingerprint
    ] | @csv' "$f" >> "$CSV"
done

# --- Build summary.txt ------------------------------------------------------
FINDINGS=$(( $(wc -l < "$CSV") - 1 ))
REPOS_WITH_LEAKS=$(wc -l < "$OUT/counts.txt" | tr -d ' ')
FAILED=$(wc -l < "$OUT/failed.txt" | tr -d ' ')
SUM="$OUT/summary.txt"
{
  echo "GITLEAKS SCAN SUMMARY - $(date '+%Y-%m-%d %H:%M')"
  echo "-------------------------------------------"
  echo "Repos scanned     : $TOTAL"
  echo "Repos with leaks  : $REPOS_WITH_LEAKS"
  echo "Total findings    : $FINDINGS"
  echo "Repos failed      : $FAILED"
  echo
  if [ "$FINDINGS" -gt 0 ]; then
    echo "Findings per repo:"
    sort -rn "$OUT/counts.txt" | awk '{printf "  %-5s %s\n", $1, $2}'
    echo
    echo "Findings by secret type:"
    files=("$RAW"/*.json)
    jq -r '.[].RuleID' "${files[@]}" | sort | uniq -c | sort -rn | awk '{printf "  %-5s %s\n", $1, $2}'
    echo
  fi
  if [ "$FAILED" -gt 0 ]; then
    echo "Failed repos:"
    sed 's/^/  /' "$OUT/failed.txt"
    echo
  fi
  echo "Details: $CSV"
} > "$SUM"

rm -f "$OUT/counts.txt"
echo
cat "$SUM"
