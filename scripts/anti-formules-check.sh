#!/bin/bash
# anti-formules-check.sh — v1.2 (vendored verbatim from the Trustility governance reference)
# Governance: MUST run on any PUBLIC-FACING asset before push (README, SDK docs, marketing).
# A single FAIL blocks delivery.
# Usage : anti-formules-check.sh <file-or-dir>

TARGET="${1:-README.md}"
EXIT=0

echo "=== Catégorie 0 : Coverage / proof scope over-claim ==="
grep -inE "respects its policy|safe behavior|safe by design|your agent is safe|is verified|fully verified|cryptographic proof your agent (is|is safe)" "$TARGET" --include="*.md" -r && { echo "❌ Cat 0 FAIL"; EXIT=1; }

echo "=== Catégorie 1 : Subject confusion (P1 / TAP1) ==="
grep -inE "trustility verified mcp server|trustility certifies the runtime|trustility scans your code|trustility analyzes your agent" "$TARGET" --include="*.md" -r && { echo "❌ Cat 1 FAIL"; EXIT=1; }

echo "=== Catégorie 2 : Positioning confusion (P5 / TAP4) ==="
grep -inE "operating system of digital trust|trust layer is the os|trustility decides what|trustility = enforcement layer|trustility = the agent governance platform" "$TARGET" --include="*.md" -r && { echo "❌ Cat 2 FAIL"; EXIT=1; }

echo "=== Catégorie 3 : Raw data leakage (P1 / TAP3) ==="
grep -inE "trustility logs your pr content|trustility stores user prompts|trustility analyzes your agent.s outputs" "$TARGET" --include="*.md" -r && { echo "❌ Cat 3 FAIL"; EXIT=1; }

echo "=== Catégorie 4 : Compliance over-claim ==="
grep -inE "trustility certifies (ai act|soc2)|trustility makes your agent soc2 compliant|trustility-certified agent|phase 0 is eu ai act compliant|no soc2 needed" "$TARGET" --include="*.md" -r && { echo "❌ Cat 4 FAIL"; EXIT=1; }

echo "=== Catégorie 5 : Pricing premature anchor (P9) ==="
# Detect numeric prices without HYPOTHESIS tag nearby
grep -inE "(€|\\\$)[0-9]+(\\.[0-9]+)?(/mo(nth)?| per month)" "$TARGET" --include="*.md" -r | grep -ivE "hypothesis|to validate" && { echo "❌ Cat 5 FAIL — pricing chiffré sans HYPOTHESIS tag"; EXIT=1; }
grep -inE "(forever|permanent free at launch.*forever|free tier limited.*forever)" "$TARGET" --include="*.md" -r && { echo "❌ Cat 5 FAIL — forever commitment"; EXIT=1; }
grep -inE "lifetime (discount|50%|access|deal)|silver lifetime" "$TARGET" --include="*.md" -r && { echo "❌ Cat 5 FAIL — lifetime engagement"; EXIT=1; }

echo "=== Catégorie 6 : Founder team / social proof over-claim ==="
grep -inE "our engineering team|the team built|trustility is the leader|trustility is the standard" "$TARGET" --include="*.md" -r && { echo "❌ Cat 6 FAIL — team / leader claim"; EXIT=1; }
grep -inE "trusted by \[(10|n|[0-9]+)\]" "$TARGET" --include="*.md" -r && { echo "❌ Cat 6 FAIL — placeholder social proof"; EXIT=1; }
grep -inE "embedded in \[(n|[0-9]+)\]" "$TARGET" --include="*.md" -r && { echo "❌ Cat 6 FAIL — placeholder embed count"; EXIT=1; }

echo "=== Catégorie 7 : Competitor framing dangerous ==="
grep -inE "better than github advanced security|replaces soc2|snyk killer|galileo killer|langsmith killer" "$TARGET" --include="*.md" -r && { echo "❌ Cat 7 FAIL"; EXIT=1; }

echo "=== Catégorie 8 : Crypto over-claim (P2) ==="
grep -inE "proprietary cryptography|zero-knowledge proof of safety|quantum-resistant cryptography" "$TARGET" --include="*.md" -r && { echo "❌ Cat 8 FAIL"; EXIT=1; }

echo "=== Catégorie 9 : Agent autonomy over-claim (P5) ==="
grep -inE "trustility = ai agent|trustility autonomously decides" "$TARGET" --include="*.md" -r && { echo "❌ Cat 9 FAIL"; EXIT=1; }

echo "=== Catégorie 10 : C2C / network over-claim (P4 / TAP8) ==="
grep -inE "trustility est un réseau d.agents" "$TARGET" --include="*.md" -r | grep -ivE "phase 0\\.5" && { echo "❌ Cat 10 FAIL"; EXIT=1; }

echo "=== Catégorie 11 : Fake quantified market claims ==="
grep -inE "(cursor at \\\$3\\.4b valuation|cursor \\\$3\\.4b valuation|replit \\\$1\\.5m revenue par agents|70\\+ ai coding (agent )?startups funded)" "$TARGET" --include="*.md" -r | grep -ivE "techcrunch|source|\\(20[0-9]{2}" && { echo "❌ Cat 11 FAIL — quantified market claim sans source date+URL"; EXIT=1; }

echo "=== Catégorie 12 : Design partners / concierge implication ==="
grep -inE "design partners?|founding members?|first 10 (design partners?|cohort|founding|members?)|inner circle|cohort|concierge|book (15|30) ?min|schedule a call|founder direct line|reach out to me directly" "$TARGET" --include="*.md" -r | grep -ivE "(banned|interdit|anti-formule|v1\\.[12])" && { echo "❌ Cat 12 FAIL — terme banni v1.2 (design partners / cohort / concierge / call CTAs)"; EXIT=1; }

echo ""
if [ $EXIT -eq 0 ]; then
  echo "✅ ALL CHECKS PASS — asset OK for delivery"
else
  echo "❌ CHECKS FAIL — STOP delivery, correct violations"
fi
exit $EXIT
