#!/bin/sh
# Regenerates data/oui.txt from the IEEE MA-L registry.
# Format: 6 uppercase hex chars, tab, vendor name (trimmed).
set -e
cd "$(dirname "$0")/.."
curl -sSL https://standards-oui.ieee.org/oui/oui.csv \
  | python3 -c '
import csv, sys, re
rows = csv.reader(sys.stdin)
next(rows)
out = {}
for reg, prefix, name, _addr in rows:
    name = re.sub(r"\([^)]*\)", "", name)
    name = re.sub(r"\s+", " ", name).strip()
    suffix = r",?\s*(inc|ltd|llc|co|corp|corporation|company|gmbh|ag|sa|sas|s\.a\.|b\.v\.|bv|plc|pte|pvt|limited|corporate|technologies|technology|electronics|international)\.?$"
    for _ in range(3):
        name = re.sub(suffix, "", name, flags=re.I).strip(" ,.")
    if name.isupper() and len(name) > 4:
        name = name.title()
    if len(name) > 26:
        name = name[:26].rsplit(" ", 1)[0]
    out[prefix.upper()] = name
for k in sorted(out):
    print(f"{k}\t{out[k]}")
' > data/oui.txt
wc -l data/oui.txt
