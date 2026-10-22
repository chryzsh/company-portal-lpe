#!/usr/bin/env python3
"""Look up Company Portal app names against the winget-stats NSIS database.

Usage:
    python3 nsis_lookup.py <search_term> [search_term ...]
    python3 nsis_lookup.py --top 30
    python3 nsis_lookup.py --file apps-output.txt
    cat apps-output.txt | python3 nsis_lookup.py --stdin

The --file and --stdin modes parse the output of CompanyPortalRecon's
apps or list commands and look up each app name automatically.

Examples:
    python3 nsis_lookup.py citrix zoom vlc 7zip notepad
    python3 nsis_lookup.py "Citrix Workspace"
    python3 nsis_lookup.py --file exe-output.txt
"""
import json
import os
import re
import sys

DB = os.path.join(os.path.dirname(__file__), "winget-stats", "public", "api", "installers.json")


def load():
    with open(DB) as f:
        return json.load(f)


def search(data, term):
    t = term.lower()
    return [
        x for x in data
        if x.get("detected") == "nsis"
        and x.get("cves")
        and (t in x.get("package", "").lower() or t in x.get("url", "").lower())
    ]


def _normalize(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())


def _match_exact(data, term, check_vendor):
    """Match term against vendor or product name exactly (normalized).

    Package format is Vendor.Product. Requires the normalized term
    to equal the normalized vendor or product portion, not just appear
    as a substring.
    """
    t = _normalize(term)
    if len(t) < 3:
        return []
    results = []
    for x in data:
        if x.get("detected") != "nsis" or not x.get("cves"):
            continue
        pkg = x.get("package", "")
        parts = pkg.rsplit(".", 1)
        product = _normalize(parts[-1])
        if t == product:
            results.append(x)
        elif check_vendor and len(parts) > 1 and t == _normalize(parts[0]):
            results.append(x)
    return results


def search_name(data, name):
    """Search by app display name with three tiers of matching.

    1. Multi-word full name: broad substring search (only for 2+ words,
       since single words like "Calendar" produce too many false positives).
    2. Product exact match: each word matched against the product portion.
    3. Vendor exact match: each word matched against the vendor portion.
    """
    words_raw = name.split()

    if len(words_raw) > 1:
        results = search(data, name)
        if results:
            return results

    skip = {"the", "for", "and", "app", "apps", "microsoft", "repair", "pro",
            "edition", "update", "pack", "extension", "extensions", "client",
            "desktop", "manual", "media", "player", "video", "studio",
            "direct", "generic", "cloud", "smart", "online", "digital",
            "service", "services", "workspace", "assist", "tune", "failed",
            "pages", "activities", "automate"}
    words = [w for w in words_raw if len(w) >= 3 and w.lower() not in skip]

    for word in words:
        results = _match_exact(data, word, check_vendor=False)
        if results:
            return results

    for word in words:
        results = _match_exact(data, word, check_vendor=True)
        if results:
            return results

    return []


def fmt(entry):
    pkg = entry.get("package", "?")
    ver = entry.get("nsis_version", "?")
    cves = entry.get("cves", [])
    arch = entry.get("architectures", "?")
    return f"  {pkg:45s} NSIS {ver:10s} {arch:6s} {', '.join(cves)}"


def top_targets(data, n=30):
    nsis = [x for x in data if x.get("detected") == "nsis" and x.get("cves")]
    by_pkg = {}
    for x in nsis:
        pkg = x.get("package", "?")
        if pkg not in by_pkg or len(x.get("cves", [])) > len(by_pkg[pkg].get("cves", [])):
            by_pkg[pkg] = x
    ranked = sorted(by_pkg.values(), key=lambda x: len(x.get("cves", [])), reverse=True)
    return ranked[:n]


def parse_apps_output(text):
    """Parse the output of CompanyPortalRecon apps or list commands.

    Handles both formats:
      apps:  '  1   <guid>   Name   Publisher'
      list:  '  1   Name   Type   InstallCmd'
    Also handles the --installed format with extra Intent/Status columns.
    """
    apps = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("[") or line.startswith("  #") or "---" in line:
            continue

        # apps command: #  GUID  [Intent]  [Status]  Name  Publisher
        m = re.match(
            r'\s+\d+\s+'
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\s+'
            r'(?:(?:Required|Available|Uninstall|None|\?)\s+)?'
            r'(?:(?:Installed|PendingInstall|ApprovedForInstall|Failed|)\s+)?'
            r'(.+?)(?:\s{2,}.+)?$',
            line, re.IGNORECASE
        )
        if m:
            name = m.group(1).strip().rstrip(".")
            if name and name != "?":
                apps.append(name)
            continue

        # list command: #  Name  Type  InstallCmd
        m2 = re.match(
            r'\s+\d+\s+'
            r'(.+?)\s{2,}'
            r'(?:msi|ps1|EXE/S|exe|cmd|)\s*',
            line
        )
        if m2:
            name = m2.group(1).strip().rstrip(".")
            if name and name != "?":
                apps.append(name)

    return apps


def main():
    data = load()

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "--top":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        print(f"Top {n} NSIS targets (most CVEs):\n")
        for e in top_targets(data, n):
            print(fmt(e))
        return

    if sys.argv[1] in ("--file", "--stdin"):
        if sys.argv[1] == "--file":
            if len(sys.argv) < 3:
                print("Usage: nsis_lookup.py --file <apps-output.txt>")
                sys.exit(1)
            with open(sys.argv[2]) as f:
                text = f.read()
        else:
            text = sys.stdin.read()

        apps = parse_apps_output(text)
        if not apps:
            print("[-] No app names found in input.")
            sys.exit(1)

        print(f"[*] Parsed {len(apps)} app name(s), checking NSIS database...\n")

        hits = 0
        for name in apps:
            results = search_name(data, name)
            if results:
                hits += 1
                seen = set()
                print(f"  {name}")
                for r in results:
                    key = r.get("package")
                    if key in seen:
                        continue
                    seen.add(key)
                    print(f"    -> {fmt(r).strip()}")
                print()

        if hits == 0:
            print("[*] No NSIS matches found.")
        else:
            print(f"[*] {hits} app(s) matched NSIS entries with CVEs.")
        return

    for term in sys.argv[1:]:
        results = search(data, term)
        if results:
            seen = set()
            print(f'\n"{term}" ({len(results)} match(es)):')
            for r in results:
                key = r.get("package")
                if key in seen:
                    continue
                seen.add(key)
                print(fmt(r))
        else:
            print(f'\n"{term}": no NSIS match')


if __name__ == "__main__":
    main()
