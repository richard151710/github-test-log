# scan_hardcoded_secrets.py
import re
import os
from pathlib import Path

# patterns for secret-like variable names
NAME_PATTERNS = re.compile(r"(?:api[_-]?key|secret[_-]?key|secret|token|password|passwd|auth|bearer)", re.I)

# pattern to match simple assignment: NAME = "value" or NAME = 'value'
ASSIGN_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([rRuUbB]?["\']{1,3})(.*)\2\s*$')

def scan_file(path: Path):
    findings = []
    with path.open('r', encoding='utf-8', errors='ignore') as fh:
        for lineno, line in enumerate(fh, 1):
            m = ASSIGN_RE.match(line)
            if m:
                name = m.group(1)
                val = m.group(3)
                if NAME_PATTERNS.search(name) or (len(val) >= 16 and re.search(r"[A-Za-z0-9]", val) and re.search(r"\d", val)):
                    findings.append((lineno, name, val))
    return findings

def scan_dir(root="."):
    results = {}
    for p in Path(root).rglob("*.py"):
        res = scan_file(p)
        if res:
            results[str(p)] = res
    return results

if __name__ == "__main__":
    results = scan_dir(".")
    if not results:
        print("No obvious hardcoded secrets found.")
    else:
        for f, items in results.items():
            for lineno, name, val in items:
                hidden = val[:4] + "..." if len(val) > 10 else val
                print(f"{f}:{lineno}  {name} = \"{hidden}\"")
