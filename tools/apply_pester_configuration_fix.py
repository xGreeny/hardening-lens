#!/usr/bin/env python3
"""Apply the Pester 5 filter configuration correction."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "build.ps1"
text = path.read_text(encoding="utf-8")
old = "    $configuration.Run.ExcludeTag = @('WindowsLive')\n"
new = "    $configuration.Filter.ExcludeTag = @('WindowsLive')\n"
if old not in text:
    raise RuntimeError("Expected Pester Run.ExcludeTag assignment was not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
print("Updated build.ps1 for the Pester 5 Filter configuration model.")
