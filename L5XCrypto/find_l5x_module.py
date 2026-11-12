#!/usr/bin/env python3
# Run on your Windows machine:
#   python find_l5x_module.py
#   python find_l5x_module.py "C:\Program Files (x86)\Rockwell Software\Studio 5000\Logix Designer\ENU\v37\Bin"
#
# Finds which module contains the L5X EncryptionConfig=9 serializer by
# counting the XML marker strings it must emit (ASCII + UTF-16LE).
import os, sys

BIN = r"C:\Program Files (x86)\Rockwell Software\Studio 5000\Logix Designer\ENU\v37\Bin"
if len(sys.argv) > 1:
    BIN = sys.argv[1]

MARKERS = [
    "EncryptionConfig",
    "EncodedData",
    "EncodedType",
    "EncodedSourceKey",
    "SourceProtectionType",
    "RLLContent",
]

def variants(s):
    return [s.encode("ascii"), s.encode("utf-16-le")]

results = {}
for fn in os.listdir(BIN):
    if not fn.lower().endswith((".dll", ".exe")):
        continue
    p = os.path.join(BIN, fn)
    try:
        data = open(p, "rb").read()
    except Exception:
        continue
    counts = {}
    for m in MARKERS:
        c = sum(data.count(b) for b in variants(m))
        if c:
            counts[m] = c
    if counts:
        results[p] = counts

if not results:
    print("No L5X marker strings found. Check the path argument.")
    sys.exit(0)

def score(c):
    return (len(c), sum(c.values()))

ranked = sorted(results, key=lambda p: score(results[p]), reverse=True)
for p in ranked:
    print(f"\n{p}  ({os.path.getsize(p):,} bytes)")
    for m, c in sorted(results[p].items()):
        print(f"    {m:22s} {c}")

top = ranked[0]
print("\n" + "=" * 60)
print("UPLOAD THIS DLL to the session:")
print("   " + top)
print("=" * 60)
