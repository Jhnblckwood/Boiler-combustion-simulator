#!/usr/bin/env python3
# Run on your Windows machine:  python find_crypto_dll.py
# Or pass one or more install paths:  python find_crypto_dll.py "C:\Path\To\Studio5000"
#
# Scans Studio 5000 / RSLogix install dirs for self-contained SHA-256 + AES
# constant tables, to locate the DLL that implements EncryptionConfig=9.
import os, sys

ROOTS = [
    r"C:\Program Files (x86)\Rockwell Software",
    r"C:\Program Files\Rockwell Automation",
    r"C:\Program Files (x86)\Rockwell Automation",
    r"C:\Program Files\Rockwell Software",
]
if len(sys.argv) > 1:
    ROOTS = sys.argv[1:]

# Distinctive signatures (first bytes of each table):
SIGS = {
    # SHA-256 K[0..3] stored little-endian 32-bit
    "SHA256_K (LE)": bytes.fromhex("982f8a4291443771cffbc0b5a5dbb5e9"),
    # SHA-256 K[0..3] big-endian
    "SHA256_K (BE)": bytes.fromhex("428a2f9871374491b5c0fbcfe9b5dba5"),
    # SHA-256 H init little-endian
    "SHA256_H (LE)": bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa5"),
    # AES forward S-box start
    "AES_Sbox":      bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
    # AES inverse S-box start
    "AES_InvSbox":   bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
    # Rijndael round constants (Rcon) common prefix
    "AES_Rcon":      bytes.fromhex("01020408102040801b366cd8ab4d9a2f"),
}

def scan(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return []
    hits = []
    for name, sig in SIGS.items():
        off = data.find(sig)
        if off != -1:
            hits.append((name, off))
    return hits

found = {}
for root in ROOTS:
    if not os.path.isdir(root):
        continue
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.lower().endswith((".dll", ".exe")):
                continue
            p = os.path.join(dirpath, fn)
            h = scan(p)
            if h:
                found[p] = h

if not found:
    print("No SHA-256/AES constant tables found in the scanned roots.")
    print('Pass the correct install path, e.g.:  python find_crypto_dll.py "C:\\Path\\To\\Studio5000"')
    sys.exit(0)

# Rank: files with BOTH a SHA256_* and an AES_* hit are the strongest candidates.
def score(hits):
    kinds = {n.split()[0].split("_")[0] for n, _ in hits}
    return ("SHA256" in kinds) + ("AES" in kinds), len(hits)

for p in sorted(found, key=lambda p: score(found[p]), reverse=True):
    sz = os.path.getsize(p)
    print(f"\n{p}  ({sz:,} bytes)")
    for name, off in found[p]:
        print(f"    {name:14s} @ 0x{off:08X}")
print("\nStrongest candidate = a DLL that shows BOTH a SHA256_* and an AES_* hit.")
print("Upload that DLL back to the session for disassembly.")
