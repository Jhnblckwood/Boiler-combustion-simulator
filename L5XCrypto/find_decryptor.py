#!/usr/bin/env python3
# Run on your Windows machine:
#   python find_decryptor.py "C:\Program Files (x86)\Rockwell Software\Studio 5000\Logix Designer\ENU\v37\Bin"
#
# Finds the module that actually DECRYPTS EncryptionConfig=9: it must contain
# both the L5X source-protection markers AND real crypto implementation markers.
import os, sys

BIN = r"C:\Program Files (x86)\Rockwell Software\Studio 5000\Logix Designer\ENU\v37\Bin"
if len(sys.argv) > 1:
    BIN = sys.argv[1]

L5X = ["EncryptionConfig", "EncodedData", "EncodedSourceKey", "SourceProtectionType"]
CRYPTO = ["Rijndael", "RijndaelManaged", "SHA256", "SHA256Managed", "AesManaged",
          "System.Security.Cryptography", "CryptoStream", "TransformFinalBlock",
          "Decrypt", "keymatl", "InitializeArray"]

def enc(s):
    out = []
    try: out.append(s.encode("ascii"))
    except Exception: pass
    out.append(s.encode("utf-16-le"))
    return out

def count(data, s):
    return sum(data.count(b) for b in enc(s))

rows = []
for fn in os.listdir(BIN):
    if not fn.lower().endswith((".dll", ".exe")):
        continue
    p = os.path.join(BIN, fn)
    try:
        data = open(p, "rb").read()
    except Exception:
        continue
    managed = b"BSJB" in data           # .NET metadata root signature
    l5x = {m: count(data, m) for m in L5X if count(data, m)}
    cry = {m: count(data, m) for m in CRYPTO if count(data, m)}
    if l5x and cry:
        rows.append((fn, p, len(data), managed, l5x, cry))

IMPL = {"Rijndael", "RijndaelManaged", "SHA256", "SHA256Managed", "AesManaged",
        "CryptoStream", "TransformFinalBlock"}
def strength(r):
    _, _, _, managed, l5x, cry = r
    has_impl = any(k in cry for k in IMPL)
    has_sp = any(k in l5x for k in ("EncodedSourceKey", "SourceProtectionType"))
    return (has_impl, has_sp, managed, sum(cry.values()))

rows.sort(key=strength, reverse=True)
if not rows:
    print("No module has both L5X + crypto markers. Check the path argument.")
    sys.exit(0)

for fn, p, sz, managed, l5x, cry in rows:
    print(f"\n{p}  ({sz:,} bytes)  {'MANAGED .NET' if managed else 'native'}")
    print("   L5X:    " + ", ".join(f"{k}={v}" for k, v in l5x.items()))
    print("   crypto: " + ", ".join(f"{k}={v}" for k, v in cry.items()))

print("\n" + "=" * 60)
print("UPLOAD the top result (a MANAGED .NET one decompiles cleanest).")
print("=" * 60)
