#!/usr/bin/env python3
# Extract the EncryptionConfig=9 key material from Services.dll WITHOUT uploading it.
#
#   pip install pefile capstone
#   python find_keymatl.py "C:\Program Files (x86)\Rockwell Software\Studio 5000\Logix Designer\ENU\v37\Bin\Services.dll" > services_report.txt
#
# Then send back services_report.txt (it's small text — paste it or upload it).
import sys, re, binascii
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

path = sys.argv[1] if len(sys.argv) > 1 else "Services.dll"
pe = pefile.PE(path, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
ib = pe.OPTIONAL_HEADER.ImageBase
data = bytes(pe.__data__)
md = Cs(CS_ARCH_X86, CS_MODE_32)

secs = []
for s in pe.sections:
    secs.append((s.Name.rstrip(b'\0').decode(errors='replace'),
                 ib + s.VirtualAddress, s.Misc_VirtualSize,
                 s.PointerToRawData, s.SizeOfRawData))

def va2off(va):
    for n, va0, vs, ro, rs in secs:
        if va0 <= va < va0 + rs:
            return ro + (va - va0)
    return None

def off2va(off):
    for n, va0, vs, ro, rs in secs:
        if ro <= off < ro + rs:
            return va0 + (off - ro)
    return None

def read(va, n):
    o = va2off(va)
    return data[o:o + n] if o is not None else b''

print("FILE", path, "size", len(data), "ImageBase 0x%X" % ib)
for n, va0, vs, ro, rs in secs:
    print("SECTION %-8s VA=0x%08X vsize=0x%X raw=0x%08X rsize=0x%X" % (n, va0, vs, ro, rs))

data_lo = min((va0 for n, va0, vs, ro, rs in secs if n.lower() in ('.rdata', '.data')), default=0)
data_hi = max((va0 + vs for n, va0, vs, ro, rs in secs if n.lower() in ('.rdata', '.data')), default=0)
def is_dataptr(v): return data_lo <= v < data_hi

def find_all(sig):
    b = binascii.unhexlify(sig); out = []; i = 0
    while True:
        j = data.find(b, i)
        if j < 0: break
        out.append(j); i = j + 1
    return out

print("\n== CRYPTO CONSTANT TABLES ==")
for name, sig in [("SHA256_K", "982f8a4291443771cffbc0b5a5dbb5e9"),
                  ("SHA256_H", "67e6096a85ae67bb72f36e3c3af54fa5"),
                  ("AES_Sbox", "637c777bf26b6fc53001672bfed7ab76"),
                  ("AES_InvSbox", "52096ad53036a538bf40a39e81f3d7fb")]:
    for off in find_all(sig):
        print("  %-12s file=0x%08X VA=0x%08X" % (name, off, off2va(off) or 0))

print("\n== CRYPTO-ISH EXPORTS (name -> VA) ==")
rx = re.compile(r'(IPProtectionCrypto|keymat|SourceKey|Decrypt|Encrypt|SHA_?256|Rijndael|\bAES\b|Cipher|Digest|Derive|KeyStream|KeySchedule|\bSalt\b|Obfusc|Secret)', re.I)
crypto_exports = []
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name:
            nm = e.name.decode(errors='replace')
            if rx.search(nm):
                va = ib + e.address
                crypto_exports.append((va, nm))
    for va, nm in sorted(crypto_exports):
        print("  0x%08X  %s" % (va, nm[:160]))
    print("  (total crypto-ish exports: %d)" % len(crypto_exports))

def annotate_dataptrs(op_str, notes):
    for m in re.finditer(r'0x([0-9a-fA-F]{6,8})', op_str):
        v = int(m.group(1), 16)
        if is_dataptr(v) and v not in notes:
            b = read(v, 80)
            if b:
                notes[v] = b

def disasm_func(va, max_ins=160):
    off = va2off(va)
    if off is None: return
    code = data[off:off + max_ins * 8]
    notes = {}
    depth_ret = 0
    count = 0
    for ins in md.disasm(code, va):
        print("    0x%08X %-9s %s" % (ins.address, ins.mnemonic, ins.op_str))
        annotate_dataptrs(ins.op_str, notes)
        count += 1
        if ins.mnemonic == 'ret' or ins.mnemonic.startswith('ret'):
            break
        if count >= max_ins:
            break
    for v in sorted(notes):
        print("      DATA 0x%08X: %s" % (v, notes[v].hex()))

# Disassemble the crypto-ish exports (cap to keep report small)
print("\n== DISASSEMBLY OF CRYPTO-ISH EXPORTS ==")
for va, nm in sorted(crypto_exports)[:40]:
    print("\n  FUNC 0x%08X %s" % (va, nm[:140]))
    disasm_func(va, 140)

# keymatl candidate hunt: length immediates 63/79/16 near a static data pointer
print("\n== keymatl CANDIDATES (static ptr fed with length 63/79/16) ==")
text_secs = [(va0, ro, rs) for n, va0, vs, ro, rs in secs if n.lower().startswith('.text')]
patterns = []
for ln in (63, 79):
    patterns.append((ln, bytes([0x6A, ln])))                       # push imm8
    patterns.append((ln, bytes([0x68]) + ln.to_bytes(4, 'little'))) # push imm32
    for reg in range(8):
        patterns.append((ln, bytes([0xB8 + reg]) + ln.to_bytes(4, 'little')))  # mov r32, imm32
seen = set()
for va0, ro, rs in text_secs:
    code = data[ro:ro + rs]
    for ln, pat in patterns:
        i = 0
        while True:
            j = code.find(pat, i)
            if j < 0: break
            i = j + 1
            va = va0 + j
            start = max(0, j - 80)
            lastptr = None
            for ins in md.disasm(code[start:j + len(pat)], va0 + start):
                for m in re.finditer(r'0x([0-9a-fA-F]{6,8})', ins.op_str):
                    v = int(m.group(1), 16)
                    if is_dataptr(v):
                        lastptr = v
            if lastptr and (lastptr, ln) not in seen:
                seen.add((lastptr, ln))
                b = read(lastptr, max(ln, 79))
                core = b[:ln]
                # reject ASCII strings, zero runs, and pointer tables
                printable = sum(32 <= c < 127 for c in core)
                words = [int.from_bytes(b[k:k + 4], 'little') for k in range(0, ln - 3, 4)]
                ptrish = sum(1 for w in words if is_dataptr(w) or w == 0)
                if printable >= ln - 4: continue
                if not any(core): continue
                if words and ptrish > len(words) // 3: continue
                print("  len=%d  near 0x%08X  data=0x%08X : %s" % (ln, va, lastptr, b.hex()))
print("\n== END ==")
