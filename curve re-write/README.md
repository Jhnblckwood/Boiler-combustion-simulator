# Curve Re-Write

A single file, `Curve Editor.html` — drop in a Studio 5000 `.ACD` or `.L5K`,
the curve table reads out exactly like the other readers in this repo, and now
you can **Edit** the values and **Write Curve** to produce a new file with the
edits baked in.

No install, no server: everything runs in the browser, the same way the other
`Fuel Curve Reader.html` tools do. Reading is unchanged from
`fuel curve reader acd wt` — firetube (`ArrayMgmt_F*`) and water-tube
(`*Characterizer_*_Y`) programs, both fuels, `.ACD` and `.L5K`.

> This folder and `fuel curve reader acd wt` (read-only) are the two current
> tools. The older `curve script`, `curve script - multi-fuel` and
> `curve script - acd` folders each handle only one fuel and/or one boiler
> type, and are superseded by these.

## How editing works

1. Drop a file in. The table reads out as usual.
2. **Edit** — every cell that has a real underlying tag turns into a text
   box, pre-filled with its current value. Blank cells (no purge tag on the
   fuel valve, no O2 light-off, a dropped column) stay blank — there's nothing
   to write back to.
3. Type new values into whichever cells need to change. Only cells you
   actually touch are written; everything else is carried through byte-for-byte
   from the original file, untouched.
4. **O2 trim: On / Off** — flips O2 trim for the written file. The button
   shows the state the file will be written with, and turns green once that
   differs from what the file currently says. See
   [Toggling O2 trim](#toggling-o2-trim) below.
5. **Write Curve** — validates every edited cell is a real number (if any
   aren't, nothing is written and it tells you which), then downloads a new
   file named `<original name>_updated.<ext>`. **The original file is never
   modified** — the browser can't overwrite it even if it wanted to; it can
   only ever hand you a new file to save.
6. **Cancel** discards the edits and goes back to the read-only view.

## Toggling O2 trim

The toggle is offered **only when the file has a real stored O2 curve** —
turning trim on for a boiler with no commissioned curve would set it trimming
against nothing, so the button simply doesn't appear there (`bb1000_2` is an
example: no O2 curve, no toggle).

It writes one flag and nothing else. Curve values are untouched:

| | Flag written | Notes |
|---|---|---|
| Firetube | bit 3 of `DesiredO2`'s packed `Cfg` word | Every other bit in that word is preserved — only bit 3 is masked in or out. The per-fuel `ArrayMgmt_F*O2` records carry no separate enable bit (the config words after their curve copies are identical to the Air record's), so this one flag is the whole story. |
| Water tube | `OxygenTrimInStandby` | **Inverted** — enabling trim writes `0`. Written across the tag's full payload width, so it's right whether it's a `BOOL`, `INT`, `DINT` or `REAL`. |
| `.L5K` | the same packed `Cfg` literal, as text | Same bit, same word, just spliced into the text as a decimal. |

The note under the table updates to match what was written.

Toggling twice returns to the original state and reports "No changes to
write" rather than producing a pointless file, and Cancel discards a staged
toggle like any other edit.

## Before you trust the output

**Open every `_updated.ACD` in Studio 5000 and check it before it goes near a
live boiler.** This tool writes the file offline, with no way to ask Studio
5000 or a real controller "is this still valid" — the only real check is
opening it there. If Studio 5000 rejects the file or a value doesn't match
what you typed, treat that as a bug in this tool, not something to work around
by hand-patching the file.

Two write paths, two very different risk levels:

* **`.L5K` (text)** is a direct text edit — the new number is spliced into the
  exact character span the old one occupied, and nothing else in the file
  moves. Low risk; easy to eyeball in a diff if you want to double-check.

* **`.ACD` (binary)** is a real binary patch: the specific float32 bytes for
  each edited value are overwritten in the decompressed tag database, the
  database is re-compressed, and the file's internal directory (which stream
  starts where) is rebuilt around the new size. See **How the ACD write-back
  works** below for why this is safe *by construction* rather than by luck —
  but it's still a binary rewrite of a proprietary format, so verify the
  output.

## What's been tested

Every write path below was driven through an actual headless-browser run of
this exact HTML file — not just the underlying functions in isolation — and
the result was independently checked with the read-only Python reader in
`fuel curve reader acd wt/acd_reader.py`, which shares no code with the writer:

* **Water-tube `.ACD` write, single value** — one curve point edited,
  re-read, exactly that value changed, everything else byte-identical
  (including flags, point count, O2/fresh-air column gating).
* **Water-tube `.ACD` write, multiple values across both fuels** — same
  result, with the edited values' full float32 precision (e.g. `33.25`)
  confirmed intact, not truncated to the table's 1-decimal display.
* **`.L5K` write** — a curve point edited, the resulting text diffed
  line-for-line against the original: exactly one literal changed
  (`21.1` → `99.75`), whitespace and formatting elsewhere untouched.
* **Firetube `.ACD` write, three values across a curve point, a purge value,
  and a second column** — re-read, exactly those three values changed
  (including full float32 precision, e.g. `29.100000381469727`), everything
  else byte-identical. Confirmed directly that *both* copies of the "double
  curve" signature were patched (not just one, which would otherwise silently
  break that column on the next read).
* **O2 trim toggle, both boiler types** — trim flipped on, re-read, flag
  changed with every curve value byte-identical. Then flipped back off:
  the firetube `Cfg` word went `0 → 8 → 0`, i.e. restored exactly, proving
  only bit 3 was touched and no other config bit was disturbed. Water tube
  round-tripped the same way with its fresh-air flag untouched. The toggle
  correctly doesn't appear on a file with no O2 curve.
* **Curve edits and a trim toggle in one write** — both applied together, on
  `.ACD` (2 values + flag) and `.L5K` (1 value + the `Cfg` literal `[8]` →
  `[0]`, nothing else in the text moved).
* **O2 column edit** — the O2 column shows whenever a stored O2 curve has real
  values, even with trim disabled in config, so those values can be edited
  like any other. Two O2 points edited across both fuels came back exact, with
  the trim enable flag itself untouched. (O2 purge and light-off stay blank
  and non-editable, as they always have.)
* **Firetube `.ACD` write on an older Studio 5000 version (V20)** — the same
  project saved as V20 rather than V31: a different tag-name offset, a
  different record count, and four fewer streams in the container. Three
  values edited (a curve point, a light-off, and one in another column) came
  back exact, everything else unchanged. Nothing in the write path is
  version-specific — offsets come from the same walk the reader already does,
  and the container rebuild is generic over how many streams a file has.
* **No-op write** (nothing edited) reports "No changes to write." and writes
  nothing.
* **Invalid input** (a non-numeric value in an edited cell) aborts the whole
  write with no file produced — never a partially-written file.
* **Cancel** reverts every field to its original value with no write.

Testing the firetube path surfaced a real pre-existing **read** bug, unrelated
to writing: on a file where `DesiredO2`'s own curve happens to be all zero, the
reader's tag-value lookup (`value_rec` / `valueRec`) picked the *first*
reference a tag definition embedded rather than checking it was actually a
value record — silently returning garbage (blank curves, garbled fuel names)
instead of the real data. Fixed by requiring the `$hash$` naming convention the
water-tube path already checked for. This shipped as its own fix, everywhere
it existed across the repo (`curve script - acd`, `fuel curve reader acd wt`,
and this folder) — see that commit for the full account. The write-back logic
itself was never the problem; it just had nothing correct to read from until
this was fixed.

## How the ACD write-back works

An `.ACD` is a flat set of named streams (`Comps.Dat`, `TagInfo.XML`, …) laid
end-to-end, indexed by a trailing table of
`[name][compressed length][file offset]` — each stream's offset is just the
running total of every prior stream's length. Editing a curve value means:

1. Decompress `Comps.Dat` (gzip) once, on load.
2. Locate each cell's value the same way the reader already does, but also
   record the **byte offset** of that value inside the decompressed buffer
   (for firetube, both copies of the value — see below).
3. On Write Curve, patch only the edited offsets directly, in place.
4. Re-compress `Comps.Dat`. It won't be the same number of bytes as before —
   that's fine and expected; gzip's compressed size isn't a fixed target,
   only the decompressed content matters, and this **needs no output-file
   opener to be forgiving about anything** — a standard gzip encoder
   producing a standard gzip stream is unconditionally something the file's
   own decompressor (also standard gzip) can read.
5. Rebuild the trailing index table with every stream's offset recomputed
   from the new total. Every *other* stream's bytes are carried through
   completely untouched — nothing about them is re-interpreted or
   re-encoded, only where they sit in the file changes.

This was validated with a round-trip test before any editing code was
written: decompress `Comps.Dat`, recompress it unchanged (forcing a different
compressed length), rebuild the container, and confirm the independent Python
reader gets byte-identical output from the rebuilt file. It did — so the
container rebuild mechanics are sound independent of what value is actually
being changed.

**Firetube** curves are stored twice in the file — the same 16-float array
sits at one offset and again 64 bytes later (`FuelAirCurveData.Ref_Data` plus
a working copy); the read path (`_decode_array`) treats the two copies
matching as its signature for "this is really a curve." An edit therefore
writes the new value to *both* offsets, or that signature breaks and the next
read of the file would silently miss the column.

## Files

| File | Purpose |
|------|---------|
| `Curve Editor.html` | No-install reader + editor. `.ACD` + `.L5K`, firetube + water-tube. |

For the read-only version and the full breakdown of the tag formats
themselves (which tags, which offsets, why), see
`fuel curve reader acd wt/README.md` and `curve script - acd/README.md` — this
tool's reading logic is unchanged from those.
