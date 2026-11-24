"""
Minimal Arabic text preparation for PDF output (no extra packages).

  visual(text) -> string ready to draw left-to-right with a font that has
                  Arabic Presentation Forms (e.g. DejaVu Sans).

It (1) picks the joined letter form for each Arabic letter, including the
lam-alef ligatures, and (2) reorders a line for right-to-left display while
keeping Latin words, numbers, emails and URLs readable left-to-right.
Call it on one already-wrapped line at a time.
"""

# letter: (isolated, final, initial, medial); 2-tuple = joins on the right only
FORMS = {
    "ء": (0xFE80,), "آ": (0xFE81, 0xFE82), "أ": (0xFE83, 0xFE84), "ؤ": (0xFE85, 0xFE86),
    "إ": (0xFE87, 0xFE88), "ئ": (0xFE89, 0xFE8A, 0xFE8B, 0xFE8C), "ا": (0xFE8D, 0xFE8E),
    "ب": (0xFE8F, 0xFE90, 0xFE91, 0xFE92), "ة": (0xFE93, 0xFE94),
    "ت": (0xFE95, 0xFE96, 0xFE97, 0xFE98), "ث": (0xFE99, 0xFE9A, 0xFE9B, 0xFE9C),
    "ج": (0xFE9D, 0xFE9E, 0xFE9F, 0xFEA0), "ح": (0xFEA1, 0xFEA2, 0xFEA3, 0xFEA4),
    "خ": (0xFEA5, 0xFEA6, 0xFEA7, 0xFEA8), "د": (0xFEA9, 0xFEAA), "ذ": (0xFEAB, 0xFEAC),
    "ر": (0xFEAD, 0xFEAE), "ز": (0xFEAF, 0xFEB0), "س": (0xFEB1, 0xFEB2, 0xFEB3, 0xFEB4),
    "ش": (0xFEB5, 0xFEB6, 0xFEB7, 0xFEB8), "ص": (0xFEB9, 0xFEBA, 0xFEBB, 0xFEBC),
    "ض": (0xFEBD, 0xFEBE, 0xFEBF, 0xFEC0), "ط": (0xFEC1, 0xFEC2, 0xFEC3, 0xFEC4),
    "ظ": (0xFEC5, 0xFEC6, 0xFEC7, 0xFEC8), "ع": (0xFEC9, 0xFECA, 0xFECB, 0xFECC),
    "غ": (0xFECD, 0xFECE, 0xFECF, 0xFED0), "ف": (0xFED1, 0xFED2, 0xFED3, 0xFED4),
    "ق": (0xFED5, 0xFED6, 0xFED7, 0xFED8), "ك": (0xFED9, 0xFEDA, 0xFEDB, 0xFEDC),
    "ل": (0xFEDD, 0xFEDE, 0xFEDF, 0xFEE0), "م": (0xFEE1, 0xFEE2, 0xFEE3, 0xFEE4),
    "ن": (0xFEE5, 0xFEE6, 0xFEE7, 0xFEE8), "ه": (0xFEE9, 0xFEEA, 0xFEEB, 0xFEEC),
    "و": (0xFEED, 0xFEEE), "ى": (0xFEEF, 0xFEF0), "ي": (0xFEF1, 0xFEF2, 0xFEF3, 0xFEF4),
}
LAM_ALEF = {"ا": (0xFEFB, 0xFEFC), "أ": (0xFEF7, 0xFEF8), "إ": (0xFEF9, 0xFEFA), "آ": (0xFEF5, 0xFEF6)}
HARAKAT = {chr(c) for c in range(0x064B, 0x0653)}
MIRROR = {"(": ")", ")": "(", "[": "]", "]": "[", "«": "»", "»": "«"}


def _is_ar(ch):
    o = ord(ch)
    return 0x0600 <= o <= 0x06FF or 0xFB50 <= o <= 0xFDFF or 0xFE70 <= o <= 0xFEFF


def _joins_left(ch):          # can connect to the following letter
    f = FORMS.get(ch)
    return bool(f) and len(f) == 4


def shape(text):
    s = [c for c in text if c not in HARAKAT]
    out, i = [], 0
    while i < len(s):
        ch = s[i]
        if ch not in FORMS:
            out.append(ch); i += 1; continue
        prev_joins = i > 0 and _joins_left(s[i - 1])
        if ch == "ل" and i + 1 < len(s) and s[i + 1] in LAM_ALEF:
            iso, fin = LAM_ALEF[s[i + 1]]
            out.append(chr(fin if prev_joins else iso)); i += 2; continue
        f = FORMS[ch]
        next_is_letter = i + 1 < len(s) and s[i + 1] in FORMS
        if len(f) == 1:
            out.append(chr(f[0]))
        elif len(f) == 2:
            out.append(chr(f[1] if prev_joins else f[0]))
        else:
            if prev_joins and next_is_letter:
                out.append(chr(f[3]))
            elif prev_joins:
                out.append(chr(f[1]))
            elif next_is_letter:
                out.append(chr(f[2]))
            else:
                out.append(chr(f[0]))
        i += 1
    return "".join(out)


def _kind(ch):
    if _is_ar(ch):
        return "R"
    if ch.isalnum():
        return "L"
    return "N"


def visual(line):
    """Logical-order line -> left-to-right drawing order (RTL paragraph)."""
    s = shape(line)
    kinds = [_kind(c) for c in s]
    # neutrals take the direction of their surroundings when both sides agree, else RTL
    for i, k in enumerate(kinds):
        if k != "N":
            continue
        prev = next((kinds[j] for j in range(i - 1, -1, -1) if kinds[j] != "N"), "R")
        nxt = next((kinds[j] for j in range(i + 1, len(kinds)) if kinds[j] != "N"), "R")
        if s[i] == "+" and nxt == "L":
            prev = "L"
        kinds[i] = "L" if prev == nxt == "L" else "R"
    runs, cur, cur_k = [], "", None
    for ch, k in zip(s, kinds):
        if k != cur_k and cur:
            runs.append((cur_k, cur)); cur = ""
        cur, cur_k = cur + ch, k
    if cur:
        runs.append((cur_k, cur))
    out = []
    for k, txt in reversed(runs):
        out.append("".join(MIRROR.get(c, c) for c in reversed(txt)) if k == "R" else txt)
    return "".join(out)
