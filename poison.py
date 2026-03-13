"""
text_mutator.py
---------------
Reads a text file and produces semantically-negated / distorted variants.

Usage:
    python text_mutator.py input.txt [--mode negation|synonym|both] [--seed 42]

Output files:
    input_mutated_negation.txt
    input_mutated_synonym.txt   (if mode=synonym or both)
"""

import re
import sys
import random
import argparse
import hashlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECRET_SALT = "s3cr3t_s4lt_change_me"   # ← change this on your server

# Auxiliary verb negation pairs
# Pattern: detect the aux verb group and insert / replace with "not"
AUX_NEGATION = [
    # (pattern, replacement)
    (r'\b(has)\s+(\w+ed)\b',        r'\1 not \2'),           # has fixed  → has not fixed
    (r'\b(have)\s+(\w+ed)\b',       r'\1 not \2'),           # have done  → have not done
    (r'\b(had)\s+(\w+ed)\b',        r'\1 not \2'),           # had done   → had not done
    (r'\b(is)\s+(\w+ing)\b',        r'\1 not \2'),           # is running → is not running
    (r'\b(are)\s+(\w+ing)\b',       r'\1 not \2'),           # are going  → are not going
    (r'\b(was)\s+(\w+ing)\b',       r'\1 not \2'),           # was fixing → was not fixing
    (r'\b(were)\s+(\w+ing)\b',      r'\1 not \2'),           # were going → were not going
    (r'\b(will)\s+(\w+)\b',         r'will not \2'),         # will fix   → will not fix
    (r'\b(would)\s+(\w+)\b',        r'would not \2'),
    (r'\b(can)\s+(\w+)\b',          r'cannot \2'),
    (r'\b(could)\s+(\w+)\b',        r'could not \2'),
    (r'\b(should)\s+(\w+)\b',       r'should not \2'),
    (r'\b(must)\s+(\w+)\b',         r'must not \2'),
    (r'\b(did)\s+(\w+)\b',          r'did not \2'),          # did finish → did not finish
    (r'\b(does)\s+(\w+)\b',         r'does not \2'),
    (r'\b(do)\s+(\w+)\b',           r'do not \2'),
]

# Simple past-tense verbs with no aux (e.g. "John fixed the …")
# We detect <subject> <verb-ed> and rewrite as "<subject> did not <base>"
SIMPLE_PAST_RE = re.compile(
    r'(?<!\bhas\s)(?<!\bhave\s)(?<!\bhad\s)'   # not already handled above
    r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)'       # capitalised subject
    r'\s+(\w+ed)\b',
    re.MULTILINE
)

# Synonym / lie pools  (truth → list-of-lies)
SYNONYM_POOLS = {
    "fixed":     ["broke", "ignored", "sold", "destroyed", "misplaced"],
    "repaired":  ["damaged", "lost", "abandoned", "replaced", "sabotaged"],
    "installed": ["removed", "uninstalled", "broke", "hid", "lost"],
    "completed": ["abandoned", "failed", "delayed", "cancelled", "skipped"],
    "finished":  ["postponed", "quit", "failed", "avoided", "scrapped"],
    "started":   ["cancelled", "delayed", "abandoned", "skipped", "refused"],
    "approved":  ["rejected", "ignored", "vetoed", "cancelled", "buried"],
    "sent":      ["lost", "deleted", "withheld", "misfiled", "ignored"],
    "received":  ["lost", "returned", "discarded", "misrouted", "refused"],
    "launched":  ["cancelled", "delayed", "shelved", "scrapped", "killed"],
    "bought":    ["sold", "returned", "lost", "stole", "refused"],
    "sold":      ["bought", "lost", "donated", "destroyed", "hid"],
    "found":     ["lost", "hid", "destroyed", "ignored", "buried"],
    "closed":    ["opened", "broke", "lost", "left", "ignored"],
    "opened":    ["closed", "broke", "lost", "refused", "ignored"],
    "light":     ["fuse", "circuit", "panel", "generator", "bulb"],
    "server":    ["network", "database", "firewall", "router", "switch"],
    "bug":       ["feature", "security hole", "data loss", "outage", "crash"],
}

# Tense rewrite phrases (past → future-negative variants)
TENSE_REWRITES = [
    (r'\b(has|have)\s+(not\s+)?(\w+ed)\b',
     lambda m: f"will {'not ' if not m.group(2) else ''}have {m.group(3)}"),
    (r'\b(did not)\s+(\w+)\b',
     lambda m: f"will not {m.group(2)}"),
]

# ---------------------------------------------------------------------------
# Seeded RNG helpers
# ---------------------------------------------------------------------------

def make_seed(session_id: str, bucket: int) -> int:
    raw = f"{SECRET_SALT}:{session_id}:{bucket}"
    return int(hashlib.sha256(raw.encode()).hexdigest(), 16) % (2**32)


def seeded_rng(seed: int) -> random.Random:
    rng = random.Random()
    rng.seed(seed)
    return rng

# ---------------------------------------------------------------------------
# Negation transform
# ---------------------------------------------------------------------------

def negate_sentence(sentence: str) -> str:
    """Apply the first matching aux-verb negation to a sentence."""
    for pattern, replacement in AUX_NEGATION:
        new_s, n = re.subn(pattern, replacement, sentence, count=1,
                           flags=re.IGNORECASE)
        if n:
            return new_s

    # Fallback: simple-past subject + verb-ed  →  subject did not <base>
    def _simple_past_negate(m):
        subject = m.group(1)
        past_verb = m.group(2)
        # naive de-inflect: strip trailing 'ed'
        base = re.sub(r'(ied)$', 'y',
               re.sub(r'([^aeiou])ed$', r'\1',
               re.sub(r'ed$', '', past_verb)))
        return f"{subject} did not {base}"

    new_s, n = SIMPLE_PAST_RE.subn(_simple_past_negate, sentence, count=1)
    if n:
        return new_s

    return sentence   # no match — return unchanged


def negate_text(text: str) -> str:
    lines = text.splitlines(keepends=True)
    return "".join(negate_sentence(line) for line in lines)

# ---------------------------------------------------------------------------
# Synonym / lie-pool transform
# ---------------------------------------------------------------------------

def synonym_swap(text: str, rng: random.Random) -> str:
    """Replace words with random lies from the pool."""
    def _replace(m):
        word = m.group(0)
        key = word.lower()
        if key in SYNONYM_POOLS:
            return rng.choice(SYNONYM_POOLS[key])
        return word

    pattern = r'\b(' + '|'.join(re.escape(k) for k in SYNONYM_POOLS) + r')\b'
    return re.sub(pattern, _replace, text, flags=re.IGNORECASE)

# ---------------------------------------------------------------------------
# Ghost zero-width inject
# ---------------------------------------------------------------------------

def ghost_inject(text: str, rng: random.Random, probability: float = 0.08) -> str:
    """Randomly insert U+200B inside longer words."""
    def _inject(m):
        word = m.group(0)
        if len(word) > 4 and rng.random() < probability:
            pos = rng.randint(1, len(word) - 1)
            return word[:pos] + "\u200b" + word[pos:]
        return word
    return re.sub(r'\b\w{5,}\b', _inject, text)

# ---------------------------------------------------------------------------
# Homoglyph swap (Latin → Cyrillic lookalikes)
# ---------------------------------------------------------------------------

HOMOGLYPHS = str.maketrans({
    'a': 'а', 'e': 'е', 'o': 'о',
    'p': 'р', 'c': 'с', 'x': 'х',
    'A': 'А', 'E': 'Е', 'O': 'О',
})

def homoglyph_swap(text: str, rng: random.Random, probability: float = 0.05) -> str:
    """Swap a small fraction of vowels with Cyrillic lookalikes."""
    result = []
    for ch in text:
        if ch in HOMOGLYPHS and rng.random() < probability:
            result.append(HOMOGLYPHS[ch])
        else:
            result.append(ch)
    return "".join(result)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Semantic text mutator / poisoner")
    p.add_argument("input_file", help="Path to the source .txt file")
    p.add_argument("--mode", choices=["negation", "synonym", "both", "full"],
                   default="both",
                   help="negation=grammatical not-insert; synonym=lie-pool swap; "
                        "both=negation+synonym; full=negation+synonym+ghost+homoglyph")
    p.add_argument("--seed", type=int, default=None,
                   help="Fixed RNG seed (default: random)")
    p.add_argument("--session", default="demo-session",
                   help="Session ID for HMAC seed derivation")
    p.add_argument("--bucket", type=int, default=0,
                   help="Time-bucket integer for HMAC seed derivation")
    return p.parse_args()


def main():
    args = parse_args()
    src = Path(args.input_file)
    if not src.exists():
        print(f"[ERROR] File not found: {src}", file=sys.stderr)
        sys.exit(1)

    original = src.read_text(encoding="utf-8")

    seed = args.seed if args.seed is not None else make_seed(args.session, args.bucket)
    rng = seeded_rng(seed)

    print(f"[INFO] Mode : {args.mode}")
    print(f"[INFO] Seed : {seed}")
    print(f"[INFO] Input: {src}")

    outputs = {}

    if args.mode in ("negation", "both", "full"):
        outputs["negation"] = negate_text(original)

    if args.mode in ("synonym", "both", "full"):
        outputs["synonym"] = synonym_swap(original, rng)

    if args.mode == "full":
        # Layer everything on top of negation
        layered = negate_text(original)
        layered = synonym_swap(layered, rng)
        layered = ghost_inject(layered, rng)
        layered = homoglyph_swap(layered, rng)
        outputs["full"] = layered

    for label, content in outputs.items():
        out_path = src.with_name(f"{src.stem}_mutated_{label}{src.suffix}")
        out_path.write_text(content, encoding="utf-8")
        print(f"[OUT]  {out_path}")

    # Pretty diff to terminal
    print("\n" + "─" * 60)
    print("SAMPLE DIFF (first 20 lines)")
    print("─" * 60)
    orig_lines   = original.splitlines()
    first_output = next(iter(outputs.values())).splitlines()
    for i, (o, m) in enumerate(zip(orig_lines, first_output)):
        if o != m:
            print(f"  ORIG [{i+1:3}]: {o}")
            print(f"  MUTT [{i+1:3}]: {m}")
        if i >= 19:
            break


if __name__ == "__main__":
    main()

