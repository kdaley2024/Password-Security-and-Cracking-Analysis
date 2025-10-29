#!/usr/bin/env python3
"""
One tool to run:
  - dictionary attack (plaintext) using a text wordlist or JSON produced by dictionary.py
  - brute-force attack (plaintext) over a charset up to a given max length

Usage examples:
  # Dictionary attack using a text wordlist:
  python attack.py --mode dict --wordlist password_dictionary.txt --targets targets.csv

  # Dictionary attack using the JSON built by dictionary.py (case-insensitive + mangling):
  python attack.py --mode dict --json passwords.json --targets targets.csv --mangle --case-insensitive

  # Brute-force attack (lowercase+digits, max length 4):
  python attack.py --mode brute --charset lower,digits --max-len 4 --targets targets.csv

  # Brute-force attack with a custom charset string:
  python attack.py --mode brute --charset "abc123" --max-len 5 --targets targets.csv

Outputs:
  cracked.csv by default (username,found_password,candidate_rank,candidate_variant,transformation)

Notes:
 - Plaintext-only comparison (no hashing/salting).
 - Brute forcing can explode combinatorially; keep max length small unless you know what you're doing.
"""
from __future__ import annotations
import argparse
import csv
import json
import itertools
import string
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

# Beginner-friendly notes:
# - This script runs simple offline password attacks for learning and lab use.
# - Modes supported:
#   * dict: try candidates from a wordlist (text or JSON)
#   * brute: generate candidates from a charset up to a maximum length
# - The script expects a CSV of targets: username,password (plaintext).
# - Output is `cracked.csv` (username, found_password, candidate_rank, ...).
# - WARNING: This is plaintext-only and for educational use. Brute-force
#   can produce an enormous number of candidates very quickly.

# -------------------------
# Utility: load targets
# -------------------------
def load_targets(path: Path, case_insensitive: bool) -> Tuple[Dict[str, List[str]], int]:
    # Read targets CSV and return a mapping password -> [usernames]
    # and the total number of rows read. If `case_insensitive` is True
    # passwords are lowercased before being used as keys.
    pwd_to_users: Dict[str, List[str]] = {}
    total = 0
    with path.open(newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        first = next(reader, None)
        # We try to detect and skip a header row like "username,password".
        # If there's no header, the first row will be treated as data.
        if first and any(h.lower() in ("username", "user", "password", "pass") for h in first):
            # header detected -> do nothing with `first`
            pass
        else:
            # first row is data -> parse it and add to mapping
            if first and len(first) >= 2:
                u, p = first[0].strip(), first[1].strip()
                key = p.lower() if case_insensitive else p
                pwd_to_users.setdefault(key, []).append(u)
                total += 1
        for row in reader:
            if not row or len(row) < 2:
                continue
            u, p = row[0].strip(), row[1].strip()
            key = p.lower() if case_insensitive else p
            pwd_to_users.setdefault(key, []).append(u)
            total += 1
    return pwd_to_users, total

# -------------------------
# Dictionary candidate streams
# -------------------------
def stream_from_txt(path: Path) -> Iterable[str]:
    # Yield each non-empty line from a text wordlist file. Each yielded
    # value is a candidate base string (no transformations applied).
    with path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            cand = line.rstrip("\r\n")
            if cand:
                yield cand

def stream_from_json(path: Path) -> Iterable[str]:
    # Yield keys from a JSON dictionary produced by dictionary.py. The
    # JSON is expected to be an object mapping password->metadata; we
    # iterate keys (candidate bases) in insertion order.
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    for k in data.keys():
        yield k

# -------------------------
# Simple mangling variants
# -------------------------
# replace the broken maketrans line with this
LEET_MAP = str.maketrans({
    'a': '4', 'o': '0', 'e': '3', 'i': '1', 'l': '1', 's': '5',
    'A': '4', 'O': '0', 'E': '3', 'I': '1', 'L': '1', 'S': '5'
})

def gen_variants(base: str, mangle: bool) -> Iterable[Tuple[str,str]]:
    """Yield (variant, transformation_name). Always yields original first."""
    yield (base, "orig")
    if not mangle:
        return
    # capitalization
    if base:
        yield (base.capitalize(), "capitalize")
        yield (base.upper(), "upper")
    # basic leet
    leet = base.translate(LEET_MAP)
    if leet != base:
        yield (leet, "leet")
    # append common suffixes
    for suf in ("1","123","!", "2023"):
        yield (base + suf, f"append:{suf}")
        yield (base.capitalize() + suf, f"cap+append:{suf}")

# gen_variants: given a base candidate (from wordlist or charset) this
# yields small "mangling" variants like capitalization, simple leet
# replacements, and common suffixes. Each yielded item is a tuple of
# (candidate_variant, transformation_name) so we can record how it was
# derived when a password is cracked.

# -------------------------
# Dictionary attack runner
# -------------------------
def dict_attack(candidate_iter: Iterable[str],
                pwd_to_users: Dict[str, List[str]],
                case_insensitive: bool,
                mangle: bool,
                stop_when_all_cracked: bool,
                progress_every: int = 50000) -> List[Tuple[str,str,int,str,str]]:
    # candidate_iter provides base words (e.g., from a wordlist). We
    # apply optional mangling to generate variants and check each
    # variant against the loaded target password mapping. When we find a
    # match we record (username, found_variant, rank, candidate_variant,
    # transformation) so we can write useful output later.
    cracked = []
    remaining = set(pwd_to_users.keys())
    rank = 0
    for base in candidate_iter:
        rank += 1
        for variant, trans in gen_variants(base, mangle):
            check = variant.lower() if case_insensitive else variant
            if check in pwd_to_users:
                users = pwd_to_users[check]
                for u in users:
                    # (username, found_password, candidate_rank, candidate_variant, transformation)
                    cracked.append((u, variant, rank, variant, trans))
                # remove this password key so we don't report it again
                pwd_to_users.pop(check, None)
                remaining.discard(check)
        if rank % progress_every == 0:
            print(f"[+] scanned {rank} base candidates — remaining unique passwords: {len(remaining)}", file=sys.stderr)
        if stop_when_all_cracked and not remaining:
            print(f"[+] all targets cracked after scanning {rank} base candidates", file=sys.stderr)
            return cracked
    return cracked

# -------------------------
# Brute-force generator & runner
# -------------------------
CHARSET_PRESETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "letters": string.ascii_letters,
    "alnum": string.ascii_letters + string.digits,
    "ascii_printable": string.ascii_letters + string.digits + string.punctuation,
}

def build_charset(spec: str) -> str:
    """
    Spec can be:
      - comma-separated presets like "lower,digits"
      - or a literal charset string (no commas) like "abc123"
    """
    # Build a literal charset string from a specification. The spec can be
    # a comma-separated list of presets (like "lower,digits") or a single
    # literal string of characters to use.
    if "," in spec:
        pieces = [s.strip() for s in spec.split(",") if s.strip()]
        out = []
        for p in pieces:
            if p in CHARSET_PRESETS:
                out.append(CHARSET_PRESETS[p])
            else:
                # treat as literal characters
                out.append(p)
        return "".join(out)
    else:
        # single token: preset or literal
        if spec in CHARSET_PRESETS:
            return CHARSET_PRESETS[spec]
        return spec  # literal characters
    # Returned string is the set of characters we will iterate over for
    # brute-force generation (order matters for reproducibility).
       
def brute_force_attack(charset: str,
                       max_len: int,
                       pwd_to_users: Dict[str, List[str]],
                       case_insensitive: bool,
                       stop_when_all_cracked: bool,
                       progress_every: int = 1000000) -> List[Tuple[str,str,int,str,str]]:
    """
    Try all combinations length 1..max_len from charset.
    Returns cracked list with same tuple format as dict_attack.
    WARNING: combinatorial explosion. Keep max_len small for large charset.
    """
    # Brute-force: generate every string of length 1..max_len from charset
    # using itertools.product. This is simple but can be extremely slow for
    # large charsets or lengths.
    cracked = []
    remaining = set(pwd_to_users.keys())
    candidate_count = 0
    # iterate by length
    for L in range(1, max_len + 1):
        # product yields tuples of characters, e.g. ('a','b','c')
        for combo in itertools.product(charset, repeat=L):
            candidate_count += 1
            cand = "".join(combo)
            check = cand.lower() if case_insensitive else cand
            if check in pwd_to_users:
                users = pwd_to_users[check]
                for u in users:
                    cracked.append((u, cand, candidate_count, cand, f"brute_len{L}"))
                pwd_to_users.pop(check, None)
                remaining.discard(check)
            if candidate_count % progress_every == 0:
                print(f"[+] generated {candidate_count} candidates (current len={L}) — remaining unique passwords: {len(remaining)}", file=sys.stderr)
            if stop_when_all_cracked and not remaining:
                print(f"[+] all targets cracked after generating {candidate_count} candidates", file=sys.stderr)
                return cracked
    return cracked

# -------------------------
# Save results
# -------------------------
def save_cracked(path: Path, data: List[Tuple[str,str,int,str,str]]) -> None:
    # Write cracked results to CSV with a helpful header row.
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["username", "found_password", "candidate_rank", "candidate_variant", "transformation"])
        for row in data:
            w.writerow(row)

# -------------------------
# CLI
# -------------------------
def main():
    # Parse command-line arguments. See the top-of-file docstring for
    # usage examples. The CLI exposes options for both dictionary and
    # brute-force modes and writes results to a CSV.
    p = argparse.ArgumentParser(description="Run dictionary or brute-force plaintext attacks (lab-only)")
    p.add_argument("--mode", choices=("dict","brute"), required=True, help="Attack mode: dict or brute")
    p.add_argument("--targets", "-t", required=True, help="CSV file: username,password")
    # dict args
    group = p.add_mutually_exclusive_group()
    group.add_argument("--wordlist", "-w", help="wordlist text file (one candidate per line)")
    group.add_argument("--json", "-j", help="JSON dictionary produced by dictionary.py")
    p.add_argument("--mangle", action="store_true", help="apply small mangling rules (dict mode)")
    p.add_argument("--case-insensitive", action="store_true", help="case-insensitive comparison")
    # brute args
    p.add_argument("--charset", default="lower,digits", help="charset preset(s) or literal string for brute mode (default: lower,digits)")
    p.add_argument("--max-len", type=int, default=4, help="max length for brute-force (default: 4) — be careful")
    p.add_argument("--out", "-o", default="cracked.csv", help="output CSV for cracked accounts")
    p.add_argument("--no-stop", action="store_true", help="do NOT stop when all targets cracked")
    p.add_argument("--progress-every", type=int, default=None, help="print progress every N candidates (mode-specific default)")
    args = p.parse_args()

    tgt = Path(args.targets)
    if not tgt.exists():
        print("Targets file not found:", tgt, file=sys.stderr); sys.exit(1)
    case_ins = args.case_insensitive
    pwd_to_users, total = load_targets(tgt, case_ins)
    if total == 0:
        print("No targets loaded. Exiting.", file=sys.stderr); sys.exit(1)
    print(f"[+] Loaded {total} accounts (unique plaintext passwords: {len(pwd_to_users)})", file=sys.stderr)

    stop_when_all = not args.no_stop

    if args.mode == "dict":
        # decide source
        if not args.wordlist and not args.json:
            print("Dictionary mode requires --wordlist or --json", file=sys.stderr); sys.exit(1)
        if args.wordlist:
            wl = Path(args.wordlist)
            if not wl.exists():
                print("Wordlist not found:", wl, file=sys.stderr); sys.exit(1)
            cand_iter = stream_from_txt(wl)
        else:
            js = Path(args.json)
            if not js.exists():
                print("JSON dictionary not found:", js, file=sys.stderr); sys.exit(1)
            cand_iter = stream_from_json(js)
        progress_every = args.progress_every or 50000
        cracked = dict_attack(cand_iter, pwd_to_users, case_ins, args.mangle, stop_when_all, progress_every)
    else:
        # brute mode
        charset = build_charset(args.charset)
        if not charset:
            print("Empty charset — nothing to do", file=sys.stderr); sys.exit(1)
        if args.max_len <= 0:
            print("max-len must be > 0", file=sys.stderr); sys.exit(1)
        # warn about explosion (informational)
        # compute approximate total candidates (may be large)
        approx_total = sum(len(charset) ** L for L in range(1, args.max_len + 1))
        print(f"[!] Brute-force mode will generate approx {approx_total:,} candidates (charset size={len(charset)}, max_len={args.max_len})", file=sys.stderr)
        if approx_total > 10_000_000:
            print("[!] Warning: this is >10M candidates — it may take a long time.", file=sys.stderr)
        progress_every = args.progress_every or (1_000_000 if approx_total > 1_000_000 else 100000)
        cracked = brute_force_attack(charset, args.max_len, pwd_to_users, case_ins, stop_when_all, progress_every)

    print(f"[+] Finished. Cracked {len(cracked)} accounts.", file=sys.stderr)
    if cracked:
        save_cracked(Path(args.out), cracked)
        print(f"[+] Results saved to {args.out}", file=sys.stderr)
    else:
        print("[+] No passwords cracked with given candidates.", file=sys.stderr)

if __name__ == "__main__":
    main()
