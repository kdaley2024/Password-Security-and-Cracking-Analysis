import math
import string
import argparse
import json
from pathlib import Path
from typing import Dict, Any, List

# Beginner-friendly notes:
# - This script provides two small utilities related to passwords:
#   1) Estimate a password's entropy and classify its strength.
#   2) Build a JSON "dictionary" from a text password list with simple metadata.
# - The file intentionally keeps functions small and easy to read so beginners
#   can follow how input is read, processed, and written out.

COMMON_WEAK = {
    "password","123456","12345678","qwerty","abc123","letmein","monkey",
    "iloveyou","admin","welcome","login","passw0rd","12345","000000"
}

# COMMON_WEAK is a small set of very common passwords. We treat these as
# immediately "weak" because they are well-known and frequently used.

def estimate_entropy(pw: str) -> float:
    pool = 0
    # If the password contains lowercase letters, consider 26 lowercase chars.
    if any(c.islower() for c in pw): pool += 26
    # If it contains uppercase letters, add another 26.
    if any(c.isupper() for c in pw): pool += 26
    # Digits add 10 possible characters.
    if any(c.isdigit() for c in pw): pool += 10
    # Punctuation adds the number of punctuation characters available.
    if any(c in string.punctuation for c in pw): pool += len(string.punctuation)
    # if still zero (e.g., empty string), treat as 1 to avoid math domain errors
    pool = max(pool, 1)
    return len(pw) * math.log2(pool)

def classify_password(pw: str) -> str:
    # Classify a password as 'weak', 'moderate', or 'strong'.
    # We first trim whitespace and treat empty strings as weak.
    pw_clean = pw.strip()
    if pw_clean == "":
        return "weak"  # empty -> weak

    # Immediately mark very common or very short passwords as weak.
    if pw_clean.lower() in COMMON_WEAK:
        return "weak"
    if len(pw_clean) < 6:
        return "weak"

    entropy = estimate_entropy(pw_clean)

    # Use simple entropy thresholds to classify strength. These thresholds
    # are illustrative, not authoritative.
    # <28 bits -> weak
    # 28..50 bits -> moderate
    # >50 bits -> strong
    if entropy < 28:
        return "weak"
    elif entropy < 50:
        return "moderate"
    else:
        return "strong"


def load_passwords(path: str) -> List[str]:
    """Load passwords from a file, returning a list of non-empty stripped lines.

    This reads the entire file and returns only lines that are not empty.
    Each returned string keeps its original case so callers can choose
    whether to treat passwords case-sensitively.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Password file not found: {path}")
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        # strip trailing newline characters but keep other whitespace in the middle
        lines = [line.rstrip('\n') for line in fh]
    # filter out lines that are blank or only whitespace
    return [line for line in lines if line.strip()]


def build_password_dict(path: str, case_sensitive: bool = True) -> Dict[str, Dict[str, Any]]:
    """Return a dictionary mapping password -> metadata.

    Metadata includes:
      - line: original line number (1-based)
      - length: number of characters
      - entropy: estimated entropy (bits)
      - classification: weak/moderate/strong
    """
    # Build a mapping where each key is a password (optionally lowercased)
    # and the value is a small metadata dict. We keep the first occurrence
    # when there are duplicates.
    pw_list = load_passwords(path)
    result: Dict[str, Dict[str, Any]] = {}
    for idx, raw in enumerate(pw_list, start=1):
        # Choose whether dictionary keys are case-sensitive.
        pw = raw if case_sensitive else raw.lower()
        # do not overwrite first occurrence — first line wins
        if pw in result:
            continue
        ent = round(estimate_entropy(raw), 2)
        cls = classify_password(raw)
        result[pw] = {
            "original": raw,
            "line": idx,
            "length": len(raw),
            "entropy": ent,
            "classification": cls,
        }
    return result


def save_dict_as_json(d: Dict[str, Any], out_path: str) -> None:
    # Save the built dictionary to a JSON file. We use ensure_ascii=False so
    # non-ASCII characters (rare in passwords) are preserved, and indent=2
    # to make the file readable.
    p = Path(out_path)
    with p.open("w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    # Parse command-line flags. Note: we kept short '-b' / '-build' flag as
    # in the original code; it accepts an optional filename value.
    parser = argparse.ArgumentParser(description="Password utilities: entropy/classification and build dictionary")
    parser.add_argument("-build", "-b", nargs="?", const="passwords.json",
                        help="Build a dictionary from password_dictionary.txt and save to given JSON file (default: passwords.json)")
    parser.add_argument("--file", "-f", default="password_dictionary.txt",
                        help="Path to password list file (default: password_dictionary.txt)")
    parser.add_argument("--case-insensitive", action="store_true",
                        help="Treat passwords case-insensitively when building the dict (keys lowercased)")
    args = parser.parse_args()

    # If the build flag is provided, build the JSON dictionary and exit.
    if args.build is not None:
        out_file = args.build or "passwords.json"
        try:
            d = build_password_dict(args.file, case_sensitive=(not args.case_insensitive))
        except FileNotFoundError as e:
            print(e)
            raise SystemExit(1)
        save_dict_as_json(d, out_file)
        print(f"Built dictionary with {len(d)} unique entries and saved to: {out_file}")
        raise SystemExit

    # Otherwise, run interactive password classification: prompt the user
    # for a password, classify it, and optionally check whether it appears
    # in the provided password file.
    try:
        pw = input("Enter password to check: ")
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        raise SystemExit

    label = classify_password(pw)
    ent = round(estimate_entropy(pw), 2)
    print(f"Strength: {label} (estimated entropy: {ent} bits)")

    # Check membership in provided password file (if available)
    try:
        pw_list = load_passwords(args.file)
        if args.case_insensitive:
            lookup = set(x.lower() for x in pw_list)
            check_val = pw.lower()
        else:
            lookup = set(pw_list)
            check_val = pw
        in_dict = check_val in lookup
        print(f"In dictionary ({args.file}): {'yes' if in_dict else 'no'}")
    except FileNotFoundError:
        print(f"Dictionary file not found: {args.file} (skipped membership check)")
