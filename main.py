"""
Driver script to run: create_password_dictionary, add_target, and attacks.

Behavior:
- Ask user for username and a strong password (unless provided via flags).
- Store the credentials in `targets.csv`.
- Generate a password dictionary (text file) using the bundled generator.
- Run a dictionary attack against `targets.csv` using that wordlist.
- Run a small brute-force attack (configurable) afterwards.

This script prefers safe defaults so a quick test run completes fast.
Use CLI flags to change sizes and behavior.
"""

from __future__ import annotations

import argparse
import copy
import getpass
from pathlib import Path
from typing import Optional

import create_password_dictionary as cpd
import add_target
import attacks
import dictionary


def ensure_strong_password(pw: str) -> bool:
    # Use the existing classifier from dictionary.py
    return dictionary.classify_password(pw) == "strong"


def prompt_for_credentials(provided_username: Optional[str], provided_password: Optional[str], allow_weak: bool) -> tuple[str, str]:
    username = provided_username
    if not username:
        username = input("Username: ").strip()
    while not username:
        print("Username cannot be empty.")
        username = input("Username: ").strip()

    password = provided_password
    if not password:
        try:
            password = getpass.getpass("Password (input hidden): ")
        except Exception:
            password = input("Password: ")

    if not allow_weak:
        # require a strong password, loop until the user provides one
        while not ensure_strong_password(password):
            print("Password is not strong enough. Please choose a stronger password.")
            try:
                password = getpass.getpass("Password (input hidden): ")
            except Exception:
                password = input("Password: ")
    return username, password


def main() -> None:
    p = argparse.ArgumentParser(description="Driver: generate dictionary, store credentials, run attacks")
    p.add_argument("--username", help="Username to add (skips prompt)")
    p.add_argument("--password", help="Password to add (skips prompt) — if omitted you will be prompted")
    p.add_argument("--allow-weak", action="store_true", help="Allow storing a password that is not classified as strong")
    p.add_argument("--dict-max", type=int, default=5000, help="Max entries for generated dictionary (default: 5000)")
    p.add_argument("--dict-out", default="password_dictionary_generated.txt", help="Output wordlist file")
    p.add_argument("--mangle", action="store_true", help="Apply mangling in dictionary attack")
    p.add_argument("--case-insensitive", action="store_true", help="Case-insensitive matching for attacks")
    p.add_argument("--brute-max-len", type=int, default=3, help="Max length for brute-force attack (default: 3; keep small)")
    p.add_argument("--charset", default="lower,digits", help="Charset for brute force (default: lower,digits)")
    p.add_argument("--out", default="cracked.csv", help="Output cracked CSV file")
    args = p.parse_args()

    # 1) Prompt for credentials
    username, password = prompt_for_credentials(args.username, args.password, args.allow_weak)

    # 2) Load existing targets, update or append the credential, and save
    out_path = Path("targets.csv")
    rows = add_target.load_targets(out_path)
    # find existing username
    existing = {u: i for i, (u, p) in enumerate(rows)}
    if username in existing:
        idx = existing[username]
        rows[idx] = (username, password)
        print(f"Updated existing user '{username}' in {out_path}")
    else:
        rows.append((username, password))
        print(f"Added user '{username}' to {out_path}")
    add_target.save_targets(out_path, rows)

    # 3) Generate dictionary wordlist (text file)
    dict_out = Path(args.dict_out)
    print(f"Generating dictionary (max {args.dict_max}) -> {dict_out}...")
    cpd.generate_dictionary(max_entries=args.dict_max, save_path=str(dict_out))
    print("Dictionary generation complete.")

    # 4) Prepare targets mapping for attacks
    pwd_to_users, total = attacks.load_targets(out_path, args.case_insensitive)
    if total == 0:
        print("No targets to attack. Exiting.")
        return
    # we will run dict then brute; each attack mutates its pwd_to_users, so use copies
    pwd_map_for_dict = copy.deepcopy(pwd_to_users)
    pwd_map_for_brute = copy.deepcopy(pwd_to_users)

    # 5) Run dictionary attack
    print("Running dictionary attack...")
    cand_iter = attacks.stream_from_txt(dict_out)
    cracked_dict = attacks.dict_attack(cand_iter, pwd_map_for_dict, args.case_insensitive, args.mangle, stop_when_all_cracked=True, progress_every=50000)
    print(f"Dictionary attack found {len(cracked_dict)} entries.")

    # 6) Run brute-force attack (safe default max length)
    print("Running brute-force attack (may be slow for large charsets/max-len)...")
    charset = attacks.build_charset(args.charset)
    cracked_brute = attacks.brute_force_attack(charset, args.brute_max_len, pwd_map_for_brute, args.case_insensitive, stop_when_all_cracked=True, progress_every=1000000)
    print(f"Brute-force attack found {len(cracked_brute)} entries.")

    # 7) Combine and save results
    combined = cracked_dict + cracked_brute
    if combined:
        attacks.save_cracked(Path(args.out), combined)
        print(f"Saved {len(combined)} cracked entries to {args.out}")
    else:
        print("No passwords cracked.")


if __name__ == "__main__":
    main()
