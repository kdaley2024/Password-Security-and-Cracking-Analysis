from __future__ import annotations

import argparse
import itertools
import os
from typing import Iterable, List, Set, Dict

# - This small script generates a simple password list (one password per line)
#   using a short set of common base words, a list of suffixes, and optional
#   simple "leet" substitutions (e.g. a->4, o->0). It's non-interactive and
#   meant for demo / lab use only.
# - The main entry point is the `_cli()` function at the bottom. You can run
#   the module as a script to write a text file with generated candidates.
# - No external dependencies required; output is plain UTF-8 text.


COMMON_BASES = [
	"password",
	"123456",
	"123456789",
	"qwerty",
	"abc123",
	"football",
	"letmein",
	"monkey",
	"iloveyou",
	"admin",
	"welcome",
	"login",
	"princess",
	"dragon",
	"sunshine",
	"flower",
	"password1",
	"passw0rd",
	"master",
	"hello",
]

# COMMON_BASES: a small list of common base words that people often use as
# passwords. We will generate variations of these (capitalization, leet,
# suffixes) to create a larger candidate set.


DEFAULT_SUFFIXES = ["", "1", "12", "123", "1234", "!", "@", "2020", "2021", "2022", "2023"]

LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}

# DEFAULT_SUFFIXES: common short additions people append to base words.
# LEET_MAP: a simple mapping used to generate common leetspeak variants.


def leet_variations(s: str, leet_map: Dict[str, str]) -> Set[str]:
	# Generate a set of strings where up to a few characters are replaced
	# with their leet equivalents. We limit the number of simultaneous
	# substitutions to keep the output tractable.
	positions = [i for i, ch in enumerate(s.lower()) if ch in leet_map]
	variants = {s}
	# Try combinations of 1..min(positions,4) replacement positions so we
	# create variants like 'password' -> 'p4ssword' or 'p455w0rd' etc.
	for r in range(1, min(len(positions), 4) + 1):
		for comb in itertools.combinations(positions, r):
			arr = list(s)
			for idx in comb:
				arr[idx] = leet_map.get(arr[idx].lower(), arr[idx])
			variants.add("".join(arr))
	return variants


def _save_list(items: Iterable[str], path: str) -> None:
	# Save an iterable of strings to a file, one per line. Creates the
	# parent directory if needed.
	os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
	with open(path, "w", encoding="utf8") as fh:
		for it in items:
			fh.write(it + "\n")


def generate_dictionary(
	bases: Iterable[str] = COMMON_BASES,
	suffixes: Iterable[str] = DEFAULT_SUFFIXES,
	leet_map: Dict[str, str] = LEET_MAP,
	max_entries: int = 20000,
	save_path: str | None = None,
) -> List[str]:
	# Build the dictionary list. The algorithm is simple and deterministic:
	# 1. For each base word create a few normalized forms: original,
	#    capitalized (First letter uppercase), and UPPERCASE.
	# 2. For each form generate leet variants (limited combinations).
	# 3. For each variant append each suffix and add the result to the
	#    output list (avoid duplicates using `seen`).
	# 4. If the requested number of entries hasn't been reached, append
	#    permutations of two different base words (e.g. 'password123456').
	# We stop early once `max_entries` is reached. Optionally save to disk.
	out: List[str] = []
	seen: Set[str] = set()

	for base in bases:
		# forms: original, Capitalize, UPPER
		forms = {base, base.capitalize(), base.upper()}
		forms_with_leet: Set[str] = set()
		for f in forms:
			# extend with leet variants for each form
			forms_with_leet.update(leet_variations(f, leet_map))

		for f in forms_with_leet:
			for suf in suffixes:
				cand = f + suf
				if cand not in seen:
					seen.add(cand)
					out.append(cand)
					if len(out) >= max_entries:
						if save_path:
							_save_list(out, save_path)
						return out

	# If we still need more entries, add permutations of two bases
	for a, b in itertools.permutations(bases, 2):
		cand = a + b
		if cand not in seen:
			seen.add(cand)
			out.append(cand)
			if len(out) >= max_entries:
				if save_path:
					_save_list(out, save_path)
				return out

	# Save to disk if requested and return the list
	if save_path:
		_save_list(out, save_path)
	return out


def _cli():
	# Command-line entry point. It accepts an output filename and a maximum
	# number of entries to generate. Example:
	#   python create_password_dictionary.py --out passwords.txt --max 5000
	p = argparse.ArgumentParser(description="Create password dictionary (non-interactive)")
	p.add_argument("--out", "-o", default="password_dictionary.txt", help="Output path for generated dictionary")
	p.add_argument("--max", "-m", type=int, default=5000, help="Maximum entries to generate")
	args = p.parse_args()

	print(f"Generating dictionary (max {args.max}) and saving to {args.out}...")
	generate_dictionary(max_entries=args.max, save_path=args.out)
	print("Done.")


if __name__ == "__main__":
	_cli()
