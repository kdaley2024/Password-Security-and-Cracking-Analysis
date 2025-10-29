"""
Interactive helper to add/update a username,password row in targets.csv.

- Prompts for username.
- Prompts for password using a hidden prompt (getpass).
- If username already exists in targets.csv, offers to overwrite or cancel.
- Writes CSV with header if the file does not exist.
"""
import csv
from pathlib import Path
import getpass

# - This small script helps you store username/password pairs in a CSV file.
# - It asks for a username and password, hides the password while you type,
#   and then saves the pair into `targets.csv`.
# - If the username already exists, it asks whether to overwrite the password.
# - The script intentionally keeps behavior simple so beginners can read it.
OUT_PATH = Path("targets.csv")

# OUT_PATH is a pathlib.Path object pointing to the file we read/write.
# Using Path makes it easy to check if the file exists and open it.
def load_targets(path: Path):
    # Load existing username,password pairs from a CSV file.
    # We return a list of tuples: [(username, password), ...]
    data = []
    if not path.exists():
        # If the file does not exist yet, return an empty list.
        return data
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        first = next(reader, None)
        # If first row looks like a header, skip it
        # We try to be tolerant of files that include a header row like
        # "username,password". If the first row contains header-like words
        # we skip it and treat the remaining rows as data. Otherwise we
        # treat the first row as data as well.
        if first and any(h.lower() in ("username", "user", "password", "pass") for h in first):
            # header detected -> read remaining rows
            for row in reader:
                if not row:
                    # skip empty lines
                    continue
                if len(row) >= 2:
                    # take only first two columns (username, password)
                    data.append((row[0], row[1]))
        else:
            # first row was actual data (not a header)
            if first and len(first) >= 2:
                data.append((first[0], first[1]))
            for row in reader:
                if not row:
                    continue
                if len(row) >= 2:
                    data.append((row[0], row[1]))
    return data

def save_targets(path: Path, rows):
    # Save the list of (username, password) tuples to a CSV file.
    # We always write a header row so the file is easy to read later.
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password"])  # header row
        for u, p in rows:
            # write each pair as a CSV row (username, password)
            writer.writerow([u, p])

def main():
    # Top-level interaction: ask for username and password, then save.
    print("Add / update entry in targets.csv")
    # Ask the user for a username and strip whitespace from both ends.
    username = input("Username: ").strip()
    if not username:
        # Do not allow empty usernames; exit early.
        print("Username cannot be empty. Exiting.")
        return
    # Use getpass so the password isn't shown on screen while typing.
    try:
        password = getpass.getpass("Password (input hidden): ")
    except Exception:
        # On some terminals getpass may fail; fall back to visible input.
        password = input("Password: ")
    if password == "":
        # Confirm with the user if they really want to use an empty password.
        confirm_empty = input("Password is empty. Proceed? (y/N): ").strip().lower()
        if confirm_empty not in ("y", "yes"):
            print("Aborted.")
            return

    # Load existing entries (if the file exists). This returns a list of tuples.
    rows = load_targets(OUT_PATH)
    # Build a dict mapping username -> index for quick lookup.
    existing_usernames = {u: i for i, (u, p) in enumerate(rows)}
    if username in existing_usernames:
        # If the username exists, show message and ask whether to overwrite.
        idx = existing_usernames[username]
        print(f"Username '{username}' already exists in {OUT_PATH} (password will be updated).")
        confirm = input("Overwrite existing password? (Y/n): ").strip().lower()
        if confirm in ("n", "no"):
            print("No changes made.")
            return
        # Replace the existing tuple at the found index with the new password.
        rows[idx] = (username, password)
    else:
        # If username not found, append as a new entry.
        rows.append((username, password))

    # Save the updated list back to the CSV file.
    save_targets(OUT_PATH, rows)
    print(f"Saved {len(rows)} entries to {OUT_PATH} (username '{username}' added/updated).")

if __name__ == "__main__":
    main()
