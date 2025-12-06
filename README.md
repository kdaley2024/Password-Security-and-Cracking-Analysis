# Password-Security-and-Cracking-Analysis
Cyber Operations Project by Karla, Elton, Nikhil

## Pasword Strength Checker
```bash
python3 dictionary.py
```

## Brute Force and Dictionary Attack - Karla Daley
### Template
```bash
python3 main.py --username <username> --password <strong password> --dict-max <n> --dict-out <wordlist name> --brute-max-len <n> --charset lower,digits --out <filename>
```
### Example Implementation
```bash
python3 main.py --username admin --password ST0d311T456$ --dict-max 10000 --dict-out dictionary.txt --brute-max-len 4 --charset lower,digits --out cracked.csv
```




## Salting and Hashing part - Nikhil:
needed pip files for using hashing and salting:
```bash
pip install bcrypt argon2-cffi
```



## Password security and cracking analysis — Elton Batista

### Commands

- **Local dictionary attack:**
  
  ```bash
  python3 main.py

- **Hydra against DVWA (Low security):**

  ```bash
  hydra -l admin -P password_dictionary_generated.txt localhost \
  http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"

- **Hydra against secure demo app (salted scrypt + lockout):**

  ```bash
  hydra -l admin -P password_dictionary_generated.txt -s 8000 localhost \
  http-post-form "/login:username=^USER^&password=^PASS^:Login failed"

- **Hashing performance demo (bcrypt/Argon2id included):**

  ```bash
  python3 hashing_and_salting_test.py

### Results summary

- **Local dictionary attack: 1 password cracked after 290 attempts.**
- **Local brute‑force attack: 0 cracked; infeasible for large charsets.**
- **DVWA dictionary attack (Hydra): 16 weak variants found for admin.**
- **Secure demo app attack (Hydra): 0 cracked; salted scrypt + lockout prevented.**
- **Hashing demo: bcrypt and Argon2id resisted due to salting and computational cost; fast hashes (MD5/SHA1/SHA256) are unsafe.**
