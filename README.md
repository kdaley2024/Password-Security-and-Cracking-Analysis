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
