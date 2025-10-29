# Password-Security-and-Cracking-Analysis
Cyber Operations Project by Karla, Elton, Nikhil

## Brute Force and Dictionary Attack - Karla Daley

## Create_Password_Dictionary.py
### To create a database of commonly used passwords and their variations run this command.
```markdown
python3 create_password_dictionary.py --out ./password_dictionary2.txt --max 5000
```

## Dictionary.py
### Password Strength Checker
```markdown
python3 dictionary.py
```
### Classify database into a JSON dictionary of passwords with metadata (length, entropy, classification)
```markdown
python3 dictionary.py -b passwords.json --file password_dictionary.txt
```

## Add_Target.py
### To create the target file, with the username and password run the add_target python file.
```markdown
python3 add_target.py
```

## Attacks.py

### Continuing after all codes are cracked
```markdown
--no-stop
```
### Output results to CSV file
```markdown
-o cracked.csv
```
### Print progress more/less often:
```markdown
--progress-every 200
```
### Case-Insensitive matching - treat PASSWORD = password
```markdown
--case-insensitive
```

## Dictionary Attack
### Basic - using text database
```markdown
python3 attacks.py --mode dict --wordlist password_dictionary.txt --targets targets.csv
```
### JSON - using dictionary
```markdown
python3 attacks.py --mode dict --json passwords.json --targets targets.csv
```
### Add simple mangling - capitalize/leet/suffixes
```markdown
python3 attacks.py --mode dict --json passwords.json --targets targets.csv --mangle
```


## Brute-Force Attack
### Lowercase + digits, up to length 4 (or any n lenght - note that longer lengths means more time to crack)
```markdown
python3 attacks.py --mode brute --charset lower,digits --max-len 4 --targets targets.csv
```
### Letters only, length up to 3
```markdown
python3 attacks.py --mode brute --charset letters --max-len 3 --targets targets.csv
```
### Full alphanumeric, length up to 5
```markdown
python3 attacks.py --mode brute --charset alnum --max-len 5 --targets targets.csv
```
### Literal custom charset
```markdown
python3 attacks.py --mode brute --charset "abc123!?" --max-len 4 --targets targets.csv
```



## Salting and Hashing part - Nikhil:
needed pip files for using hashing and salting:
```bash
pip install bcrypt argon2-cffi
```
