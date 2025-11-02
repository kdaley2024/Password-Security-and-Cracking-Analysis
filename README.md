# Password-Security-and-Cracking-Analysis
Cyber Operations Project by Karla, Elton, Nikhil

## Pasword Strength Checker

## Brute Force and Dictionary Attack - Karla Daley
```python
python3 main.py --username <username> --password <strong password> --dict-max <n> --dict-out <wordlist name> --brute-max-len <n> --charset lower,digits --out <filename>
```



## Salting and Hashing part - Nikhil:
needed pip files for using hashing and salting:
```bash
pip install bcrypt argon2-cffi
```



## Brute-Force Testing with John the Ripper - Elton:
### Environment Setup (macOS)
Build John the Ripper Jumbo from source
```bash
git clone https://github.com/openwall/john.git
cd john/src
brew install openssl
export CPPFLAGS="-I/opt/homebrew/opt/openssl/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl/lib"
./configure
make -sj4
```
### Hash Preparation
Create a SHA-1 hash for testing
```bash
echo "letmein:e0c9035898dd52fc65c41454cec9c4d2611bfb37" > hashes_sha1.txt
```
### Brute-Force Attack with John the Ripper
Run incremental brute-force attack
```bash
./john --format=raw-sha1 --incremental hashes_sha1.txt
```
Show cracked password
```bash
./john --show hashes_sha1.txt
```
### Performance Logging
Install GNU time
```bash
brew install gnu-time
```
Run with detailed metrics
```bash
/opt/homebrew/bin/gtime -v ./john --format=raw-sha1 --incremental hashes_sha1.txt
```
### Results
```markdown
password,hash_type,time_to_crack,cpu_usage,max_memory_kb,page_faults_major,page_faults_minor,context_switches_voluntary,context_switches_involuntary,cracked_status
letmein,SHA-1,0.07s,79%,185760,94,11734,36,170,cracked
```

