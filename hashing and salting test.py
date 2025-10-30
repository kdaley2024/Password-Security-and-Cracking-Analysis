import os, time, hashlib, bcrypt
hash_secret = None
ARGON2_TYPE = None

from argon2.low_level import hash_secret, Type as ARGON2_TYPE

SALT_LEN = 12        # standardized salt length
DKLEN = 32           # standardized derived key length
ITERS = 1

pw = input("Enter your password: ")
pw_b = pw.encode()

# variables for output of results:
md5_out = None
sha1_out = None
sha256_out = None
pbkdf2_out = None
bcrypt_out = None
argon2id_out = None

methods = [
    ("MD5",
     lambda: hashlib.md5(os.urandom(SALT_LEN) + pw_b).hexdigest()),

    ("SHA1",
     lambda: hashlib.sha1(os.urandom(SALT_LEN) + pw_b).hexdigest()),

    ("SHA256",
     lambda: hashlib.sha256(os.urandom(SALT_LEN) + pw_b).hexdigest()),

    ("PBKDF2",
     lambda: hashlib.pbkdf2_hmac("sha256", pw_b, os.urandom(SALT_LEN), 100000, DKLEN)),
    
    ("bcrypt",
        lambda: bcrypt.hashpw(pw_b, bcrypt.gensalt(SALT_LEN))),
    
    ("Argon2id",
        lambda: hash_secret(
            pw_b, os.urandom(SALT_LEN),
            ITERS, memory_cost=65536,  # 64 MiB
            parallelism=1, hash_len=DKLEN, type=ARGON2_TYPE.ID))
]

print("\nMethod                                               Avg time (ms/op)")
print("----------------------------------------------------------------------")

for name, fn in methods:
    t0 = time.perf_counter()
    out = fn()
    ms = (time.perf_counter() - t0) * 1000.0
    print(f"{name:<58} {ms:.2f}")
        
    if name == "MD5":
        md5_out = out
    if name == "SHA1":
        sha1_out = out
    if name == "SHA256":
        sha256_out = out
    if name == "PBKDF2":
        pbkdf2_out = out
    if name == "bcrypt":
        bcrypt_out = out
    if name == "Argon2id":
        argon2id_out = out
        
print("\nOutputs:")
print(f"MD5:      {md5_out}")
print(f"SHA1:     {sha1_out}")
print(f"SHA256:   {sha256_out}")
print(f"PBKDF2:   {pbkdf2_out}")
print(f"bcrypt:   {bcrypt_out}")
print(f"Argon2id: {argon2id_out}")