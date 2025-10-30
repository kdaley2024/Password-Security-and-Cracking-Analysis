import os, time, hashlib, bcrypt
hash_secret = None
ARGON2_TYPE = None

from argon2.low_level import hash_secret, Type as ARGON2_TYPE

SALT_LEN = 12        # standardized salt length
DKLEN = 32           # standardized derived key length
ITERS = 1           # standardized benchmark iterations for all rows

pw = input("Enter your password: ")
pw_b = pw.encode()

methods = [
    ("MD5",
     lambda: hashlib.md5(os.urandom(SALT_LEN) + pw_b).hexdigest()),

    ("SHA1",
     lambda: hashlib.sha1(os.urandom(SALT_LEN) + pw_b).hexdigest()),

    ("SHA256",
     lambda: hashlib.sha256(os.urandom(SALT_LEN) + pw_b).hexdigest()),

    ("PBKDF2",
     lambda: hashlib.pbkdf2_hmac("sha256", pw_b, os.urandom(SALT_LEN), ITERS, DKLEN)),
]

# bcrypt
if bcrypt is not None:
    methods.append((
        "bcrypt",
        lambda: bcrypt.hashpw(pw_b, bcrypt.gensalt(SALT_LEN))
    ))

# Argon2id
if hash_secret is not None and ARGON2_TYPE is not None:
    methods.append((
        "Argon2id",
        lambda: hash_secret(
            pw_b, os.urandom(SALT_LEN),
            ITERS, memory_cost=65536,  # 64 MiB
            parallelism=1, hash_len=DKLEN, type=ARGON2_TYPE.ID
        )
    ))

print("\nMethod                                               Avg time (ms/op)")
print("----------------------------------------------------------------------")

for name, fn in methods:
        t0 = time.perf_counter()
        _ = fn()
        ms = (time.perf_counter() - t0) * 1000.0
        print(f"{name:<58} {ms:.2f}")