import os, time, hashlib

bcrypt = None
hash_secret = None
ARGON2_TYPE = None

import bcrypt as _bcrypt
bcrypt = _bcrypt

from argon2.low_level import hash_secret, Type as ARGON2_TYPE

SALT_LEN = 12        # standardized salt length
DKLEN = 32           # standardized derived key length
ITERS = 1           # standardized benchmark iterations for all rows

pw = input("Enter your password: ")
pw_b = pw.encode()

def bench(fn, iters=ITERS):
    t0 = time.perf_counter()
    for _ in range(iters):
        fn()
    return (time.perf_counter() - t0) * 1000 / iters  # ms/op

methods = [
    ("MD5 + 12B salt (not secure)",
     lambda: hashlib.md5(os.urandom(SALT_LEN) + pw_b).hexdigest()),

    ("SHA1 + 12B salt (not secure)",
     lambda: hashlib.sha1(os.urandom(SALT_LEN) + pw_b).hexdigest()),

    ("SHA256 + 12B salt (not secure)",
     lambda: hashlib.sha256(os.urandom(SALT_LEN) + pw_b).hexdigest()),

    ("PBKDF2",
     lambda: hashlib.pbkdf2_hmac("sha256", pw_b, os.urandom(SALT_LEN), 100_000, dklen=DKLEN)),
]

# bcrypt with standardized 12B salt; cost=12
if bcrypt is not None:
    methods.append((
        "bcrypt",
        lambda: bcrypt.hashpw(pw_b, bcrypt.gensalt(rounds=12))
    ))
else:
    methods.append(("bcrypt", None))

# Argon2id with standardized 12B salt
if hash_secret is not None and ARGON2_TYPE is not None:
    methods.append((
        "Argon2id",
        lambda: hash_secret(
            pw_b, os.urandom(SALT_LEN),
            time_cost=2, memory_cost=65536,  # 64 MiB
            parallelism=1, hash_len=DKLEN, type=ARGON2_TYPE.ID
        )
    ))
else:
    methods.append(("Argon2id (install 'argon2-cffi' to measure)", None))

print("\nMethod                                               Avg time (ms/op)")
print("----------------------------------------------------------------------")
for name, fn in methods:
    if fn is None:
        print(f"{name:<58} (not measured)")
        continue
    ms = bench(fn, ITERS)
    print(f"{name:<58} {ms:.2f}")
