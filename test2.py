import bcrypt

pw = input("Enter your password: ")
print(bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode())