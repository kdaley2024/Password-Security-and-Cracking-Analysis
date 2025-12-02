import html
import time
import secrets
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import hashlib
import dictionary

# In-memory "database"
users = {}       # username -> {"salt": bytes, "hash": bytes}
fail_log = {}    # username -> [timestamps]

# Lockout policy
LOCK_THRESHOLD = 5       # number of failed attempts before lock
LOCK_WINDOW = 300        # seconds to count failures (5 minutes)
LOCK_DURATION = 600      # lock duration in seconds (10 minutes)

# Scrypt parameters
SCRYPT_N = 2**14   # CPU/memory cost
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32
SALT_LEN = 16

# Group-only password trigger
GROUP_SECRET_PASSWORD = "GroupSecret123!"

# HTML template (escaped CSS braces)
PAGE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Secure Demo App</title>
<style>
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }}
  h2 {{ margin-bottom: 0.25rem; }}
  form {{ margin-bottom: 1rem; }}
  input {{ margin-right: 0.25rem; }}
  .msg {{ margin-top: 1rem; color: #0a7; }}
  .err {{ margin-top: 1rem; color: #b00; }}
</style>
</head>
<body>
  <h2>Secure Demo App</h2>

  <h3>Register</h3>
  <form method="post" action="/register">
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Register</button>
  </form>

  <h3>Login</h3>
  <form method="post" action="/login">
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Login</button>
  </form>
  <h3>Check Password</h3>
  <form method="post" action="/check-password">
    <input name="password" type="password" placeholder="Password to check" required>
    <button type="submit">Check</button>
  </form>

  {message}
</body>
</html>
"""

def is_locked(user: str) -> bool:
    now = time.time()
    events = fail_log.get(user, [])
    events = [t for t in events if now - t < LOCK_WINDOW]
    fail_log[user] = events
    if len(events) >= LOCK_THRESHOLD:
        return (now - events[-1]) < LOCK_DURATION
    return False

def render(message: str = "", error: bool = False) -> bytes:
    cls = "err" if error else "msg"
    block = f'<div class="{cls}">{html.escape(message)}</div>' if message else ""
    return (PAGE.format(message=block)).encode("utf-8")

def scrypt_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_LEN,
    )

def register_user(username: str, password: str) -> None:
    salt = secrets.token_bytes(SALT_LEN)
    h = scrypt_hash(password, salt)
    users[username] = {"salt": salt, "hash": h}


def verify_user(username: str, password: str) -> bool:
    record = users.get(username)
    if not record:
        return False
    candidate = scrypt_hash(password, record["salt"])
    return secrets.compare_digest(candidate, record["hash"])

class App(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(render(""))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")
        fields = urllib.parse.parse_qs(body)

        username = fields.get("username", [""])[0].strip()
        password = fields.get("password", [""])[0]

        if self.path == "/check-password":
            pwd = password
            if not pwd:
                self._reply("Missing password.", error=True)
                return
            try:
                common = dictionary.is_common(pwd)
            except Exception:
                common = False
            if common:
                self._reply("This password appears in the dictionary — choose a stronger one.", error=True)
            else:
                self._reply("Password not found in dictionary (good).")
            return

        if self.path == "/register":
            if not username or not password:
                self._reply("Missing username or password.", error=True)
                return
            register_user(username, password)
            self._reply(f"Registered {username} securely with scrypt.")
            return

        if self.path == "/login":
            if not username or not password:
                self._reply("Missing username or password.", error=True)
                return
            if username not in users:
                self._reply("Login failed.", error=True)
                return
            if is_locked(username):
                self._reply("Account locked due to repeated failures.", error=True)
                return
            if verify_user(username, password):
                if password == GROUP_SECRET_PASSWORD:
                    self._reply(f"Welcome {username}, login successful. 🛡️ Group-only alert: Internal test case matched.")
                else:
                    self._reply(f"Welcome {username}, login successful.")
            else:
                fail_log.setdefault(username, []).append(time.time())
                self._reply("Login failed.", error=True)
            return

        self.send_response(404)
        self.end_headers()

    def _reply(self, message: str, error: bool = False):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(render(message, error))

def run(host: str = "127.0.0.1", port: int = 8000):
    print(f"Serving on http://{host}:{port}")
    HTTPServer((host, port), App).serve_forever()

if __name__ == "__main__":
    run()
