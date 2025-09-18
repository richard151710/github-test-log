# app.py - vulnerable sample for CodeQL testing
from flask import Flask, request
import subprocess

app = Flask(__name__)

# ❌ Hardcoded secret (what we want CodeQL to find)
API_KEY = "DUMMY_SECRET_KEY_123456"
API_KEY = "DUMMY_SECRET_KEY_123456"         # flagged by name & value
db_password = "mypassword"                 # flagged by name (maybe low entropy)
bearer = "A1b2C3d4E5f6G7h8"                # flagged by value (length+alnum)
not_secret = "hello"    
@app.route("/ping")
def ping():
    # ❌ Command injection (not needed for secret detection, but good to test)
    ip = request.args.get("ip", "127.0.0.1")
    return subprocess.getoutput(f"ping -c 1 {ip}")

if __name__ == "__main__":
    app.run(debug=True)
