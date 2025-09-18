from flask import Flask
import os
import subprocess

app = Flask(__name__)

# ❌ Hardcoded secret (what we want CodeQL to find)
API_KEY = "DUMMY_SECRET_KEY_123456"

@app.route("/run")
def run():
    # ❌ Command injection (already detected)
    cmd = os.getenv("USER_INPUT")
    return subprocess.getoutput(cmd)

if __name__ == "__main__":
    # ❌ Flask debug mode (already detected)
    app.run(debug=True)
