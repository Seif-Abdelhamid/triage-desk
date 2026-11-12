# Test cases for triage-desk.yml: run `semgrep --test semgrep-rules/`
import hashlib
import hmac
import os
import subprocess

from sqlalchemy import text

mac = hmac.new(b"k", b"body", hashlib.sha256)

# ruleid: hmac-digest-compared-with-equals
if mac.hexdigest() == "abc":
    pass

# ok: hmac-digest-compared-with-equals
if hmac.compare_digest(mac.hexdigest(), "abc"):
    pass

# ruleid: subprocess-shell-true
subprocess.run("ls " + os.environ["X"], shell=True)

# ruleid: subprocess-shell-true
os.system("ls")

# ok: subprocess-shell-true
subprocess.run(["semgrep", "scan", "--json", "./a.py"], check=False)

name = "x"
# ruleid: sqlalchemy-text-fstring
text(f"SELECT * FROM findings WHERE rule_id = '{name}'")

# ok: sqlalchemy-text-fstring
text("SELECT * FROM findings WHERE rule_id = :rule").bindparams(rule=name)
