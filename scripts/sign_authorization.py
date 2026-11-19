import json
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

REPO = Path(r"C:\Users\User\Desktop\ASTRA CODER")
KEYS_DIR = Path(r"C:\Users\User\.astra-keys")
AUTH_FILE = REPO / "authorization.json"

KEYS_DIR.mkdir(parents=True, exist_ok=True)
priv_path = KEYS_DIR / "operator_ed25519.pem"
pub_path = KEYS_DIR / "operator_ed25519.pub.pem"

if not priv_path.exists():
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_path.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    pub_path.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    key_id = hashlib.sha256(pub_path.read_bytes()).hexdigest()[:16]
    print(f"KEY_ID: {key_id}")
else:
    print("Key already exists, reusing.")

priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
auth = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
auth["signature"]["value"] = None
auth_bytes = json.dumps(auth, sort_keys=True, separators=(",", ":")).encode("utf-8")
sig = priv.sign(auth_bytes)
auth["signature"]["value"] = sig.hex()
auth["result"]["status"] = "SIGNED"
auth["result"]["approved"] = True
auth["artifact_status"] = "SIGNED"
AUTH_FILE.write_text(json.dumps(auth, indent=2), encoding="utf-8")
print(f"Signed: {AUTH_FILE}")
print(f"Signature (hex): {sig.hex()[:32]}...")
