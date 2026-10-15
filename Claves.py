from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_bytes = priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
pub_bytes = pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
print("PRIVADA:", base64.b64encode(priv_bytes).decode())
print("PÚBLICA:", base64.b64encode(pub_bytes).decode())