from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def traffic_keys(ikm: bytes) -> tuple[ChaCha20Poly1305, ChaCha20Poly1305]:
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b"Noise",
        info=b"valetvpn v1 traffic",
    ).derive(ikm)
    return ChaCha20Poly1305(material[:32]), ChaCha20Poly1305(material[32:])