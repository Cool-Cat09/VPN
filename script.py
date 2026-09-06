import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

private_key = x25519.X25519PrivateKey.generate()

public_key = private_key.public_key()

private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)
private_base64 = base64.b64encode(private_bytes).decode('utf-8')
with open('private_key.pem', 'w', encoding='utf-8') as file:
    file.write(private_base64)

public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
public_base64 = base64.b64encode(public_bytes).decode('utf-8')

with open('public_key.pem', 'w', encoding='utf-8') as file:
    file.write(public_base64)

print(f"Приватный ключ (держать в секрете): {private_base64}")
print(f"Публичный ключ (можно отдавать):    {public_base64}")
