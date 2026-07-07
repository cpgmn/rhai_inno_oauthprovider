#!/bin/bash
# Quick start script for local development

set -e

echo "🔑 Generating RSA keypair..."
cd innovationcloud_authprovider

if [ ! -f "private_key.pem" ] || [ ! -f "public_key.pem" ]; then
    python3 -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

with open('private_key.pem', 'w') as f:
    f.write(private_pem)
with open('public_key.pem', 'w') as f:
    f.write(public_pem)
    
print('✓ Keys generated')
"
fi

echo "📦 Creating virtual environments..."
[ -d ".venv" ] || uv venv
source .venv/bin/activate
uv pip install -q -r requirements.txt

cd ../authclient
[ -d ".venv" ] || uv venv
source .venv/bin/activate
uv pip install -q -r requirements.txt

cd ..
echo "✅ Setup complete!"
echo ""
echo "To start the Identity Provider:"
echo "  cd innovationcloud_authprovider"
echo "  source .venv/bin/activate"
echo "  export JWT_PRIVATE_KEY=\$(cat private_key.pem)"
echo "  export JWT_PUBLIC_KEY=\$(cat public_key.pem)"
echo "  uvicorn app.main:app --reload --port 8080"
echo ""
echo "To start the test client (in another terminal):"
echo "  cd authclient"
echo "  source .venv/bin/activate"
echo "  uvicorn app.main:app --reload --port 3000"
echo ""
echo "Then visit: http://localhost:3000"
