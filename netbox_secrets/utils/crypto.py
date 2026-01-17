"""
Cryptographic utilities for netbox-secrets.

Supports both RSA (legacy) and X25519 (modern) key types.
X25519 uses libsodium's SealedBox pattern for asymmetric encryption.
"""
import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# X25519/Ed25519 support via libsodium (pynacl)
try:
    from nacl.public import PrivateKey, PublicKey, SealedBox
    from nacl.signing import VerifyKey
    from nacl.encoding import Base64Encoder, RawEncoder
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

import base64
import struct


# Key type constants
KEY_TYPE_RSA = 'rsa'
KEY_TYPE_X25519 = 'x25519'
KEY_TYPE_SSH_ED25519 = 'ssh-ed25519'

# X25519 public key PEM markers
X25519_PUBLIC_KEY_HEADER = '-----BEGIN X25519 PUBLIC KEY-----'
X25519_PUBLIC_KEY_FOOTER = '-----END X25519 PUBLIC KEY-----'
X25519_PRIVATE_KEY_HEADER = '-----BEGIN X25519 PRIVATE KEY-----'
X25519_PRIVATE_KEY_FOOTER = '-----END X25519 PRIVATE KEY-----'


def generate_random_key(bits=256):
    """
    Generate a random encryption key. Sizes is given in bits and must be in increments of 32.
    """
    if bits % 32:
        raise Exception(f"Invalid key size ({bits}). Key sizes must be in increments of 32 bits.")
    return os.urandom(int(bits / 8))


def detect_key_type(public_key):
    """
    Detect the type of public key (RSA, X25519, or SSH ed25519).

    Returns KEY_TYPE_RSA, KEY_TYPE_X25519, or KEY_TYPE_SSH_ED25519.
    """
    if isinstance(public_key, bytes):
        public_key = public_key.decode('utf-8')

    public_key = public_key.strip()

    if X25519_PUBLIC_KEY_HEADER in public_key:
        return KEY_TYPE_X25519

    if public_key.startswith('ssh-ed25519 '):
        return KEY_TYPE_SSH_ED25519

    # Default to RSA for backwards compatibility
    return KEY_TYPE_RSA


def parse_ssh_ed25519_public_key(ssh_key):
    """
    Parse an SSH ed25519 public key and extract the raw 32-byte key.

    SSH format: ssh-ed25519 <base64-blob> [comment]
    The blob contains: 4-byte length + "ssh-ed25519" + 4-byte length + 32-byte key

    Returns the raw 32-byte Ed25519 public key.
    """
    if isinstance(ssh_key, bytes):
        ssh_key = ssh_key.decode('utf-8')

    ssh_key = ssh_key.strip()
    parts = ssh_key.split()

    if len(parts) < 2:
        raise ValueError("Invalid SSH key format: expected 'ssh-ed25519 <key> [comment]'")

    if parts[0] != 'ssh-ed25519':
        raise ValueError(f"Invalid key type: expected 'ssh-ed25519', got '{parts[0]}'")

    try:
        blob = base64.b64decode(parts[1])
    except Exception as e:
        raise ValueError(f"Invalid base64 in SSH key: {e}")

    # Parse the SSH wire format
    offset = 0

    # Read key type length and string
    if len(blob) < 4:
        raise ValueError("SSH key blob too short")
    type_len = struct.unpack('>I', blob[offset:offset + 4])[0]
    offset += 4

    if len(blob) < offset + type_len:
        raise ValueError("SSH key blob truncated (key type)")
    key_type = blob[offset:offset + type_len].decode('utf-8')
    offset += type_len

    if key_type != 'ssh-ed25519':
        raise ValueError(f"Key type mismatch in blob: expected 'ssh-ed25519', got '{key_type}'")

    # Read public key length and data
    if len(blob) < offset + 4:
        raise ValueError("SSH key blob truncated (key length)")
    key_len = struct.unpack('>I', blob[offset:offset + 4])[0]
    offset += 4

    if key_len != 32:
        raise ValueError(f"Invalid Ed25519 key length: expected 32, got {key_len}")

    if len(blob) < offset + key_len:
        raise ValueError("SSH key blob truncated (key data)")

    return blob[offset:offset + key_len]


def convert_ssh_ed25519_to_x25519(ssh_key):
    """
    Convert an SSH ed25519 public key to X25519 format.

    Ed25519 (signing) and X25519 (encryption) use the same curve (Curve25519),
    but different point representations. This function converts between them.

    Returns the public key in our X25519 PEM-like format.

    Note: Some Ed25519 keys cannot be converted to X25519 (low-order points,
    keys on small subgroups). In such cases, a ValueError is raised.
    """
    if not NACL_AVAILABLE:
        raise ImportError("pynacl is required for SSH key conversion. Install with: pip install pynacl")

    # Parse the SSH key to get raw Ed25519 public key bytes
    ed25519_bytes = parse_ssh_ed25519_public_key(ssh_key)

    # Create Ed25519 verify key and convert to X25519
    try:
        verify_key = VerifyKey(ed25519_bytes)
        x25519_public_key = verify_key.to_curve25519_public_key()
    except Exception as e:
        raise ValueError(
            "This SSH ed25519 key cannot be converted to X25519 for encryption. "
            "This can happen with certain edge-case keys. Please generate a new "
            "X25519 keypair using the 'Generate a New Key Pair' button, or use "
            "an RSA key instead."
        ) from e

    # Encode as our PEM-like format
    public_key_b64 = x25519_public_key.encode(encoder=Base64Encoder).decode('utf-8')
    return f"{X25519_PUBLIC_KEY_HEADER}\n{public_key_b64}\n{X25519_PUBLIC_KEY_FOOTER}"


def normalize_public_key(public_key):
    """
    Normalize a public key to internal format.

    Converts SSH ed25519 keys to X25519 PEM format.
    RSA and X25519 PEM keys are returned unchanged.
    """
    key_type = detect_key_type(public_key)

    if key_type == KEY_TYPE_SSH_ED25519:
        return convert_ssh_ed25519_to_x25519(public_key)

    return public_key


def generate_x25519_keypair():
    """
    Generate a new X25519 keypair for asymmetric encryption.

    Returns a tuple of (private_key_pem, public_key_pem) as strings.
    """
    if not NACL_AVAILABLE:
        raise ImportError("pynacl is required for X25519 support. Install with: pip install pynacl")

    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    # Encode keys in PEM-like format for consistency with RSA
    private_key_b64 = private_key.encode(encoder=Base64Encoder).decode('utf-8')
    public_key_b64 = public_key.encode(encoder=Base64Encoder).decode('utf-8')

    private_pem = f"{X25519_PRIVATE_KEY_HEADER}\n{private_key_b64}\n{X25519_PRIVATE_KEY_FOOTER}"
    public_pem = f"{X25519_PUBLIC_KEY_HEADER}\n{public_key_b64}\n{X25519_PUBLIC_KEY_FOOTER}"

    return private_pem, public_pem


def parse_x25519_public_key(pem_data):
    """
    Parse an X25519 public key from PEM format.

    Returns a nacl.public.PublicKey object.
    """
    if not NACL_AVAILABLE:
        raise ImportError("pynacl is required for X25519 support. Install with: pip install pynacl")

    if isinstance(pem_data, bytes):
        pem_data = pem_data.decode('utf-8')

    pem_data = pem_data.strip()

    if X25519_PUBLIC_KEY_HEADER not in pem_data:
        raise ValueError("Invalid X25519 public key format: missing header")

    # Extract the base64-encoded key data
    lines = pem_data.split('\n')
    key_data = ''
    in_key = False
    for line in lines:
        line = line.strip()
        if line == X25519_PUBLIC_KEY_HEADER:
            in_key = True
            continue
        if line == X25519_PUBLIC_KEY_FOOTER:
            break
        if in_key:
            key_data += line

    return PublicKey(key_data.encode('utf-8'), encoder=Base64Encoder)


def parse_x25519_private_key(pem_data):
    """
    Parse an X25519 private key from PEM format.

    Returns a nacl.public.PrivateKey object.
    """
    if not NACL_AVAILABLE:
        raise ImportError("pynacl is required for X25519 support. Install with: pip install pynacl")

    if isinstance(pem_data, bytes):
        pem_data = pem_data.decode('utf-8')

    pem_data = pem_data.strip()

    if X25519_PRIVATE_KEY_HEADER not in pem_data:
        raise ValueError("Invalid X25519 private key format: missing header")

    # Extract the base64-encoded key data
    lines = pem_data.split('\n')
    key_data = ''
    in_key = False
    for line in lines:
        line = line.strip()
        if line == X25519_PRIVATE_KEY_HEADER:
            in_key = True
            continue
        if line == X25519_PRIVATE_KEY_FOOTER:
            break
        if in_key:
            key_data += line

    return PrivateKey(key_data.encode('utf-8'), encoder=Base64Encoder)


def encrypt_master_key_x25519(master_key, public_key_pem):
    """
    Encrypt a master key using X25519 SealedBox pattern.

    SealedBox uses ephemeral keypairs for forward secrecy:
    - Sender generates ephemeral X25519 keypair
    - ECDH with recipient's public key derives shared secret
    - Shared secret encrypts the message
    - Ephemeral public key is prepended to ciphertext

    Only the recipient's private key can decrypt.
    """
    if not NACL_AVAILABLE:
        raise ImportError("pynacl is required for X25519 support. Install with: pip install pynacl")

    public_key = parse_x25519_public_key(public_key_pem)
    sealed_box = SealedBox(public_key)
    return sealed_box.encrypt(master_key)


def decrypt_master_key_x25519(master_key_cipher, private_key_pem):
    """
    Decrypt a master key using X25519 SealedBox pattern.

    Requires the recipient's private key to derive the shared secret
    and decrypt the message.
    """
    if not NACL_AVAILABLE:
        raise ImportError("pynacl is required for X25519 support. Install with: pip install pynacl")

    private_key = parse_x25519_private_key(private_key_pem)
    sealed_box = SealedBox(private_key)
    return sealed_box.decrypt(master_key_cipher)


def encrypt_master_key(master_key, public_key):
    """
    Encrypt a master key with the provided public key.

    Automatically detects key type (RSA or X25519) and uses
    the appropriate encryption method.
    """
    key_type = detect_key_type(public_key)

    if key_type == KEY_TYPE_X25519:
        return encrypt_master_key_x25519(master_key, public_key)
    else:
        # RSA encryption (legacy)
        return encrypt_master_key_rsa(master_key, public_key)


def decrypt_master_key(master_key_cipher, private_key):
    """
    Decrypt a master key with the provided private key.

    Automatically detects key type (RSA or X25519) and uses
    the appropriate decryption method.
    """
    key_type = detect_key_type(private_key)

    if key_type == KEY_TYPE_X25519:
        return decrypt_master_key_x25519(master_key_cipher, private_key)
    else:
        # RSA decryption (legacy)
        return decrypt_master_key_rsa(master_key_cipher, private_key)


def encrypt_master_key_rsa(master_key, public_key):
    """
    Encrypt a secret key with the provided public RSA key.
    """
    key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(master_key)


def decrypt_master_key_rsa(master_key_cipher, private_key):
    """
    Decrypt a secret key with the provided private RSA key.
    """
    key = RSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(master_key_cipher)


def validate_x25519_public_key(public_key_pem):
    """
    Validate that a string is a valid X25519 public key.

    Returns True if valid, raises ValueError otherwise.
    """
    if not NACL_AVAILABLE:
        raise ImportError("pynacl is required for X25519 support. Install with: pip install pynacl")

    try:
        parse_x25519_public_key(public_key_pem)
        return True
    except Exception as e:
        raise ValueError(f"Invalid X25519 public key: {e}")
