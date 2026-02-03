import secrets
import random
import os
import json
from sgx import SgxClient

# BN-SNARK1 Fr order (scalar field modulus)
# BLS private keys must be in range [0, FR_ORDER-1]
FR_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def generate_valid_bls_key() -> str:
    """Generate a random BLS private key that is valid (< Fr order)."""
    # Generate random 256-bit value and reduce modulo Fr order
    random_value = secrets.randbits(256)
    valid_key = random_value % FR_ORDER
    # Convert to 64-char hex string (zero-padded)
    return format(valid_key, '064x')

def provision_keys(sgx_url: str, dkg_id: int = None) -> dict:
    sgx = SgxClient(sgx_url)

    if dkg_id is None:
        dkg_id = random.randint(0, 10**50)

    bls_key_name = f"BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:{dkg_id}"
    bls_private_key = generate_valid_bls_key()
    sgx.import_bls_private_key(bls_key_name, bls_private_key)
    bls_public_key = sgx.get_bls_public_key(bls_key_name)

    ecdsa_key_name = "NEK:" + secrets.token_hex(32)
    ecdsa_private_key = secrets.token_hex(32)
    ecdsa_public_key = sgx.import_ecdsa_private_key(ecdsa_key_name, ecdsa_private_key)

    keys = {
        "bls": {
            "name": bls_key_name,
            "private_key": bls_private_key,
            "public_key": bls_public_key,
        },
        "ecdsa": {
            "name": ecdsa_key_name,
            "private_key": ecdsa_private_key,
            "public_key": ecdsa_public_key,
        },
        "dkg_id": dkg_id
    }

    return keys
