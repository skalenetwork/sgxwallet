import secrets
import random
import os
import json
from sgx import SgxClient

def provision_keys(sgx_url: str, dkg_id: int = None) -> dict:
    sgx = SgxClient(sgx_url)

    if dkg_id is None:
        dkg_id = random.randint(0, 10**50)

    bls_key_name = f"BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:{dkg_id}"
    bls_private_key = secrets.token_hex(32)
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
