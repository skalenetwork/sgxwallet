import secrets
import random
import json
from urllib import error, request

try:
    from sgx import SgxClient  # type: ignore
except ModuleNotFoundError:
    class SgxClient:
        """Small JSON-RPC client fallback used when sgx.py is unavailable."""

        def __init__(self, endpoint: str):
            self.endpoint = endpoint

        @staticmethod
        def _with_0x(hex_value: str) -> str:
            return hex_value if hex_value.startswith("0x") else f"0x{hex_value}"

        def _rpc(self, method: str, params: dict):
            payload = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": 1,
            }
            body = json.dumps(payload).encode("utf-8")
            req = request.Request(
                self.endpoint,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with request.urlopen(req) as response:
                    reply = json.loads(response.read().decode("utf-8"))
            except error.URLError as exc:
                raise RuntimeError(f"RPC call '{method}' failed: {exc}") from exc

            if "error" in reply and reply["error"] is not None:
                err = reply["error"]
                raise RuntimeError(
                    f"RPC error in '{method}': code={err.get('code')} message={err.get('message')}"
                )

            result = reply.get("result", {})
            if isinstance(result, dict) and result.get("status", 0) != 0:
                raise RuntimeError(
                    f"RPC method '{method}' returned status {result.get('status')}: "
                    f"{result.get('errorMessage', '')}"
                )
            return result

        def import_bls_private_key(self, key_share_name: str, key_share: str):
            return self._rpc(
                "importBLSKeyShare",
                {
                    "keyShare": self._with_0x(key_share),
                    "keyShareName": key_share_name,
                },
            )

        def get_bls_public_key(self, bls_key_name: str):
            result = self._rpc("getBLSPublicKeyShare", {"blsKeyName": bls_key_name})
            return result.get("blsPublicKeyShare")

        def import_ecdsa_private_key(self, key_name: str, key: str):
            result = self._rpc(
                "importECDSAKey",
                {"key": self._with_0x(key), "keyName": key_name},
            )
            return result.get("publicKey") or result.get("PublicKey")

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
