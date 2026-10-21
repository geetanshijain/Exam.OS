import base64
import hashlib
import json
import logging
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from app.vault.kms import KMSKeyStore

logger = logging.getLogger(__name__)


class CiphertextTamperedError(Exception):
    """Raised when authentication tag verification or AAD binding fails."""
    pass


class IntegrityCheckFailedError(Exception):
    """Raised when decrypted payload does not match its expected cryptographic digest."""
    pass


def canonical_aad_bytes(metadata: dict[str, Any]) -> bytes:
    """Produces deterministic canonical byte representation of metadata for AAD."""
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt_paper_envelope(
    plaintext: bytes,
    metadata: dict[str, Any],
    kms: KMSKeyStore,
) -> tuple[bytes, dict[str, Any]]:
    """
    Encrypts paper contents using envelope encryption with authenticated AES-256-GCM.
    Binds metadata into AAD.

    Returns:
        (ciphertext_bytes, envelope_info)
    """
    if not plaintext:
        raise ValueError("Cannot encrypt empty paper content.")

    # 1. Compute integrity hash of original plaintext
    payload_sha256 = hashlib.sha256(plaintext).hexdigest()

    # 2. Generate unique 256-bit DEK using CSPRNG
    raw_dek = bytearray(get_random_bytes(32))

    try:
        # 3. Wrap DEK via managed KMS
        wrapped_dek_b64, kek_version = kms.wrap_dek(bytes(raw_dek))

        # 4. Prepare Authenticated Additional Data (AAD)
        aad_bytes = canonical_aad_bytes(metadata)

        # 5. Encrypt with AES-256-GCM
        cipher = AES.new(bytes(raw_dek), AES.MODE_GCM)
        cipher.update(aad_bytes)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        envelope_info = {
            "wrapped_dek": wrapped_dek_b64,
            "kek_version": kek_version,
            "nonce_b64": base64.b64encode(cipher.nonce).decode("ascii"),
            "tag_b64": base64.b64encode(tag).decode("ascii"),
            "aad_json": aad_bytes.decode("utf-8"),
            "payload_sha256": payload_sha256,
        }

        return ciphertext, envelope_info

    finally:
        # 6. Cryptographic Memory Zeroization: overwrite DEK bytes in memory
        for i in range(len(raw_dek)):
            raw_dek[i] = 0


def decrypt_paper_envelope(
    ciphertext: bytes,
    nonce_b64: str,
    tag_b64: str,
    aad_json: str,
    wrapped_dek: str,
    kek_version: str,
    expected_sha256: str,
    kms: KMSKeyStore,
) -> bytes:
    """
    Decrypts paper envelope using AES-256-GCM, verifying authentication tag and AAD.
    Zeroizes decrypted DEK in memory.
    """
    # 1. Unwrap DEK using KMS
    plaintext_dek = bytearray(kms.unwrap_dek(wrapped_dek, kek_version))

    try:
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        aad_bytes = aad_json.encode("utf-8")

        # 2. Authenticated Decryption
        cipher = AES.new(bytes(plaintext_dek), AES.MODE_GCM, nonce=nonce)
        cipher.update(aad_bytes)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise CiphertextTamperedError(
                "Decryption rejected: GCM authentication tag verification failed. "
                "Ciphertext or authenticated metadata has been modified or corrupted."
            ) from exc

        # 3. Payload Integrity Digest Verification
        actual_sha256 = hashlib.sha256(plaintext).hexdigest()
        if actual_sha256.lower() != expected_sha256.lower():
            raise IntegrityCheckFailedError(
                f"Decrypted payload integrity digest mismatch. Expected: {expected_sha256}, Actual: {actual_sha256}"
            )

        return plaintext

    finally:
        # Zeroize DEK in memory
        for i in range(len(plaintext_dek)):
            plaintext_dek[i] = 0
