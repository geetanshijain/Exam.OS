import base64
import logging
import os
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)


class KMSKeyStore:
    """
    Isolated Key Management Service (KMS) / HSM interface.
    Maintains Master Key Encryption Keys (KEKs) strictly separated from paper storage.
    Enforces key versioning and key rotation procedures.
    """

    def __init__(self, primary_secret: str | None = None):
        self._keys: dict[str, bytes] = {}
        # Initialize primary master key (KEK v1)
        if primary_secret and len(primary_secret) >= 32:
            seed = primary_secret[:32].encode("utf-8")
        else:
            seed = get_random_bytes(32)
        self._keys["v1"] = seed
        self._active_version = "v1"

    @property
    def active_version(self) -> str:
        return self._active_version

    def wrap_dek(self, plaintext_dek: bytes, kek_version: str | None = None) -> tuple[str, str]:
        """
        Wraps (encrypts) a Data Encryption Key using AES-256-GCM under the designated KEK version.
        Returns: (wrapped_dek_b64, kek_version)
        """
        version = kek_version or self._active_version
        kek = self._keys.get(version)
        if not kek:
            raise ValueError(f"KMS KEK version '{version}' not found in key store.")

        # Encrypt DEK with KEK
        cipher = AES.new(kek, AES.MODE_GCM)
        cipher.update(f"KMS_DEK_ENVELOPE_{version}".encode("utf-8"))
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_dek)

        # Pack nonce (16) + tag (16) + ciphertext (32) into single base64 envelope
        payload = cipher.nonce + tag + ciphertext
        wrapped_b64 = base64.b64encode(payload).decode("ascii")
        return wrapped_b64, version

    def unwrap_dek(self, wrapped_dek_b64: str, kek_version: str) -> bytes:
        """
        Unwraps (decrypts) a Data Encryption Key using AES-256-GCM under the specified KEK version.
        Verifies the KMS authentication tag.
        """
        kek = self._keys.get(kek_version)
        if not kek:
            raise ValueError(f"KMS KEK version '{kek_version}' not found in key store.")

        raw_payload = base64.b64decode(wrapped_dek_b64)
        if len(raw_payload) < 32:
            raise ValueError("Corrupt wrapped DEK payload.")

        nonce = raw_payload[:16]
        tag = raw_payload[16:32]
        ciphertext = raw_payload[32:]

        cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
        cipher.update(f"KMS_DEK_ENVELOPE_{kek_version}".encode("utf-8"))
        
        try:
            plaintext_dek = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext_dek
        except ValueError as exc:
            raise ValueError("KMS DEK unwrapping failed: Authentication tag verification failed.") from exc

    def rotate_master_key(self) -> str:
        """
        Generates a new Master Key (KEK) version and updates the active version.
        Existing keys remain in the key store to allow unwrapping and re-wrapping.
        """
        new_version_num = len(self._keys) + 1
        new_version = f"v{new_version_num}"
        new_kek = get_random_bytes(32)
        self._keys[new_version] = new_kek
        self._active_version = new_version
        logger.info(f"KMS Master Key rotated successfully. New active version: {new_version}")
        return new_version

    def rewrap_dek(self, wrapped_dek_b64: str, old_version: str, new_version: str) -> str:
        """
        Re-encrypts a DEK from an old KEK version to a new KEK version without
        decrypting the underlying paper ciphertext.
        """
        plaintext_dek = self.unwrap_dek(wrapped_dek_b64, old_version)
        new_wrapped, _ = self.wrap_dek(plaintext_dek, new_version)
        return new_wrapped


# Global singleton KMS client instance
kms_client = KMSKeyStore(primary_secret=os.environ.get("EXAMOS_KMS_MASTER_SECRET"))
