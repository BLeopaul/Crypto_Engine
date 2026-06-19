import abc
import secrets
import typing
from typing import Dict, Tuple, Any


from tenacity import (
    retry,
    wait_exponential_jitter,
    stop_after_attempt,
)

# Security Rationale: Encryption Context must be enforced to cryptographically bind 
# ciphertext to a specific environment/purpose, preventing cross-environment decryption attacks.
EncryptionContext = Dict[str, str]

class AbstractKMSProvider(abc.ABC):
    """Hexagonal Architecture: Port for Key Management Systems."""
    @abc.abstractmethod
    async def generate_data_key(self, context: EncryptionContext) -> Tuple[bytes, bytes]:
        """Returns (plaintext_key, encrypted_key)."""
        pass

    @abc.abstractmethod
    async def decrypt_data_key(self, encrypted_key: bytes, context: EncryptionContext) -> bytes:
        """Returns plaintext_key."""
        pass

class MockKMSProvider(AbstractKMSProvider):
    """Local CI/CD Testing adapter."""
    async def generate_data_key(self, context: EncryptionContext) -> Tuple[bytes, bytes]:
        if not context:
            raise ValueError("EncryptionContext is strictly required.")
        pt_key = secrets.token_bytes(32)  # AES-256
        enc_key = b"MOCK_KMS:" + pt_key
        return pt_key, enc_key

    async def decrypt_data_key(self, encrypted_key: bytes, context: EncryptionContext) -> bytes:
        if not context:
            raise ValueError("EncryptionContext is strictly required.")
        if not encrypted_key.startswith(b"MOCK_KMS:"):
            raise ValueError("Invalid KMS key format.")
        return encrypted_key[9:]

class AWSKMSProvider(AbstractKMSProvider):
    """Production AWS KMS adapter using non-blocking aiobotocore client."""
    def __init__(self, kms_client: Any, key_id: str):
        # IMPORTANT: The kms_client should ideally be initialized upstream with:
        # botocore.config.Config(retries={'max_attempts': 10, 'mode': 'adaptive'})
        # This wrapper adds an ultimate layer of resilience (Explicit Exponential Backoff)
        # for non-AWS networking errors or 5xx not caught by adaptive mode.
        self.kms_client = kms_client
        self.key_id = key_id

    @retry(
        wait=wait_exponential_jitter(initial=1, max=10),
        stop=stop_after_attempt(5),
        reraise=True
    )
    async def generate_data_key(self, context: EncryptionContext) -> Tuple[bytes, bytes]:
        if not context:
            raise ValueError("EncryptionContext is strictly required.")
        response = await self.kms_client.generate_data_key(
            KeyId=self.key_id,
            KeySpec='AES_256',
            EncryptionContext=context
        )
        return response['Plaintext'], response['CiphertextBlob']

    @retry(
        wait=wait_exponential_jitter(initial=1, max=10),
        stop=stop_after_attempt(5),
        reraise=True
    )
    async def decrypt_data_key(self, encrypted_key: bytes, context: EncryptionContext) -> bytes:
        if not context:
            raise ValueError("EncryptionContext is strictly required.")
        response = await self.kms_client.decrypt(
            CiphertextBlob=encrypted_key,
            EncryptionContext=context
        )
        return response['Plaintext']
