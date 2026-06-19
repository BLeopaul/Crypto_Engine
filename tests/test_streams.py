import pytest
import io
import typing
from crypto_engine.kms import MockKMSProvider, EncryptionContext
from crypto_engine.streams import encrypt_stream, pipe_decrypted_stream

class MemoryAsyncReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    async def readinto(self, buffer: typing.Union[bytearray, memoryview]) -> int:
        available = len(self.data) - self.pos
        to_read = min(len(buffer), available)
        if to_read == 0:
            return 0
        buffer[:to_read] = self.data[self.pos:self.pos + to_read]
        self.pos += to_read
        return to_read

class UnstableMemoryAsyncWriter:
    def __init__(self):
        self.buffer = bytearray()
        self.fail_countdown = 2  # Fail the first 2 times a chunk is written

    async def write(self, data: bytes) -> int:
        if self.fail_countdown > 0:
            self.fail_countdown -= 1
            raise ConnectionError("Simulated network drop")
        # Reset countdown for the next chunk to prove it can survive multiple drops
        self.fail_countdown = 1
        
        self.buffer.extend(data)
        return len(data)

class EncryptStreamAdapter(MemoryAsyncReader):
    """
    Consumes the encrypt_stream async generator to expose it as an AsyncReader
    so that decrypt_stream can read it.
    """
    def __init__(self, generator: typing.AsyncGenerator[bytes, None]):
        self.generator = generator
        self.internal_buffer = bytearray()

    async def readinto(self, buffer: typing.Union[bytearray, memoryview]) -> int:
        # Fill internal buffer if empty
        if not self.internal_buffer:
            try:
                chunk = await self.generator.__anext__()
                self.internal_buffer.extend(chunk)
            except StopAsyncIteration:
                pass

        if not self.internal_buffer:
            return 0

        # Read from internal buffer into the requested buffer
        to_read = min(len(buffer), len(self.internal_buffer))
        buffer[:to_read] = self.internal_buffer[:to_read]
        del self.internal_buffer[:to_read]
        return to_read


@pytest.mark.asyncio
async def test_encrypt_decrypt_stream_with_retries():
    # 1. Prepare data and KMS
    plaintext = b"A" * (2 * 1024 * 1024 + 123)  # Just over 2MB
    reader = MemoryAsyncReader(plaintext)
    writer = UnstableMemoryAsyncWriter()
    kms = MockKMSProvider()
    context: EncryptionContext = {"project": "test", "env": "ci"}

    # 2. Encrypt
    enc_gen = encrypt_stream(reader, kms, context, chunk_size=1024*1024)
    enc_reader = EncryptStreamAdapter(enc_gen)

    # 3. Decrypt and Pipe
    await pipe_decrypted_stream(enc_reader, writer, kms, context)

    # 4. Verify
    assert writer.buffer == plaintext
