import struct
import secrets
import typing
import asyncio
from typing import AsyncGenerator, Protocol, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tenacity import AsyncRetrying, wait_exponential_jitter, stop_after_attempt

from .kms import AbstractKMSProvider, EncryptionContext
from .utils import wipe_memory

class AsyncReader(Protocol):
    """
    Protocol for non-blocking I/O reading directly into mutable buffers.
    Compatible with aiofiles or custom async wrappers around streams.
    """
    async def readinto(self, buffer: Union[bytearray, memoryview]) -> int: ...

class AsyncWriter(Protocol):
    """
    Protocol for non-blocking I/O writing.
    """
    async def write(self, data: bytes) -> int: ...

async def _readexactly_into(reader: AsyncReader, view: memoryview) -> int:
    """Helper to fill the memoryview exactly or stop at EOF without allocating new bytes."""
    total_read = 0
    target = len(view)
    while total_read < target:
        bytes_read = await reader.readinto(view[total_read:])
        if bytes_read == 0:
            break
        total_read += bytes_read
    return total_read

# Magic Number (b'ENV1' 4s), Chunk Size (I 4b), Base Nonce (12s 12b), EDK Length (I 4b)
HEADER_STRUCT = struct.Struct("!4s I 12s I")

async def encrypt_stream(
    reader: AsyncReader,
    kms: AbstractKMSProvider,
    context: EncryptionContext,
    chunk_size: int = 1024 * 1024  # 1MB blocks to optimize CPU/RAM
) -> AsyncGenerator[bytes, None]:
    """
    High-concurrency streaming encryptor using Envelope Encryption.
    Yields the dynamic header followed by AES-GCM encrypted chunks.
    """
    if not context:
        raise ValueError("EncryptionContext is strictly required.")

    pt_dek, edk = await kms.generate_data_key(context)
    base_nonce = secrets.token_bytes(12)
    
    header_fixed = HEADER_STRUCT.pack(b'ENV1', chunk_size, base_nonce, len(edk))
    binary_header = header_fixed + edk
    yield binary_header

    buffer = bytearray(chunk_size)
    view = memoryview(buffer)
    aesgcm = AESGCM(pt_dek)
    
    # WARNING: boto3 outputs immutable bytes. The downstream consumer must handle the yielded plaintext lifecycle.
    del pt_dek

    try:
        chunk_idx = 0
        while True:
            bytes_read = await _readexactly_into(reader, view)
            
            is_last = (bytes_read < chunk_size)
            data_view = view[:bytes_read]
            
            nonce_int = int.from_bytes(base_nonce, 'big') ^ chunk_idx
            block_nonce = nonce_int.to_bytes(12, 'big')
            
            aad = binary_header + struct.pack("!?I", is_last, chunk_idx)
            
            encrypted_chunk = await asyncio.to_thread(aesgcm.encrypt, block_nonce, bytes(data_view), aad)
            
            wipe_memory(buffer)
            yield encrypted_chunk
            
            if is_last:
                break
            chunk_idx += 1
    finally:
        wipe_memory(buffer)
        del view
        del buffer


async def decrypt_stream(
    reader: AsyncReader,
    kms: AbstractKMSProvider,
    context: EncryptionContext
) -> AsyncGenerator[bytes, None]:
    """
    High-concurrency streaming decryptor.
    Reads binary header, decrypts DEK, and yields processed plaintext chunks.
    """
    if not context:
        raise ValueError("EncryptionContext is strictly required.")

    fixed_header_size = HEADER_STRUCT.size
    fixed_header_buf = bytearray(fixed_header_size)
    fixed_view = memoryview(fixed_header_buf)
    
    edk_buf: bytearray = bytearray()
    
    try:
        read_bytes = await _readexactly_into(reader, fixed_view)
        if read_bytes < fixed_header_size:
            raise ValueError("Corrupted Stream: File too short to contain header.")
            
        magic, chunk_size, base_nonce, edk_len = HEADER_STRUCT.unpack(fixed_header_buf)
        if magic != b'ENV1':
            raise ValueError("Corrupted Stream: Invalid magic number.")
            
        edk_buf = bytearray(edk_len)
        edk_view = memoryview(edk_buf)
        read_bytes = await _readexactly_into(reader, edk_view)
        if read_bytes < edk_len:
            raise ValueError("Corrupted Stream: File too short to contain full EDK.")
            
        binary_header = bytes(fixed_header_buf) + bytes(edk_buf)
        
        pt_dek = await kms.decrypt_data_key(bytes(edk_buf), context)
        aesgcm = AESGCM(pt_dek)
        # WARNING: boto3 outputs immutable bytes. The downstream consumer must handle the yielded plaintext lifecycle.
        del pt_dek
        
    finally:
        wipe_memory(fixed_header_buf)
        wipe_memory(edk_buf)

    enc_chunk_size = chunk_size + 16
    buffer = bytearray(enc_chunk_size)
    view = memoryview(buffer)
    
    try:
        chunk_idx = 0
        while True:
            bytes_read = await _readexactly_into(reader, view)
            
            if bytes_read == 0 and chunk_idx > 0:
                break
                
            is_last = (bytes_read < enc_chunk_size)
            
            if bytes_read < 16:
                raise ValueError("Corrupted Stream: Chunk too small to contain AES-GCM tag.")
                
            enc_data_view = view[:bytes_read]
            
            nonce_int = int.from_bytes(base_nonce, 'big') ^ chunk_idx
            block_nonce = nonce_int.to_bytes(12, 'big')
            
            aad = binary_header + struct.pack("!?I", is_last, chunk_idx)
            
            plaintext_chunk = await asyncio.to_thread(aesgcm.decrypt, block_nonce, bytes(enc_data_view), aad)
            
            # WARNING: cryptography outputs immutable bytes. The downstream consumer must handle the yielded plaintext lifecycle.
            yield plaintext_chunk
            
            if is_last:
                break
            chunk_idx += 1
    finally:
        del view
        del buffer


async def pipe_decrypted_stream(
    reader: AsyncReader,
    writer: AsyncWriter,
    kms: AbstractKMSProvider,
    context: EncryptionContext
) -> None:
    """
    Consumes the decrypt_stream generator and writes plaintext directly to a writer.
    Ensures memory is minimized by not retaining plaintext references longer than necessary.
    Includes explicit Exponential Backoff to tolerate partial I/O failures (e.g. S3 drops).
    """
    async for plaintext_chunk in decrypt_stream(reader, kms, context):
        # Fault Tolerance: Re-attempt writing the exact same chunk to survive intermittent network drops
        async for attempt in AsyncRetrying(
            wait=wait_exponential_jitter(initial=1, max=10),
            stop=stop_after_attempt(5),
            reraise=True
        ):
            with attempt:
                await writer.write(plaintext_chunk)
                
        # Force garbage collector cleanup of immutable plaintext buffer
        del plaintext_chunk
