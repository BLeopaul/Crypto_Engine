import time
import asyncio
import tracemalloc
from crypto_engine.kms import MockKMSProvider
from crypto_engine.streams import encrypt_stream, decrypt_stream, AsyncReader

class DummyAsyncReader(AsyncReader):
    def __init__(self, total_size: int):
        self.total_size = total_size
        self.read_so_far = 0
        self.dummy_data = b"0" * (1024 * 1024)

    async def readinto(self, buffer: memoryview) -> int:
        if self.read_so_far >= self.total_size:
            return 0
        to_read = min(len(buffer), self.total_size - self.read_so_far, len(self.dummy_data))
        buffer[:to_read] = self.dummy_data[:to_read]
        self.read_so_far += to_read
        return to_read

class ListAsyncReader(AsyncReader):
    def __init__(self, chunks: list[bytearray]):
        self.chunks = chunks
        self.chunk_idx = 0
        self.pos = 0

    async def readinto(self, buffer: memoryview) -> int:
        if self.chunk_idx >= len(self.chunks):
            return 0
        chunk = self.chunks[self.chunk_idx]
        avail = len(chunk) - self.pos
        to_read = min(len(buffer), avail)
        buffer[:to_read] = chunk[self.pos:self.pos+to_read]
        self.pos += to_read
        if self.pos >= len(chunk):
            self.chunk_idx += 1
            self.pos = 0
        return to_read

async def run_benchmark(size_mb: int):
    print(f"\n--- Benchmarking {size_mb} MB ---")
    total_bytes = size_mb * 1024 * 1024
    kms = MockKMSProvider()
    context = {"purpose": "benchmark"}
    
    reader = DummyAsyncReader(total_bytes)
    encrypted_chunks = []
    
    tracemalloc.start()
    
    start_enc = time.perf_counter()
    async for chunk in encrypt_stream(reader, kms, context):
        encrypted_chunks.append(chunk)
    end_enc = time.perf_counter()
    
    current, peak = tracemalloc.get_traced_memory()
    print(f"Encryption Peak RAM: {peak / 10**6:.2f} MB")
    
    enc_time = end_enc - start_enc
    enc_throughput = size_mb / enc_time if enc_time > 0 else 0
    print(f"Encryption Time: {enc_time:.2f} s ({enc_throughput:.2f} MB/s)")
    
    # Decryption
    dec_reader = ListAsyncReader(encrypted_chunks)
    
    tracemalloc.clear_traces()
    
    start_dec = time.perf_counter()
    async for plaintext_chunk in decrypt_stream(dec_reader, kms, context):
        pass # Discard to simulate pure throughput
    end_dec = time.perf_counter()
    
    current, peak = tracemalloc.get_traced_memory()
    print(f"Decryption Peak RAM: {peak / 10**6:.2f} MB")
    tracemalloc.stop()
    
    dec_time = end_dec - start_dec
    dec_throughput = size_mb / dec_time if dec_time > 0 else 0
    print(f"Decryption Time: {dec_time:.2f} s ({dec_throughput:.2f} MB/s)")

async def main():
    await run_benchmark(100)
    await run_benchmark(500)

if __name__ == "__main__":
    asyncio.run(main())
