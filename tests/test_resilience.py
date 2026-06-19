import pytest
import typing
from crypto_engine.streams import ResilientAsyncReaderAdapter, AsyncReader

class FailingReader(AsyncReader):
    def __init__(self, data: bytes, start_offset: int, fail_at: int):
        self.data = data
        self.pos = start_offset
        self.fail_at = fail_at

    async def readinto(self, buffer: typing.Union[bytearray, memoryview]) -> int:
        if self.pos >= self.fail_at and self.pos < self.fail_at + 10:
            # Simulate a broken socket midway
            raise ConnectionError("Simulated Drop")
            
        avail = len(self.data) - self.pos
        to_read = min(len(buffer), avail)
        if to_read == 0:
            return 0
            
        buffer[:to_read] = self.data[self.pos:self.pos+to_read]
        self.pos += to_read
        return to_read

@pytest.mark.asyncio
async def test_resilient_reader_adapter():
    data = b"Hello World! " * 1000 # ~13KB
    
    fail_state = {"failed_once": False}
    
    async def reader_factory(offset: int) -> AsyncReader:
        # We want it to fail at byte 5000 if it hasn't failed yet
        if not fail_state["failed_once"] and offset <= 5000:
            fail_at = 5000
            fail_state["failed_once"] = True
        else:
            fail_at = 999999 # won't fail anymore
            
        return FailingReader(data, offset, fail_at)
        
    resilient_reader = ResilientAsyncReaderAdapter(reader_factory)
    
    out_buf = bytearray(len(data))
    view = memoryview(out_buf)
    
    total_read = 0
    # Read in small chunks of 1024 bytes
    while total_read < len(data):
        chunk_view = view[total_read:total_read+1024]
        read = await resilient_reader.readinto(chunk_view)
        if read == 0:
            break
        total_read += read
        
    assert bytes(out_buf) == data
    assert fail_state["failed_once"] == True
