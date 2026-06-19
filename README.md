# Crypto Engine

Crypto Engine is a production-grade, highly concurrent, and asynchronous Python module designed for encrypting and decrypting gigabytes of sensitive file streams. 

Built with stringent security requirements, this module utilizes Envelope Encryption, integrates with AWS KMS, implements strict anti-forensic memory hygiene, and includes network resilience mechanisms to survive scale and I/O intermittent failures.

## Features

- **Envelope Encryption**: Generates a unique Data Encryption Key (DEK) for every processed file via a Key Management Service (KMS), mathematically bound to a specific Encryption Context.
- **Asynchronous I/O (Non-Blocking)**: Implemented as asynchronous Python generators (`AsyncGenerator`), allowing orchestration layers to handle massive throughput (e.g., local disk, S3, network) without blocking the CPU.
- **Best-effort Memory Hygiene**: Reduces RAM footprint by explicitly zeroing sensitive mutable I/O buffers in C-land (via `ctypes.memset`), though inherently limited by CPython's immutable `bytes` lifecycles.
- **Indivisible Cryptographic Seal**: Uses AES-GCM. The dynamic binary header, sequence indices, and truncation flags are bound into the Additional Authenticated Data (AAD) to mathematically prevent chunk reordering, header manipulation, and perfect-truncation attacks.
- **Network Resilience**: 
  - AWS KMS API calls are protected against `ThrottlingException` (HTTP 429) via Exponential Backoff and Jitter.
  - Partial I/O failures (e.g., micro-cuts when writing to an S3 bucket) are tolerated through asynchronous chunk-level retries.

## Prerequisites

- Python 3.10+
- [Poetry](https://python-poetry.org/) (Dependency Management)

## Installation

Clone the repository and install the dependencies using Poetry:

```bash
cd crypto-engine
poetry install
```

This will create an isolated virtual environment and install both production dependencies (`cryptography`, `aiobotocore`, `tenacity`) and development tools (`pytest`, `ruff`, `mypy`).

## Architecture

The project strictly follows the Separation of Concerns principle (Hexagonal Architecture):

- `kms.py`: Defines the `AbstractKMSProvider` port and provides adapters (`AWSKMSProvider`, `MockKMSProvider`). Manages network retry policies for external key services.
- `streams.py`: Contains the core asynchronous generators (`encrypt_stream`, `decrypt_stream`) and the `pipe_decrypted_stream` orchestrator.
- `utils.py`: Low-level cryptographic plumbing, including secure memory wiping.

## Usage

### 1. Implementing the Interfaces

The engine requires objects complying with the `AsyncReader` and `AsyncWriter` protocols. These can be asynchronous file wrappers (like `aiofiles`) or custom network stream implementations.

### 2. Encryption

```python
import asyncio
from crypto_engine import encrypt_stream, AWSKMSProvider

async def encrypt_data(reader, kms_client):
    kms = AWSKMSProvider(kms_client=kms_client, key_id="arn:aws:kms:region:account:key/id")
    context = {"project": "finance", "classification": "restricted"}

    # encrypt_stream yields an asynchronous stream of AES-GCM encrypted chunks
    async for encrypted_chunk in encrypt_stream(reader, kms, context):
        # Handle the encrypted chunk (e.g., write to S3, send over network)
        pass
```

### 3. Decryption

```python
import asyncio
from crypto_engine import pipe_decrypted_stream, AWSKMSProvider

async def decrypt_data(reader, writer, kms_client):
    kms = AWSKMSProvider(kms_client=kms_client, key_id="arn:aws:kms:region:account:key/id")
    context = {"project": "finance", "classification": "restricted"}

    # The pipe automatically handles decryption, I/O resilience, and memory clearing
    await pipe_decrypted_stream(reader, writer, kms, context)
```

## Testing and Quality Assurance

The project enforces strict software quality gates. A GitHub Actions pipeline runs on every push and pull request.

To run the checks locally:

**1. Type Checking:**
```bash
poetry run mypy src/ tests/
```

**2. Linting:**
```bash
poetry run ruff check .
```

**3. Unit Tests:**
Tests are executed asynchronously using `pytest-asyncio`, utilizing the internal `MockKMSProvider` and simulating network throttling conditions.
```bash
poetry run pytest -v
```
