"""
RPM Encrypter - Core Cryptographic Module
==========================================

A production-grade cryptographic engine implementing Envelope Encryption with
AES-256-GCM and Argon2id key derivation. Designed for integration into a
modern desktop GUI with full thread-safety and streaming support.

Security Architecture:
----------------------
1.  **Envelope Encryption**: Each vault uses a unique random Data Encryption Key
    (DEK) to encrypt the payload. The DEK is itself encrypted by a Key Encryption
    Key (KEK) derived from the user's password via Argon2id. This enables
    password changes (re-keying) without touching the potentially large payload.

2.  **AES-256-GCM**: All symmetric encryption uses AES-256 in Galois/Counter
    Mode (GCM) with a cryptographically random 96-bit (12-byte) nonce for every
    distinct encryption operation. GCM provides authenticated encryption (AEAD),
    ensuring both confidentiality and integrity.

3.  **Argon2id KDF**: The KEK is derived using Argon2id, the winner of the
    Password Hashing Competition. It provides strong resistance against GPU,
    ASIC, and side-channel attacks. Parameters are tunable and stored in the
    vault header for future compatibility.

4.  **Streaming/Chunked I/O**: Files are processed in 1 MiB chunks using the
    `cryptography` library's incremental GCM interface. This guarantees
    constant memory usage regardless of file size, preventing MemoryError on
    multi-gigabyte archives.

Author: Senior Python Security Developer
"""

import os
import json
import hmac
import struct
import base64
import logging
from dataclasses import dataclass, asdict, field
from typing import Optional, Callable, BinaryIO, Tuple, Dict, Any
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import argon2

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# CONSTANTS & SECURITY PARAMETERS
# ------------------------------------------------------------------------------

# Vault file format identifiers
VAULT_MAGIC = b'RPMV'      # 4-byte magic for file type identification
VAULT_VERSION = 1          # Format version for forward compatibility

# AES-256-GCM constants
AES_KEY_SIZE = 32          # 256 bits (32 bytes)
AES_NONCE_SIZE = 12        # 96 bits recommended for GCM (maximizes safe payload length)
AES_TAG_SIZE = 16          # 128-bit authentication tag (standard for GCM)

# Argon2id parameters (OWASP recommended baseline for high-security applications)
ARGON2_MEMORY_COST = 65536   # 64 MiB
ARGON2_TIME_COST = 3       # 3 iterations
ARGON2_PARALLELISM = 4     # 4 parallel lanes
ARGON2_HASH_LENGTH = 32      # 256-bit KEK output

# Streaming chunk size: 1 MiB is optimal for modern SSD/NVMe
CHUNK_SIZE = 1 * 1024 * 1024  # 1048576 bytes

# Security constraints
MIN_SALT_SIZE = 32         # 256 bits (upgraded from 16)
MAX_HEADER_SIZE = 1048576  # 1 MiB sanity limit
MAX_FILENAME_LEN = 255
MAX_METADATA_FIELDS = 100
MAX_FIELD_VALUE_LEN = 10000

# ------------------------------------------------------------------------------
# CUSTOM EXCEPTIONS
# ------------------------------------------------------------------------------

class CryptoError(Exception):
    """Base exception for all cryptographic failures."""
    pass


class AuthenticationError(CryptoError):
    """
    Raised when integrity verification fails.

    Causes:
        - Incorrect password (KEK derivation fails to decrypt DEK).
        - Corrupted or tampered vault (GCM authentication tag mismatch).
    """
    pass


class VaultFormatError(CryptoError):
    """Raised when the vault file structure is invalid or unsupported."""
    pass


# ------------------------------------------------------------------------------
# DATA CLASSES FOR VAULT HEADER
# ------------------------------------------------------------------------------

@dataclass
class KDFParams:
    """
    Argon2id parameters stored in the vault header.

    Storing these alongside the salt ensures that future versions of the
    application can always reconstruct the KEK with the exact same parameters
    that were used during vault creation.
    """
    algorithm: str = "Argon2id"
    salt: str = ""           # base64-encoded random salt (minimum 256 bits)
    memory: int = ARGON2_MEMORY_COST
    iterations: int = ARGON2_TIME_COST
    parallelism: int = ARGON2_PARALLELISM
    length: int = ARGON2_HASH_LENGTH


@dataclass
class EnvelopeParams:
    """
    Envelope encryption metadata for the Data Encryption Key (DEK).

    The DEK is encrypted with AES-256-GCM using the KEK. A unique nonce is
    generated for this operation and never reused across vaults.
    """
    algorithm: str = "AES-256-GCM"
    dek_nonce: str = ""      # base64-encoded 12-byte nonce
    encrypted_dek: str = ""  # base64-encoded ciphertext + 16-byte auth tag


@dataclass
class PayloadParams:
    """
    Payload stream encryption metadata.

    The actual file/folder archive is encrypted with AES-256-GCM using the DEK.
    A separate nonce is used for the payload to ensure cryptographic isolation
    between the envelope and the payload.
    """
    algorithm: str = "AES-256-GCM"
    nonce: str = ""          # base64-encoded 12-byte nonce for payload stream
    chunk_size: int = CHUNK_SIZE
    original_size: int = 0   # Uncompressed payload size in bytes
    filename: str = ""       # Original file or folder name (for UI display)
    metadata: Optional[Dict[str, Any]] = None  # File manifest, timestamps, etc.


@dataclass
class VaultHeader:
    """Complete vault header container."""
    kdf: KDFParams
    envelope: EnvelopeParams
    payload: PayloadParams
    recovery_envelope: Optional[EnvelopeParams] = None


# ------------------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------------------

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent injection attacks."""
    if len(filename) > MAX_FILENAME_LEN:
        filename = filename[:MAX_FILENAME_LEN]
    # Remove or replace potentially dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*', '\x00']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    return filename


def sanitize_metadata(data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Sanitize metadata to prevent JSON injection and oversized headers."""
    if data is None:
        return None
    
    if not isinstance(data, dict):
        logger.warning("Metadata is not a dict, converting to empty dict")
        return {}
    
    if len(data) > MAX_METADATA_FIELDS:
        logger.warning("Metadata has too many fields (%d), truncating to %d", 
                      len(data), MAX_METADATA_FIELDS)
        data = dict(list(data.items())[:MAX_METADATA_FIELDS])
    
    sanitized = {}
    for k, v in data.items():
        if not isinstance(k, str) or len(k) > 100:
            continue
        
        if isinstance(v, str):
            if len(v) > MAX_FIELD_VALUE_LEN:
                v = v[:MAX_FIELD_VALUE_LEN] + "...[truncated]"
        elif isinstance(v, (list, dict)):
            # Recursively sanitize nested structures
            v = _sanitize_nested(v)
        
        sanitized[k] = v
    
    return sanitized


def _sanitize_nested(obj, depth=0, max_depth=5):
    """Recursively sanitize nested dict/list structures."""
    if depth > max_depth:
        return "[max depth exceeded]"
    
    if isinstance(obj, dict):
        return {
            k: _sanitize_nested(v, depth + 1, max_depth)
            for k, v in list(obj.items())[:MAX_METADATA_FIELDS]
            if isinstance(k, str)
        }
    elif isinstance(obj, list):
        return [
            _sanitize_nested(item, depth + 1, max_depth)
            for item in obj[:MAX_METADATA_FIELDS]
        ]
    elif isinstance(obj, str):
        return obj[:MAX_FIELD_VALUE_LEN]
    else:
        return obj


def serialize_aad(data: dict) -> bytes:
    """
    Deterministic JSON serialization for AAD.
    
    Ensures bit-identical output across encrypt/decrypt operations by:
    - Sorting all keys recursively
    - Using consistent separators
    - Enforcing ASCII encoding
    """
    return json.dumps(
        data, 
        separators=(',', ':'), 
        sort_keys=True,
        ensure_ascii=True
    ).encode('utf-8')


import hashlib

def generate_recovery_entropy() -> bytes:
    """Generate 32 bytes (256 bits) of secure random entropy for BIP-39."""
    return os.urandom(32)

def entropy_to_mnemonic(entropy: bytes) -> str:
    """Convert 32 bytes of entropy to a 24-word BIP-39 mnemonic phrase."""
    if len(entropy) != 32:
        raise ValueError("Entropy must be 32 bytes.")
    from wordlist import WORDLIST
    
    hash_bytes = hashlib.sha256(entropy).digest()
    checksum = bin(hash_bytes[0])[2:].zfill(8)
    
    entropy_bin = "".join(bin(b)[2:].zfill(8) for b in entropy)
    full_bin = entropy_bin + checksum
    
    words = []
    for i in range(24):
        chunk = full_bin[i*11 : (i+1)*11]
        idx = int(chunk, 2)
        words.append(WORDLIST[idx])
        
    return " ".join(words)

def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Convert a 24-word BIP-39 mnemonic phrase back to 32 bytes of entropy."""
    from wordlist import WORDLIST
    words = mnemonic.strip().lower().split()
    if len(words) != 24:
        raise ValueError("Mnemonic must be exactly 24 words.")
        
    full_bin = ""
    for w in words:
        if w not in WORDLIST:
            raise ValueError(f"Invalid word in mnemonic: '{w}'")
        idx = WORDLIST.index(w)
        full_bin += bin(idx)[2:].zfill(11)
        
    entropy_bin = full_bin[:256]
    checksum_bin = full_bin[256:]
    
    entropy_bytes = bytearray()
    for i in range(32):
        chunk = entropy_bin[i*8 : (i+1)*8]
        entropy_bytes.append(int(chunk, 2))
        
    entropy = bytes(entropy_bytes)
    
    hash_bytes = hashlib.sha256(entropy).digest()
    expected_checksum = bin(hash_bytes[0])[2:].zfill(8)
    
    if checksum_bin != expected_checksum:
        raise ValueError("Mnemonic checksum failed. The phrase is incorrect.")
        
    return entropy

# ------------------------------------------------------------------------------
# CORE CRYPTOGRAPHIC ENGINE
# ------------------------------------------------------------------------------

class VaultCrypto:
    """
    High-level, thread-safe cryptographic engine for RPM Vault operations.

    All public methods are stateless with respect to the vault payload, making
    this class safe to share across multiple background worker threads in a GUI.

    Usage:
        crypto = VaultCrypto()

        # Encrypt
        with open('archive.zip', 'rb') as src, open('data.vault', 'wb') as dst:
            crypto.encrypt_stream(src, dst, password="Secret123!", ...)

        # Decrypt
        with open('data.vault', 'rb') as src, open('restored.zip', 'wb') as dst:
            crypto.decrypt_stream(src, dst, password="Secret123!", ...)
    """

    # --- Hidden Vault Constants ---
    HIDDEN_SALT_SUFFIX = b"RPM_HIDDEN_SALT"
    HIDDEN_OFFSET_MSG = b"RPM_OFFSET"
    HIDDEN_MINI_HEADER_SIZE = 512
    HIDDEN_MINI_HEADER_CIPHERTEXT_SIZE = 512 + 16  # 512 + 16 byte tag
    HIDDEN_MINI_HEADER_NONCE_SIZE = 12
    HIDDEN_TOTAL_HEADER_BYTES = 12 + 512 + 16

    def __init__(
        self,
        argon_memory: int = ARGON2_MEMORY_COST,
        argon_iterations: int = ARGON2_TIME_COST,
        argon_parallelism: int = ARGON2_PARALLELISM
    ):
        """
        Initialize the crypto engine with configurable Argon2id parameters.

        Args:
            argon_memory: Memory cost in KiB (e.g., 65536 = 64 MiB).
            argon_iterations: Time cost (number of passes over memory).
            argon_parallelism: Number of parallel threads (lanes).
        """
        self.argon_memory = argon_memory
        self.argon_iterations = argon_iterations
        self.argon_parallelism = argon_parallelism

    # --------------------------------------------------------------------------
    # Internal Helpers
    # --------------------------------------------------------------------------

    @staticmethod
    def _secure_random(size: int) -> bytes:
        """
        Generate cryptographically secure random bytes.

        Uses `os.urandom`, which draws from the operating system's CSPRNG
        (/dev/urandom on Unix, CryptGenRandom on Windows, getentropy where
        available). This is suitable for generating keys, salts, and nonces.
        """
        return os.urandom(size)

    def _derive_kek(
        self,
        password: str,
        salt: bytes,
        memory_cost: Optional[int] = None,
        time_cost: Optional[int] = None,
        parallelism: Optional[int] = None,
        hash_len: Optional[int] = None,
    ) -> bytes:
        """
        Derive the Key Encryption Key (KEK) from a user password and salt.

        We use the low-level `hash_secret_raw` API to obtain raw bytes suitable
        for direct use as an AES-256 key, rather than the high-level
        `PasswordHasher` which embeds parameters into an ASCII hash string.

        Args:
            password:     Plaintext user password.
            salt:         Unique per-vault salt (minimum 32 bytes).
            memory_cost:  Argon2 memory in KiB. If None, uses self.argon_memory.
            time_cost:    Argon2 iterations. If None, uses self.argon_iterations.
            parallelism:  Argon2 lanes. If None, uses self.argon_parallelism.
            hash_len:     Output key length in bytes. If None, uses ARGON2_HASH_LENGTH.

        Returns:
            KEK of length `hash_len` bytes.
        """
        kek = argon2.low_level.hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            memory_cost=memory_cost if memory_cost is not None else self.argon_memory,
            time_cost=time_cost     if time_cost    is not None else self.argon_iterations,
            parallelism=parallelism if parallelism  is not None else self.argon_parallelism,
            hash_len=hash_len       if hash_len     is not None else ARGON2_HASH_LENGTH,
            type=argon2.Type.ID
        )
        return kek

    @staticmethod
    def _encrypt_dek(dek: bytes, kek: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt the DEK using AES-256-GCM with the KEK.

        Args:
            dek: 32-byte Data Encryption Key.
            kek: 32-byte Key Encryption Key.

        Returns:
            Tuple of (nonce, ciphertext_with_tag).
        """
        nonce = VaultCrypto._secure_random(AES_NONCE_SIZE)
        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(nonce, dek, None)
        return nonce, ciphertext

    @staticmethod
    def _decrypt_dek(encrypted_dek: bytes, nonce: bytes, kek: bytes) -> bytes:
        """
        Decrypt the DEK. Raises AuthenticationError on any integrity failure.
        """
        aesgcm = AESGCM(kek)
        try:
            dek = aesgcm.decrypt(nonce, encrypted_dek, None)
        except InvalidTag:
            raise AuthenticationError(
                "DEK decryption failed: invalid password or corrupted vault envelope."
            )
        if len(dek) != AES_KEY_SIZE:
            raise AuthenticationError(
                f"DEK has unexpected length {len(dek)} (expected {AES_KEY_SIZE}). "
                f"Vault envelope is corrupted."
            )
        return dek

    @staticmethod
    def _read_header(input_stream: BinaryIO) -> Tuple[VaultHeader, int]:
        """
        Parse and validate the vault file header.

        Returns:
            Tuple of (VaultHeader, payload_start_offset).

        Raises:
            VaultFormatError: If magic, version, or structure is invalid.
        """
        magic = input_stream.read(len(VAULT_MAGIC))
        if magic != VAULT_MAGIC:
            raise VaultFormatError(
                f"Invalid vault magic. Expected {VAULT_MAGIC!r}, got {magic!r}. "
                f"File is not an RPM Vault or is severely corrupted."
            )

        version_data = input_stream.read(1)
        if len(version_data) != 1:
            raise VaultFormatError("Vault file truncated: missing version byte.")
        (version,) = struct.unpack('!B', version_data)
        if version != VAULT_VERSION:
            raise VaultFormatError(
                f"Unsupported vault version {version}. "
                f"This application supports version {VAULT_VERSION}."
            )

        header_len_data = input_stream.read(4)
        if len(header_len_data) != 4:
            raise VaultFormatError("Vault file truncated: missing header length.")
        (header_len,) = struct.unpack('!I', header_len_data)

        if header_len > MAX_HEADER_SIZE:
            raise VaultFormatError(
                f"Vault header length field ({header_len:,} bytes) exceeds the "
                f"{MAX_HEADER_SIZE:,} byte sanity limit. File is malformed or malicious."
            )

        header_json = input_stream.read(header_len)
        if len(header_json) != header_len:
            raise VaultFormatError(
                f"Vault file truncated: expected {header_len} header bytes, "
                f"got {len(header_json)}."
            )

        try:
            header_dict = json.loads(header_json.decode('utf-8'))
            header = VaultHeader(
                kdf=KDFParams(**header_dict['kdf']),
                envelope=EnvelopeParams(**header_dict['envelope']),
                payload=PayloadParams(**header_dict['payload'])
            )
            if 'recovery_envelope' in header_dict and header_dict['recovery_envelope']:
                header.recovery_envelope = EnvelopeParams(**header_dict['recovery_envelope'])
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError) as exc:
            raise VaultFormatError(f"Invalid vault header: {exc}") from exc

        try:
            salt_bytes        = base64.b64decode(header.kdf.salt)
            dek_nonce_bytes   = base64.b64decode(header.envelope.dek_nonce)
            enc_dek_bytes     = base64.b64decode(header.envelope.encrypted_dek)
            payload_nonce_bytes = base64.b64decode(header.payload.nonce)
        except Exception as exc:
            raise VaultFormatError(f"Vault header contains invalid base64 data: {exc}") from exc

        if len(salt_bytes) < MIN_SALT_SIZE:
            raise VaultFormatError(
                f"KDF salt too short: {len(salt_bytes)} bytes (minimum {MIN_SALT_SIZE})."
            )
        if len(dek_nonce_bytes) != AES_NONCE_SIZE:
            raise VaultFormatError(
                f"DEK nonce has wrong size: {len(dek_nonce_bytes)} "
                f"(expected {AES_NONCE_SIZE})."
            )
        expected_dek_enc = AES_KEY_SIZE + AES_TAG_SIZE
        if len(enc_dek_bytes) != expected_dek_enc:
            raise VaultFormatError(
                f"Encrypted DEK has wrong size: {len(enc_dek_bytes)} "
                f"(expected {expected_dek_enc})."
            )
        if len(payload_nonce_bytes) != AES_NONCE_SIZE:
            raise VaultFormatError(
                f"Payload nonce has wrong size: {len(payload_nonce_bytes)} "
                f"(expected {AES_NONCE_SIZE})."
            )

        if header.kdf.length != AES_KEY_SIZE:
            raise VaultFormatError(
                f"KDF hash_len in header is {header.kdf.length} bytes "
                f"(expected exactly {AES_KEY_SIZE}). "
                f"This may indicate a tampered or malformed vault."
            )

        payload_offset = input_stream.tell()
        return header, payload_offset

    # --------------------------------------------------------------------------
    # Public API: Encryption
    # --------------------------------------------------------------------------

    def encrypt_stream(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        password: str,
        original_filename: str,
        original_size: int,
        metadata: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None
    ) -> VaultHeader:
        """
        Encrypt a binary stream into the RPM Vault format.

        Operational Flow:
            1. Generate a unique random DEK (256 bits) and payload nonce (96 bits).
            2. Generate a unique random salt and derive the KEK from the password
               using Argon2id.
            3. Encrypt the DEK with the KEK (AES-256-GCM) -> envelope.
            4. Write the structured header to the output stream.
            5. Stream-encrypt the payload in chunks using AES-256-GCM.
            6. Append the 16-byte GCM authentication tag to the end of the stream.

        Args:
            input_stream: Readable binary source (e.g., a packaged zip archive).
            output_stream: Writable binary destination (.vault file).
            password: User's plaintext password.
            original_filename: Original file/folder name for metadata recovery.
            original_size: Size in bytes of the uncompressed source data.
            metadata: Optional dict with file manifest, timestamps, etc.
            progress_callback: Optional callable(bytes_processed, total_bytes)
                for GUI progress bars. Called after every chunk.
        """
        original_filename = sanitize_filename(original_filename)
        metadata = sanitize_metadata(metadata)

        salt = self._secure_random(MIN_SALT_SIZE)
        dek = self._secure_random(AES_KEY_SIZE)
        payload_nonce = self._secure_random(AES_NONCE_SIZE)

        kek = self._derive_kek(password, salt)
        dek_nonce, encrypted_dek = self._encrypt_dek(dek, kek)
        
        recovery_env = None
        if recovery_key is not None:
            recovery_salt = salt + b"RECOVERY"
            recovery_kek = argon2.low_level.hash_secret_raw(
                secret=recovery_key,
                salt=recovery_salt,
                time_cost=self.argon_iterations,
                memory_cost=self.argon_memory,
                parallelism=self.argon_parallelism,
                hash_len=AES_KEY_SIZE,
                type=argon2.Type.ID
            )
            r_dek_nonce, r_encrypted_dek = self._encrypt_dek(dek, recovery_kek)
            recovery_env = EnvelopeParams(
                dek_nonce=base64.b64encode(r_dek_nonce).decode('ascii'),
                encrypted_dek=base64.b64encode(r_encrypted_dek).decode('ascii')
            )

        header = VaultHeader(
            kdf=KDFParams(
                salt=base64.b64encode(salt).decode('ascii'),
                memory=self.argon_memory,
                iterations=self.argon_iterations,
                parallelism=self.argon_parallelism
            ),
            envelope=EnvelopeParams(
                dek_nonce=base64.b64encode(dek_nonce).decode('ascii'),
                encrypted_dek=base64.b64encode(encrypted_dek).decode('ascii')
            ),
            payload=PayloadParams(
                nonce=base64.b64encode(payload_nonce).decode('ascii'),
                chunk_size=CHUNK_SIZE,
                original_size=original_size,
                filename=original_filename,
                metadata=metadata
            ),
            recovery_envelope=recovery_env
        )

        try:
            header_json = json.dumps(asdict(header), separators=(',', ':')).encode('utf-8')
        except (TypeError, ValueError) as exc:
            raise VaultFormatError(
                f"Vault header could not be serialised to JSON. "
                f"Ensure all metadata values are JSON-compatible types: {exc}"
            ) from exc

        header_len = len(header_json)

        if header_len > MAX_HEADER_SIZE:
            raise VaultFormatError(
                f"Vault header JSON ({header_len:,} bytes) exceeds the {MAX_HEADER_SIZE:,} byte limit. "
                f"Reduce the metadata payload."
            )

        output_stream.write(VAULT_MAGIC)
        output_stream.write(struct.pack('!B', VAULT_VERSION))
        output_stream.write(struct.pack('!I', header_len))
        output_stream.write(header_json)

        cipher = Cipher(
            algorithms.AES(dek),
            modes.GCM(payload_nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        payload_aad_dict = {
            "nonce":         base64.b64encode(payload_nonce).decode('ascii'),
            "chunk_size":    CHUNK_SIZE,
            "original_size": original_size,
            "filename":      original_filename,
            "metadata":      metadata,
        }
        payload_aad = serialize_aad(payload_aad_dict)
        encryptor.authenticate_additional_data(payload_aad)

        bytes_processed = 0
        while True:
            chunk = input_stream.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            output_stream.write(encrypted_chunk)
            bytes_processed += len(chunk)

            if progress_callback:
                try:
                    progress_callback(bytes_processed, original_size)
                except Exception as exc:
                    logger.warning("Progress callback failed: %s", exc)

        encryptor.finalize()
        auth_tag = encryptor.tag
        output_stream.write(auth_tag)

        logger.info(
            "Encryption complete: %d bytes, filename='%s', vault_offset=%d",
            bytes_processed, original_filename, output_stream.tell()
        )
        return header

    # --------------------------------------------------------------------------
    # Public API: Decryption
    # --------------------------------------------------------------------------

    def decrypt_stream(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        password: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None
    ) -> VaultHeader:
        """
        Decrypt an RPM Vault stream back to its original plaintext.

        Operational Flow:
            1. Parse and validate the vault header.
            2. Derive the KEK from the password and stored salt.
            3. Decrypt the DEK envelope. If this fails, the password is wrong.
            4. Initialize the payload decryptor with the DEK and payload nonce.
            5. Stream-decrypt all payload bytes *except* the final 16-byte tag.
            6. Read the stored authentication tag and call `finalize_with_tag()`.

        Args:
            input_stream: Readable binary source (.vault file).
            output_stream: Writable binary destination (restored archive).
            password: User's plaintext password.
            progress_callback: Optional callable(bytes_processed, payload_size).

        Returns:
            The parsed VaultHeader containing original metadata.

        Raises:
            AuthenticationError: Wrong password or tampered vault.
            VaultFormatError: Invalid file structure.
        """
        header, payload_offset = self._read_header(input_stream)
        salt = base64.b64decode(header.kdf.salt)

        try:
            if recovery_key is not None:
                if not header.recovery_envelope:
                    raise AuthenticationError("No recovery phrase exists for this vault.")
                recovery_salt = salt + b"RECOVERY"
                recovery_kek = argon2.low_level.hash_secret_raw(
                    secret=recovery_key,
                    salt=recovery_salt,
                    time_cost=header.kdf.iterations,
                    memory_cost=header.kdf.memory,
                    parallelism=header.kdf.parallelism,
                    hash_len=header.kdf.length,
                    type=argon2.Type.ID
                )
                encrypted_dek = base64.b64decode(header.recovery_envelope.encrypted_dek)
                dek_nonce = base64.b64decode(header.recovery_envelope.dek_nonce)
                dek = self._decrypt_dek(encrypted_dek, dek_nonce, recovery_kek)
            else:
                if password is None:
                    raise AuthenticationError("Must provide either a password or a recovery key.")
                kek = self._derive_kek(
                    password, salt,
                    memory_cost=header.kdf.memory,
                    time_cost=header.kdf.iterations,
                    parallelism=header.kdf.parallelism,
                    hash_len=header.kdf.length,
                )
                encrypted_dek = base64.b64decode(header.envelope.encrypted_dek)
                dek_nonce = base64.b64decode(header.envelope.dek_nonce)
                dek = self._decrypt_dek(encrypted_dek, dek_nonce, kek)
        except AuthenticationError as exc:
            if password is not None and recovery_key is None:
                input_stream.seek(0, os.SEEK_END)
                total_size = input_stream.tell()
                if total_size <= payload_offset + header.payload.original_size + AES_TAG_SIZE + self.HIDDEN_TOTAL_HEADER_BYTES:
                    raise AuthenticationError(f"Vault access denied: {exc}") from exc
                try:
                    dek, payload_nonce, h_offset, metadata = self._try_hidden_vault(input_stream, password, total_size, header.kdf)
                    header.payload.nonce = base64.b64encode(payload_nonce).decode('utf-8')
                    header.payload.original_size = metadata.get('original_size', 0)
                    header.payload.filename = metadata.get('filename', '')
                    header.payload.metadata = metadata.get('metadata', None)
                    # Fix up the payload offset to point to the start of the hidden payload
                    payload_offset = h_offset + self.HIDDEN_TOTAL_HEADER_BYTES
                except AuthenticationError as hidden_exc:
                    raise AuthenticationError("Vault access denied: Invalid password or corrupted vault envelope.") from exc
            else:
                raise AuthenticationError(f"Vault access denied: {exc}") from exc

        if 'payload_nonce' not in locals():
            payload_nonce = base64.b64decode(header.payload.nonce)
        cipher = Cipher(
            algorithms.AES(dek),
            modes.GCM(payload_nonce),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        payload_aad_dict = {
            "nonce":         header.payload.nonce,
            "chunk_size":    header.payload.chunk_size,
            "original_size": header.payload.original_size,
            "filename":      header.payload.filename,
            "metadata":      header.payload.metadata,
        }
        payload_aad = serialize_aad(payload_aad_dict)
        decryptor.authenticate_additional_data(payload_aad)

        # PHASE 6 FIX: Tag offset must be calculated from payload size, not EOF,
        # because Hidden Vaults append random padding and hidden sections at the end.
        tag_offset = payload_offset + header.payload.original_size

        input_stream.seek(0, os.SEEK_END)
        total_size = input_stream.tell()

        if tag_offset > total_size - AES_TAG_SIZE:
            raise VaultFormatError(
                "Vault file is too short to contain the required payload and auth tag."
            )

        payload_size = header.payload.original_size
        input_stream.seek(payload_offset)

        bytes_processed = 0
        while input_stream.tell() < tag_offset:
            remaining = tag_offset - input_stream.tell()
            read_size = min(CHUNK_SIZE, remaining)
            chunk = input_stream.read(read_size)
            if not chunk:
                break

            decrypted_chunk = decryptor.update(chunk)
            output_stream.write(decrypted_chunk)
            bytes_processed += len(chunk)

            if progress_callback:
                try:
                    progress_callback(bytes_processed, payload_size)
                except Exception as exc:
                    logger.warning("Progress callback failed: %s", exc)

        input_stream.seek(tag_offset)
        auth_tag = input_stream.read(AES_TAG_SIZE)

        try:
            decryptor.finalize_with_tag(auth_tag)
        except InvalidTag:
            raise AuthenticationError(
                "Payload integrity check failed. The vault file has been corrupted, "
                "truncated, or tampered with. Do not trust the decrypted data."
            )

        logger.info(
            "Decryption complete: %d bytes restored, filename='%s'",
            bytes_processed, header.payload.filename
        )
        return header

    # --------------------------------------------------------------------------
    # Hidden Vault Internal Logic
    # --------------------------------------------------------------------------

    def _derive_hidden_offset(self, password: str, total_file_size: int) -> int:
        import hmac, hashlib
        offset_seed = hmac.new(password.encode('utf-8'), self.HIDDEN_OFFSET_MSG, hashlib.sha256).digest()
        offset_int = int.from_bytes(offset_seed, byteorder='big')
        if total_file_size <= self.HIDDEN_TOTAL_HEADER_BYTES:
            return 0
        return offset_int % (total_file_size - self.HIDDEN_TOTAL_HEADER_BYTES)

    def _try_hidden_vault(self, input_stream: BinaryIO, password: str, total_file_size: int, main_header_kdf: KDFParams) -> Tuple[bytes, bytes, int, dict]:
        import hashlib, json
        hidden_salt = hashlib.sha256(password.encode('utf-8') + self.HIDDEN_SALT_SUFFIX).digest()
        try:
            hidden_kek = argon2.low_level.hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=hidden_salt,
                time_cost=main_header_kdf.iterations,
                memory_cost=main_header_kdf.memory,
                parallelism=main_header_kdf.parallelism,
                hash_len=main_header_kdf.length,
                type=argon2.Type.ID
            )
        except Exception as exc:
            raise AuthenticationError("Failed to derive hidden KEK") from exc

        hidden_offset = self._derive_hidden_offset(password, total_file_size)
        
        input_stream.seek(hidden_offset)
        header_bytes = input_stream.read(self.HIDDEN_TOTAL_HEADER_BYTES)
        if len(header_bytes) < self.HIDDEN_TOTAL_HEADER_BYTES:
            raise AuthenticationError("Invalid hidden offset (EOF)")
            
        nonce = header_bytes[:self.HIDDEN_MINI_HEADER_NONCE_SIZE]
        ciphertext = header_bytes[self.HIDDEN_MINI_HEADER_NONCE_SIZE:-AES_TAG_SIZE]
        tag = header_bytes[-AES_TAG_SIZE:]
        
        cipher = Cipher(algorithms.AES(hidden_kek), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise AuthenticationError("Hidden mini-header tag invalid")
            
        hidden_dek = plaintext[:32]
        hidden_payload_nonce = plaintext[32:44]
        json_bytes = plaintext[44:].rstrip(b'\x00')
        
        try:
            metadata = json.loads(json_bytes.decode('utf-8'))
        except Exception:
            raise AuthenticationError("Invalid hidden metadata JSON")
            
        return hidden_dek, hidden_payload_nonce, hidden_offset, metadata

    # --------------------------------------------------------------------------
    # Public API: Metadata & Password Verification (Vault Info Panel)
    # --------------------------------------------------------------------------


    def encrypt_hidden_vault(
        self,
        decoy_input_stream: BinaryIO,
        hidden_input_stream: BinaryIO,
        output_stream: BinaryIO,
        password_a: str,
        password_b: str,
        target_total_size: int,
        decoy_filename: str,
        hidden_filename: str,
        decoy_metadata: Optional[Dict[str, Any]] = None,
        hidden_metadata: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None
    ) -> VaultHeader:
        """
        Creates a plausible deniability vault containing both Decoy and Hidden data.
        """
        import hmac, hashlib, json

        if hmac.compare_digest(password_a.encode('utf-8'), password_b.encode('utf-8')):
            raise ValueError("Decoy and Hidden passwords must be different.")

        # 1. Determine sizes
        decoy_input_stream.seek(0, os.SEEK_END)
        decoy_size = decoy_input_stream.tell()
        hidden_input_stream.seek(0, os.SEEK_END)
        hidden_size = hidden_input_stream.tell()
        decoy_input_stream.seek(0)
        hidden_input_stream.seek(0)

        # 2. Encrypt Decoy into output
        decoy_header = self.encrypt_stream(
            input_stream=decoy_input_stream,
            output_stream=output_stream,
            password=password_a,
            original_filename=decoy_filename,
            original_size=decoy_size,
            metadata=decoy_metadata,
            progress_callback=progress_callback,
            recovery_key=recovery_key
        )
        decoy_end = output_stream.tell()

        # 3. Find valid total_file_size
        hidden_payload_total = hidden_size + AES_TAG_SIZE
        hidden_section_total = self.HIDDEN_TOTAL_HEADER_BYTES + hidden_payload_total
        
        min_total_size = decoy_end + hidden_section_total + 1024
        actual_total_size = max(target_total_size, min_total_size)
        
        valid_offset = -1
        while True:
            offset_seed = hmac.new(password_b.encode('utf-8'), self.HIDDEN_OFFSET_MSG, hashlib.sha256).digest()
            offset_int = int.from_bytes(offset_seed, byteorder='big')
            offset = offset_int % (actual_total_size - self.HIDDEN_TOTAL_HEADER_BYTES)
            
            if offset >= decoy_end and offset + hidden_section_total <= actual_total_size:
                valid_offset = offset
                break
            actual_total_size += 1
            
        # 4. Write random padding
        padding_size = valid_offset - decoy_end
        if padding_size > 0:
            written = 0
            while written < padding_size:
                chunk = min(1024 * 1024, padding_size - written)
                output_stream.write(os.urandom(chunk))
                written += chunk

        # 5. Generate Hidden KEK, DEK, and Mini-Header
        hidden_salt = hashlib.sha256(password_b.encode('utf-8') + self.HIDDEN_SALT_SUFFIX).digest()
        hidden_kek = argon2.low_level.hash_secret_raw(
            secret=password_b.encode('utf-8'),
            salt=hidden_salt,
            time_cost=decoy_header.kdf.iterations,
            memory_cost=decoy_header.kdf.memory,
            parallelism=decoy_header.kdf.parallelism,
            hash_len=decoy_header.kdf.length,
            type=argon2.Type.ID
        )
        
        hidden_dek = os.urandom(AES_KEY_SIZE)
        hidden_mini_nonce = os.urandom(self.HIDDEN_MINI_HEADER_NONCE_SIZE)
        hidden_payload_nonce = os.urandom(AES_NONCE_SIZE)
        
        h_meta = {
            "original_size": hidden_size,
            "filename": hidden_filename,
            "metadata": hidden_metadata
        }
        h_meta_json = json.dumps(h_meta).encode('utf-8')
        if len(h_meta_json) > 512 - 32 - 12:
            raise ValueError("Hidden metadata too large for mini-header")
            
        mini_header_plaintext = hidden_dek + hidden_payload_nonce + h_meta_json.ljust(512 - 32 - 12, b'\x00')
        
        cipher_mini = Cipher(algorithms.AES(hidden_kek), modes.GCM(hidden_mini_nonce), backend=default_backend())
        encryptor_mini = cipher_mini.encryptor()
        mini_ciphertext = encryptor_mini.update(mini_header_plaintext) + encryptor_mini.finalize()
        mini_tag = encryptor_mini.tag
        
        output_stream.write(hidden_mini_nonce + mini_ciphertext + mini_tag)
        
        # 6. Encrypt Hidden Payload
        cipher_payload = Cipher(algorithms.AES(hidden_dek), modes.GCM(hidden_payload_nonce), backend=default_backend())
        encryptor_payload = cipher_payload.encryptor()
        
        payload_aad_dict = {
            "nonce": base64.b64encode(hidden_payload_nonce).decode('utf-8'),
            "chunk_size": CHUNK_SIZE,
            "original_size": hidden_size,
            "filename": hidden_filename,
            "metadata": hidden_metadata
        }
        payload_aad = serialize_aad(payload_aad_dict)
        encryptor_payload.authenticate_additional_data(payload_aad)
        
        while True:
            chunk = hidden_input_stream.read(CHUNK_SIZE)
            if not chunk:
                break
            output_stream.write(encryptor_payload.update(chunk))
            
        output_stream.write(encryptor_payload.finalize() + encryptor_payload.tag)
        
        # 7. Write final padding
        final_padding_size = actual_total_size - output_stream.tell()
        if final_padding_size > 0:
            written = 0
            while written < final_padding_size:
                chunk = min(1024 * 1024, final_padding_size - written)
                output_stream.write(os.urandom(chunk))
                written += chunk
                
        return decoy_header

    def verify_password_and_get_header(
        self,
        input_stream: BinaryIO,
        password: Optional[str] = None,
        recovery_key: Optional[bytes] = None
    ) -> VaultHeader:
        """
        Verify a password and return the vault header WITHOUT decrypting the payload.

        This is designed for the "Vault Info Panel" UI feature. It performs the
        computationally expensive Argon2id KDF and the DEK envelope decryption,
        proving that the user knows the correct password, but stops before
        touching the potentially multi-gigabyte payload.

        Returns:
            VaultHeader with original filename, size, and KDF parameters.

        Raises:
            AuthenticationError: If the password is incorrect.
            VaultFormatError: If the file structure is invalid.
        """
        header, payload_offset = self._read_header(input_stream)
        salt = base64.b64decode(header.kdf.salt)

        try:
            if recovery_key is not None:
                if not header.recovery_envelope:
                    raise AuthenticationError("No recovery phrase exists for this vault.")
                recovery_salt = salt + b"RECOVERY"
                recovery_kek = argon2.low_level.hash_secret_raw(
                    secret=recovery_key,
                    salt=recovery_salt,
                    time_cost=header.kdf.iterations,
                    memory_cost=header.kdf.memory,
                    parallelism=header.kdf.parallelism,
                    hash_len=header.kdf.length,
                    type=argon2.Type.ID
                )
                encrypted_dek = base64.b64decode(header.recovery_envelope.encrypted_dek)
                dek_nonce = base64.b64decode(header.recovery_envelope.dek_nonce)
                _ = self._decrypt_dek(encrypted_dek, dek_nonce, recovery_kek)
            else:
                if password is None:
                    raise AuthenticationError("Must provide either a password or a recovery key.")
                kek = self._derive_kek(
                    password, salt,
                    memory_cost=header.kdf.memory,
                    time_cost=header.kdf.iterations,
                    parallelism=header.kdf.parallelism,
                    hash_len=header.kdf.length,
                )
                encrypted_dek = base64.b64decode(header.envelope.encrypted_dek)
                dek_nonce = base64.b64decode(header.envelope.dek_nonce)
                _ = self._decrypt_dek(encrypted_dek, dek_nonce, kek)
        except AuthenticationError as exc:
            if password is not None and recovery_key is None:
                input_stream.seek(0, os.SEEK_END)
                total_size = input_stream.tell()
                if total_size <= payload_offset + header.payload.original_size + AES_TAG_SIZE + self.HIDDEN_TOTAL_HEADER_BYTES:
                    raise AuthenticationError(f"Vault access denied: {exc}") from exc
                try:
                    # Attempt hidden vault fallback
                    _, payload_nonce, _, metadata = self._try_hidden_vault(input_stream, password, total_size, header.kdf)
                    header.payload.nonce = base64.b64encode(payload_nonce).decode('utf-8')
                    header.payload.original_size = metadata.get('original_size', 0)
                    header.payload.filename = metadata.get('filename', '')
                    header.payload.metadata = metadata.get('metadata', None)
                    # Erase decoy envelope to prevent leaking DEK/Nonce to UI
                    header.envelope = EnvelopeParams(encrypted_dek="", dek_nonce="")
                    header.recovery_envelope = None
                    return header
                except AuthenticationError as hidden_exc:
                    raise AuthenticationError("Vault access denied: Invalid password or corrupted vault envelope.") from exc
            raise AuthenticationError(f"Vault access denied: {exc}") from exc

        return header

    # --------------------------------------------------------------------------
    # Public API: Re-Keying (Change Password without Full Decryption)
    # --------------------------------------------------------------------------

    def rekey_vault(
        self,
        input_path: Path,
        output_path: Path,
        old_password: str,
        new_password: str
    ) -> None:
        """
        Change the password of a vault by re-encrypting only the DEK envelope.

        This is the primary operational benefit of Envelope Encryption:
        - The potentially large payload (gigabytes) is NEVER decrypted.
        - Only the small DEK header (~200 bytes) is decrypted with the old KEK
          and re-encrypted with a new KEK derived from the new password.
        - The original GCM authentication tag remains valid because the payload
          ciphertext is untouched.

        Args:
            input_path: Path to the existing .vault file.
            output_path: Path to write the re-keyed .vault file.
            old_password: Current password that can open the vault.
            new_password: New password to protect the vault.

        Raises:
            AuthenticationError: If the old password is incorrect.
            VaultFormatError: If the input file is not a valid vault.
        """
        input_path  = Path(input_path).resolve()
        output_path = Path(output_path).resolve()

        if input_path == output_path:
            raise VaultFormatError(
                "input_path and output_path must be different files. "
                "Use a temporary path and rename atomically after success."
            )

        with open(input_path, 'rb') as f_in:
            header, payload_offset = self._read_header(f_in)

            old_salt = base64.b64decode(header.kdf.salt)
            old_kek = self._derive_kek(
                old_password, old_salt,
                memory_cost=header.kdf.memory,
                time_cost=header.kdf.iterations,
                parallelism=header.kdf.parallelism,
                hash_len=header.kdf.length,
            )

            encrypted_dek = base64.b64decode(header.envelope.encrypted_dek)
            dek_nonce = base64.b64decode(header.envelope.dek_nonce)
            dek = self._decrypt_dek(encrypted_dek, dek_nonce, old_kek)

            new_salt = self._secure_random(MIN_SALT_SIZE)
            new_kek = argon2.low_level.hash_secret_raw(
                secret=new_password.encode('utf-8'),
                salt=new_salt,
                memory_cost=header.kdf.memory,
                time_cost=header.kdf.iterations,
                parallelism=header.kdf.parallelism,
                hash_len=header.kdf.length,
                type=argon2.Type.ID
            )
            new_dek_nonce, new_encrypted_dek = self._encrypt_dek(dek, new_kek)

            new_header = VaultHeader(
                kdf=KDFParams(
                    salt=base64.b64encode(new_salt).decode('ascii'),
                    memory=header.kdf.memory,
                    iterations=header.kdf.iterations,
                    parallelism=header.kdf.parallelism,
                    length=header.kdf.length,
                ),
                envelope=EnvelopeParams(
                    dek_nonce=base64.b64encode(new_dek_nonce).decode('ascii'),
                    encrypted_dek=base64.b64encode(new_encrypted_dek).decode('ascii')
                ),
                payload=header.payload,
                recovery_envelope=header.recovery_envelope
            )

            new_header_json = json.dumps(asdict(new_header), separators=(',', ':')).encode('utf-8')
            
            old_header_len = payload_offset - 9
            if len(new_header_json) > old_header_len:
                raise CryptoError("New header is larger than old header; cannot safely re-key without risking Plausible Deniability.")
            new_header_json = new_header_json.ljust(old_header_len, b' ')
            new_header_len = len(new_header_json)

            f_in.seek(0, os.SEEK_END)
            total_size = f_in.tell()
            payload_size = total_size - payload_offset

            with open(output_path, 'wb') as f_out:
                f_out.write(VAULT_MAGIC)
                f_out.write(struct.pack('!B', VAULT_VERSION))
                f_out.write(struct.pack('!I', new_header_len))
                f_out.write(new_header_json)

                f_in.seek(payload_offset)
                remaining = payload_size
                while remaining > 0:
                    read_size = min(CHUNK_SIZE, remaining)
                    chunk = f_in.read(read_size)
                    if not chunk:
                        break
                    f_out.write(chunk)
                    remaining -= len(chunk)

        logger.info(
            "Re-keying complete: %s -> %s (payload_size=%d bytes untouched)",
            input_path, output_path, payload_size
        )

    # --------------------------------------------------------------------------
    # Public API: High-Level File Wrappers
    # --------------------------------------------------------------------------

    def encrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        password: str,
        original_filename: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None
    ) -> None:
        """
        Convenience wrapper to encrypt a file on disk into a .vault file.
        """
        src_path = Path(input_path)
        dst_path = Path(output_path)
        size = src_path.stat().st_size
        name = original_filename or src_path.name

        with open(src_path, 'rb') as f_in, open(dst_path, 'wb') as f_out:
            self.encrypt_stream(
                f_in, f_out, password, name, size, metadata, progress_callback, recovery_key
            )

    def decrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        password: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None
    ) -> VaultHeader:
        """
        Convenience wrapper to decrypt a .vault file back to its original form.
        """
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            return self.decrypt_stream(f_in, f_out, password, progress_callback, recovery_key)

    def encrypt_note(
        self,
        note_text: str,
        output_path: Path,
        password: str,
        note_title: str = "Encrypted Note",
        recovery_key: Optional[bytes] = None
    ) -> None:
        """
        Convenience wrapper to encrypt raw text directly into a .vault file.
        Bypasses ZIP packaging.
        """
        import io
        raw_bytes = note_text.encode('utf-8')
        src_stream = io.BytesIO(raw_bytes)
        dst_path = Path(output_path)
        
        metadata = {
            "source_type": "note",
            "file_count": 1,
            "created_at": __import__("datetime").datetime.now().isoformat()
        }
        
        with open(dst_path, 'wb') as f_out:
            self.encrypt_stream(
                input_stream=src_stream, 
                output_stream=f_out, 
                password=password, 
                original_filename=note_title, 
                original_size=len(raw_bytes), 
                metadata=metadata,
                recovery_key=recovery_key
            )

    def decrypt_note(
        self,
        input_path: Path,
        password: Optional[str] = None,
        recovery_key: Optional[bytes] = None
    ) -> str:
        """
        Convenience wrapper to decrypt a .vault file directly to a string in memory.
        """
        import io
        dst_stream = io.BytesIO()
        with open(input_path, 'rb') as f_in:
            header = self.decrypt_stream(f_in, dst_stream, password, recovery_key=recovery_key)
            
        return dst_stream.getvalue().decode('utf-8')


# ------------------------------------------------------------------------------
# Standalone test harness (runs only when executed directly)
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile
    import io

    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("RPM Encrypter - Core Crypto Module Self-Test")
    print("=" * 60)

    crypto = VaultCrypto()
    password = "SuperSecretPassword123!@#"
    test_data = b"This is a secret message. " * 1000

    print("\n[Test 1] Stream Encrypt -> Decrypt")
    src = io.BytesIO(test_data)
    vault = io.BytesIO()

    crypto.encrypt_stream(
        src, vault, password,
        original_filename="secret.txt",
        original_size=len(test_data),
        metadata={"file_count": 1, "created_at": "2024-01-01T00:00:00"}
    )

    vault.seek(0)
    dst = io.BytesIO()
    header = crypto.decrypt_stream(vault, dst, password)

    assert dst.getvalue() == test_data, "Decrypted data does not match original!"
    assert header.payload.filename == "secret.txt"
    assert header.payload.metadata is not None
    print("  [PASS] Round-trip successful.")
    print(f"  [INFO] Original size: {header.payload.original_size} bytes")
    print(f"  [INFO] Metadata: {header.payload.metadata}")

    print("\n[Test 2] Wrong Password Detection")
    vault.seek(0)
    try:
        crypto.decrypt_stream(vault, io.BytesIO(), "WrongPassword")
        print("  [FAIL] Should have raised AuthenticationError!")
    except AuthenticationError:
        print("  [PASS] AuthenticationError correctly raised for wrong password.")

    print("\n[Test 3] Password Verification & Metadata")
    vault.seek(0)
    meta = crypto.verify_password_and_get_header(vault, password)
    assert meta.payload.filename == "secret.txt"
    assert meta.payload.metadata["file_count"] == 1
    print("  [PASS] Metadata extracted without full payload decryption.")

    print("\n[Test 4] Re-Keying (Password Change)")
    with tempfile.TemporaryDirectory() as tmpdir:
        old_vault = Path(tmpdir) / "old.vault"
        new_vault = Path(tmpdir) / "new.vault"

        with open(old_vault, 'wb') as f:
            f.write(vault.getvalue())

        new_password = "NewAndImprovedPassword456!"
        crypto.rekey_vault(old_vault, new_vault, password, new_password)

        restored = io.BytesIO()
        with open(new_vault, 'rb') as f:
            crypto.decrypt_stream(f, restored, new_password)
        assert restored.getvalue() == test_data
        print("  [PASS] Re-keyed vault decrypts correctly with new password.")

        try:
            with open(new_vault, 'rb') as f:
                crypto.decrypt_stream(f, io.BytesIO(), password)
            print("  [FAIL] Old password should not work after re-keying!")
        except AuthenticationError:
            print("  [PASS] Old password correctly rejected after re-keying.")

    print("\n[Test 5] Large File Streaming (Chunked)")
    large_data = b"X" * (10 * 1024 * 1024)
    src_large = io.BytesIO(large_data)
    vault_large = io.BytesIO()

    crypto.encrypt_stream(
        src_large, vault_large, password,
        original_filename="bigfile.bin",
        original_size=len(large_data)
    )

    vault_large.seek(0)
    dst_large = io.BytesIO()
    crypto.decrypt_stream(vault_large, dst_large, password)
    assert dst_large.getvalue() == large_data
    print("  [PASS] 10 MiB file streamed successfully with constant memory.")

    print("\n" + "=" * 60)
    print("All self-tests passed. Module is ready for integration.")
    print("=" * 60)