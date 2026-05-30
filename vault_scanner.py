import json
import logging
from pathlib import Path
from typing import Dict, Any, List
import struct

from crypto_core import (
    VAULT_MAGIC, VAULT_VERSION, VaultFormatError, MAX_HEADER_SIZE
)

logger = logging.getLogger(__name__)

CACHE_FILE = Path.home() / ".rpm_encrypter_library.json"

class VaultScanner:
    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = self._load_cache()

    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load library cache: {e}")
        return {}

    def _save_cache(self) -> None:
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Failed to save library cache: {e}")

    def _extract_metadata(self, path: Path) -> Dict[str, Any]:
        """
        Extract the limited, non-sensitive metadata available from a vault header
        WITHOUT a password.

        F1/C2 FIX: format v3 keeps the original filename, the full file manifest
        AND the true payload size inside an AES-256-GCM block sealed under the
        DEK, NOT in the cleartext header. Without the password the scanner can
        therefore only report the on-disk ``.vault`` name and the (cleartext)
        bucketed ``container_size``; the rest is shown as locked until the user
        supplies a password.
        """
        with open(path, "rb") as f:
            magic = f.read(len(VAULT_MAGIC))
            if magic != VAULT_MAGIC:
                raise VaultFormatError("Invalid vault magic bytes")

            (version,) = struct.unpack("!B", f.read(1))
            if version != VAULT_VERSION:
                raise VaultFormatError(f"Unsupported vault version: {version}")

            (header_len,) = struct.unpack("!I", f.read(4))
            # M1 FIX: Bound the attacker-controlled header length before reading.
            # Without this, a malicious/corrupted vault declaring a multi-gigabyte
            # header would make the background scan allocate gigabytes and crash.
            if header_len > MAX_HEADER_SIZE:
                raise VaultFormatError(f"Vault header length ({header_len}) exceeds maximum allowed size")
            header_json_bytes = f.read(header_len)

            header_dict = json.loads(header_json_bytes.decode('utf-8'))
            payload = header_dict.get("payload", {})

            # F1/C2 FIX: v3 vaults expose no filenames, manifests, timestamps, or
            # true payload size in the cleartext header. Do NOT attempt to read
            # them — return a generic, locked entry. The only cleartext size is
            # the bucketed container_size, reported under its own key. The Library
            # still has a stale-cache fallback for older cache entries.
            if version == 3:
                try:
                    container_size = int(payload.get("container_size", 0))
                except (TypeError, ValueError):
                    container_size = 0
                return {
                    "filename": path.name,  # Only the .vault file name on disk is known
                    "container_size": container_size,  # = bucketed size; no real-size leak
                    "source_type": "Encrypted Metadata",
                    "created_at": "Requires Password",
                }

    def scan_directories(self, directories: List[str]) -> List[Dict[str, Any]]:
        """
        Scan directories for .vault files.
        Uses cache to skip extracting metadata from unmodified files.
        """
        results = []
        cache_updated = False
        
        # We need to track which files still exist to prune the cache eventually
        seen_paths = set()

        for dir_str in directories:
            dir_path = Path(dir_str)
            if not dir_path.is_dir():
                continue
                
            for vault_file in dir_path.rglob("*.vault"):
                if not vault_file.is_file():
                    continue
                
                path_str = str(vault_file.resolve())
                seen_paths.add(path_str)
                
                try:
                    stat = vault_file.stat()
                    mtime = stat.st_mtime
                    size = stat.st_size
                    
                    cached = self.cache.get(path_str)
                    
                    if cached and cached.get("mtime") == mtime:
                        # Cache hit
                        results.append(cached)
                    else:
                        # Cache miss or file modified
                        meta = self._extract_metadata(vault_file)
                        entry = {
                            "path": path_str,
                            "mtime": mtime,
                            "encrypted_size": size,
                            "filename": meta.get("filename"),
                            "container_size": meta.get("container_size"),
                            "source_type": meta.get("source_type"),
                            "created_at": meta.get("created_at"),
                        }
                        self.cache[path_str] = entry
                        results.append(entry)
                        cache_updated = True
                except Exception as e:
                    logger.warning(f"Skipping unreadable vault {path_str}: {e}")

        # Cleanup cache for files that no longer exist
        keys_to_remove = [p for p in self.cache.keys() if p not in seen_paths and any(p.startswith(str(Path(d).resolve())) for d in directories)]
        for k in keys_to_remove:
            del self.cache[k]
            cache_updated = True

        if cache_updated:
            self._save_cache()

        return results
