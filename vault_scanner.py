import json
import logging
from pathlib import Path
from typing import Dict, Any, List
import struct

from crypto_core import (
    VAULT_MAGIC, VAULT_VERSION, VaultFormatError
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
        """Extract unencrypted metadata directly from vault header."""
        with open(path, "rb") as f:
            magic = f.read(len(VAULT_MAGIC))
            if magic != VAULT_MAGIC:
                raise VaultFormatError("Invalid vault magic bytes")
            
            (version,) = struct.unpack("!B", f.read(1))
            if version != VAULT_VERSION:
                raise VaultFormatError(f"Unsupported vault version: {version}")
                
            (header_len,) = struct.unpack("!I", f.read(4))
            header_json_bytes = f.read(header_len)
            
            header_dict = json.loads(header_json_bytes.decode('utf-8'))
            
            payload = header_dict.get("payload", {})
            metadata = payload.get("metadata", {}) or {}
            
            return {
                "filename": payload.get("filename", path.name),
                "original_size": payload.get("original_size", 0),
                "source_type": metadata.get("source_type", "folder/file"),
                "created_at": metadata.get("created_at", "Unknown"),
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
                            "original_size": meta.get("original_size"),
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
