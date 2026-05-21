"""
RPM Encrypter - File Handling Module
=====================================

Handles secure file operations including folder packaging into zip archives,
secure file wiping (multi-pass overwrite), vault metadata inspection,
and archive extraction. All operations are designed to integrate cleanly
with the GUI's background worker threads.

Security Notes:
---------------
- Secure wipe overwrites file sectors with CSPRNG bytes before unlinking.
- Folder packaging preserves directory structure and file metadata in zip.
- Vault inspection leverages envelope encryption to read metadata without
  decrypting the potentially massive payload.
"""

import os
import zipfile
import tempfile
import shutil
import secrets
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Callable, Any

from crypto_core import VaultCrypto, VaultHeader, AuthenticationError, VaultFormatError

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# SECURE FILE WIPER
# ------------------------------------------------------------------------------

class SecureWiper:
    """
    Best-effort secure deletion utility.

    Instead of calling `os.remove()` directly (which only unlinks the inode
    and leaves data recoverable via undelete tools), this class overwrites
    the file's allocated sectors with cryptographically random bytes before
    deletion. For directories, it walks the tree bottom-up, wiping every file
    and then removing empty folders.

    Limitations (inherent to the OS / storage layer — not a bug):
    - SSDs with wear leveling may not overwrite the original physical sectors.
    - Copy-on-write filesystems (ZFS, Btrfs, APFS) may retain old data blocks.
    - Cloud-backed or network volumes offer no overwrite guarantees.
    - Filename and directory structure remain in the filesystem journal until
      the journal entries are overwritten by subsequent activity.
    For maximum assurance, use full-disk encryption on the source volume.
    """

    def __init__(self, passes: int = 1):
        """
        Args:
            passes: Number of overwrite iterations. OWASP recommends 1 pass
                of random data for modern media (SSD/HDD) as multi-pass
                patterns are largely obsolete for flash-based storage.
        """
        self.passes = passes

    def wipe_file(self, path: Path) -> None:
        """
        Overwrite a single file with random bytes, then delete it.

        Steps:
            1. Determine exact file size.
            2. Open in read+write binary mode ('r+b') to preserve the inode.
            3. For each pass, seek to start and write `secrets.token_bytes(size)`.
            4. Call `os.fsync()` to force flush to physical media.
            5. Close and `unlink()` the file.
        """
        path = Path(path)
        if not path.exists() or not path.is_file():
            logger.warning("Wipe target does not exist or is not a file: %s", path)
            return

        success = False
        try:
            with open(path, 'r+b') as f:
                size = os.fstat(f.fileno()).st_size
                if size > 0:
                    for _ in range(self.passes):
                        f.seek(0)
                        f.write(secrets.token_bytes(size))
                        f.flush()
                        os.fsync(f.fileno())
            success = True
            logger.info("Overwrite successful: %s", path)
        except OSError as exc:
            logger.error("Failed to overwrite %s: %s", path, exc)
        finally:
            try:
                path.unlink()
                logger.info("Securely wiped file: %s", path)
            except Exception as del_exc:
                if success:
                    logger.critical("Wiped file could not be deleted: %s - %s", path, del_exc)
                raise

    def wipe_folder(self, path: Path) -> None:
        """
        Recursively wipe all files in a directory tree, then remove directories.

        Uses a bottom-up walk to ensure we never attempt to delete a directory
        that still contains files.
        """
        path = Path(path)
        if not path.exists():
            return
        if not path.is_dir():
            self.wipe_file(path)
            return

        for file_path in path.rglob('*'):
            if file_path.is_file():
                self.wipe_file(file_path)

        dirs = sorted(
            [p for p in path.rglob('*') if p.is_dir()],
            key=lambda p: len(p.parts),
            reverse=True
        )
        for dir_path in dirs:
            try:
                dir_path.rmdir()
            except OSError:
                pass

        try:
            path.rmdir()
        except OSError:
            pass

        logger.info("Securely wiped folder: %s", path)


# ------------------------------------------------------------------------------
# FOLDER PACKAGER
# ------------------------------------------------------------------------------

class FolderPackager:
    """
    Creates compressed zip archives from folders or file lists.

    The resulting zip is written to a temporary file that the caller is
    responsible for deleting after encryption. Using `zipfile.ZIP_STORED`
    provides maximum speed since encrypted data doesn't compress well anyway.
    """

    def package_folder(
        self,
        source_path: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        exclude_paths: Optional[List[Path]] = None
    ) -> Path:
        """
        Recursively zip a folder into a temporary archive.

        Args:
            source_path: Directory to archive.
            progress_callback: (bytes_processed, total_bytes) -> None

        Returns:
            Path to the temporary zip file.
        """
        source_path = Path(source_path).resolve()
        if not source_path.is_dir():
            raise ValueError(f"Source must be a directory: {source_path}")

        temp_fd, temp_name = tempfile.mkstemp(suffix='.zip', dir=source_path.parent)
        temp_path = Path(temp_name)

        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))
        
        def is_excluded(p: Path) -> bool:
            res = p.resolve()
            return any(res == ex or ex in res.parents for ex in exclude_set)

        total_size = sum(
            f.stat().st_size
            for f in source_path.rglob('*')
            if f.is_file() and not is_excluded(f)
        )
        processed = 0

        try:
            with os.fdopen(temp_fd, 'wb') as temp_file:
                with zipfile.ZipFile(temp_file, 'w', zipfile.ZIP_STORED) as zf:
                    for file_path in source_path.rglob('*'):
                        if file_path.is_file() and not is_excluded(file_path):
                            arcname = str(file_path.relative_to(source_path))
                            zf.write(file_path, arcname)
                            processed += file_path.stat().st_size
                            if progress_callback:
                                try:
                                    progress_callback(processed, total_size)
                                except Exception as exc:
                                    logger.warning("Progress callback failed: %s", exc)
        except Exception:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            raise

        logger.info("Packaged folder '%s' -> '%s' (%d bytes)", source_path, temp_path, total_size)
        return temp_path

    def package_files(
        self,
        file_paths: List[Path],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        exclude_paths: Optional[List[Path]] = None
    ) -> Path:
        """
        Create a zip archive containing multiple individual files.

        Args:
            file_paths: List of file paths to include.
            progress_callback: (bytes_processed, total_bytes) -> None

        Returns:
            Path to the temporary zip file.
        """
        if not file_paths:
            raise ValueError("file_paths cannot be empty")

        temp_dir = Path(file_paths[0]).parent
        temp_fd, temp_name = tempfile.mkstemp(suffix='.zip', dir=temp_dir)
        temp_path = Path(temp_name)

        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))
        valid_files = [Path(f) for f in file_paths if Path(f).resolve() not in exclude_set]
        
        total_size = sum(f.stat().st_size for f in valid_files if f.is_file())
        processed = 0

        try:
            with os.fdopen(temp_fd, 'wb') as temp_file:
                with zipfile.ZipFile(temp_file, 'w', zipfile.ZIP_STORED) as zf:
                    for file_path in valid_files:
                        if file_path.exists() and file_path.is_file():
                            zf.write(file_path, file_path.name)
                            processed += file_path.stat().st_size
                            if progress_callback:
                                try:
                                    progress_callback(processed, total_size)
                                except Exception as exc:
                                    logger.warning("Progress callback failed: %s", exc)
        except Exception:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            raise

        logger.info("Packaged %d files -> '%s' (%d bytes)", len(file_paths), temp_path, total_size)
        return temp_path

    def get_manifest(self, source_path: Path, exclude_paths: list = None) -> dict:
        """
        Build a JSON-serializable manifest of the source for vault header metadata.

        Returns:
            Dict with keys: file_count, total_size, files[], created_at, source_type
        """
        source_path = Path(source_path)
        files = []
        total_size = 0

        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))
        def is_excluded(p: Path) -> bool:
            res = p.resolve()
            return any(res == ex or ex in res.parents for ex in exclude_set)

        if source_path.is_file():
            if not is_excluded(source_path):
                files.append({
                    "path": source_path.name,
                    "size": source_path.stat().st_size,
                    "mtime": datetime.fromtimestamp(source_path.stat().st_mtime).isoformat()
                })
                total_size = source_path.stat().st_size
            source_type = "file"
        elif source_path.is_dir():
            for file_path in source_path.rglob('*'):
                if file_path.is_file() and not is_excluded(file_path):
                    rel_path = str(file_path.relative_to(source_path))
                    files.append({
                        "path": rel_path,
                        "size": file_path.stat().st_size,
                        "mtime": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                    })
                    total_size += file_path.stat().st_size
            source_type = "folder"
        else:
            raise ValueError(f"Source does not exist: {source_path}")

        return {
            "file_count": len(files),
            "total_size": total_size,
            "files": files,
            "created_at": datetime.now().isoformat(),
            "source_type": source_type
        }

    def get_manifest_multiple(self, file_paths: list, exclude_paths: list = None) -> dict:
        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))
        files = []
        total_size = 0
        for fp in file_paths:
            fp = Path(fp)
            if fp.is_file() and fp.resolve() not in exclude_set:
                files.append({
                    "path": fp.name,
                    "size": fp.stat().st_size,
                    "mtime": datetime.fromtimestamp(fp.stat().st_mtime).isoformat()
                })
                total_size += fp.stat().st_size
        return {
            "file_count": len(files),
            "total_size": total_size,
            "files": files,
            "created_at": datetime.now().isoformat(),
            "source_type": "archive"
        }

    def extract_archive(
        self,
        archive_path: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> None:
        """
        Extract a zip archive to the specified output directory.

        Args:
            archive_path: Path to the zip file.
            output_dir: Destination directory.
            progress_callback: Optional progress callback.
        """
        archive_path = Path(archive_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        output_dir_resolved = output_dir.resolve()

        with zipfile.ZipFile(archive_path, 'r') as zf:
            total = len(zf.namelist())
            for idx, member in enumerate(zf.namelist(), 1):
                info = zf.getinfo(member)

                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if unix_mode and (unix_mode & 0o170000) == 0o120000:
                    logger.error(
                        "Symlink entry blocked: %r in archive %s",
                        member, archive_path
                    )
                    raise VaultFormatError(
                        f"Archive contains a symlink entry: {member!r}. "
                        f"Symlinks are not permitted in RPM vaults."
                    )

                member_path = output_dir_resolved / member
                try:
                    member_resolved = member_path.resolve()
                    member_resolved.relative_to(output_dir_resolved)
                except (ValueError, RuntimeError):
                    logger.error(
                        "Zip Slip attempt blocked: member %r would escape output dir %s",
                        member, output_dir_resolved
                    )
                    raise VaultFormatError(
                        f"Archive contains a path-traversal entry: {member!r}. "
                        f"The vault may have been tampered with."
                    )

                zf.extract(member, output_dir)
                if progress_callback:
                    try:
                        progress_callback(idx, total)
                    except Exception as exc:
                        logger.warning("Progress callback failed: %s", exc)

        logger.info("Extracted '%s' -> '%s'", archive_path, output_dir)


# ------------------------------------------------------------------------------
# VAULT INSPECTOR
# ------------------------------------------------------------------------------

class VaultInspector:
    """
    Provides metadata extraction from vault headers without full decryption.

    This is the backend for the GUI's "Vault Info Panel". It leverages the
    Envelope Encryption architecture: only the small DEK header is decrypted
    to prove password correctness, while the massive payload stream is never
    touched.
    """

    def __init__(self, crypto: VaultCrypto):
        self.crypto = crypto

    def inspect(self, vault_path: Path, password: Optional[str] = None, recovery_key: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Verify password or recovery key and return vault metadata.

        Args:
            vault_path: Path to the .vault file.
            password: User's password.
            recovery_key: Optional recovery phrase entropy.

        Returns:
            Dictionary containing all metadata fields.

        Raises:
            AuthenticationError: Wrong password/key.
            VaultFormatError: Corrupted or invalid vault.
        """
        vault_path = Path(vault_path)
        if not vault_path.exists():
            raise VaultFormatError(f"Vault file not found: {vault_path}")

        try:
            with open(vault_path, 'rb') as f:
                header = self.crypto.verify_password_and_get_header(f, password=password, recovery_key=recovery_key)
        except AuthenticationError:
            raise
        except Exception as exc:
            raise VaultFormatError(f"Failed to read vault header: {exc}") from exc

        metadata = {
            "filename": header.payload.filename,
            "original_size": header.payload.original_size,
            "kdf_algorithm": header.kdf.algorithm,
            "encryption": header.envelope.algorithm,
            "payload_encryption": header.payload.algorithm,
            "argon_memory": header.kdf.memory,
            "argon_iterations": header.kdf.iterations,
            "argon_parallelism": header.kdf.parallelism,
        }

        if header.payload.metadata:
            metadata.update(header.payload.metadata)

        return metadata