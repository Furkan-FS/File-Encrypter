"""
RPM Encrypter - Vault Versioning Module
========================================

Automatically preserves historical copies of vault files before they are
overwritten by destructive operations (currently: Re-Key only).

Storage layout:
    ~/.rpm_encrypter/versions/<vault_stem>/<vault_stem>__<YYYY-MM-DDTHH-MM-SS>.vault

Design constraints:
  - No GUI imports — pure Python, fully testable in isolation.
  - All file copies are assumed to run inside a background thread (caller's responsibility).
  - Versioning failures are non-fatal: errors are logged and returned as None/False.
  - Dual-limit pruning: per-vault max count AND total directory size cap.
  - Atomic restore via write-temp-then-replace.
"""

import hashlib
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Default storage location
VERSIONS_ROOT_DEFAULT = Path.home() / ".rpm_encrypter" / "versions"

# Default limits
DEFAULT_MAX_VERSIONS_PER_VAULT = 5
DEFAULT_MAX_TOTAL_SIZE_BYTES   = 2 * 1024 * 1024 * 1024  # 2 GiB

# Filename timestamp format (colons replaced with dashes for Windows safety)
_TS_FMT = "%Y-%m-%dT%H-%M-%S"


@dataclass(frozen=True)
class VersionEntry:
    """Represents a single saved version of a vault file."""
    path: Path
    timestamp: datetime
    size_bytes: int

    @property
    def display_timestamp(self) -> str:
        """Human-readable timestamp string."""
        return self.timestamp.strftime("%Y-%m-%d  %H:%M:%S")

    @property
    def display_size(self) -> str:
        """Human-readable file size."""
        mb = self.size_bytes / (1024 * 1024)
        if mb >= 1024:
            return f"{mb / 1024:.2f} GiB"
        return f"{mb:.2f} MiB"


class VaultVersionManager:
    """
    Manages historical versions of vault files.

    Thread-safety: The public methods are safe to call from background
    threads. The pruning methods do not hold long-lived locks; they
    operate on filesystem metadata which is inherently racy, but any
    race results in a harmless extra file being left on disk at most.

    All destructive operations (version save, delete, replace) are
    logged via the standard logging module.
    """

    def __init__(
        self,
        versions_root: Optional[Path] = None,
        max_versions_per_vault: int = DEFAULT_MAX_VERSIONS_PER_VAULT,
        max_total_size_bytes: int = DEFAULT_MAX_TOTAL_SIZE_BYTES,
        enabled: bool = False,
    ):
        """
        Args:
            versions_root: Root directory for all version storage.
            max_versions_per_vault: Maximum number of historical copies to keep per vault.
            max_total_size_bytes: Hard ceiling on total disk usage of the versions directory.
            enabled: If False, save_version() is a no-op. Controlled from Settings.
        """
        self.versions_root = Path(versions_root) if versions_root else VERSIONS_ROOT_DEFAULT
        self.max_versions_per_vault = max_versions_per_vault
        self.max_total_size_bytes = max_total_size_bytes
        self.enabled = enabled

    # --------------------------------------------------------------------------
    # PUBLIC API
    # --------------------------------------------------------------------------

    def save_version(self, vault_path: Path) -> Optional[Path]:
        """
        Copy vault_path into the versions directory, appending a timestamp.

        This should be called from a background thread BEFORE any operation
        that will overwrite the vault file.

        Returns:
            Path to the newly created version file, or None on any failure
            (failure is non-fatal — callers should log the result and continue).
        """
        if not self.enabled:
            return None

        vault_path = Path(vault_path)
        if not vault_path.is_file():
            logger.warning("save_version: vault not found: %s", vault_path)
            return None

        try:
            vault_dir = self._vault_versions_dir(vault_path)
            vault_dir.mkdir(parents=True, exist_ok=True)

            ts = datetime.now().strftime(_TS_FMT)
            dest_name = f"{vault_path.stem}__{ts}{vault_path.suffix}"
            dest = vault_dir / dest_name

            # Handle the (extremely unlikely) case of a timestamp collision
            counter = 1
            while dest.exists():
                dest = vault_dir / f"{vault_path.stem}__{ts}_{counter}{vault_path.suffix}"
                counter += 1

            logger.info("Saving version: %s → %s", vault_path.name, dest.name)
            shutil.copy2(vault_path, dest)   # copy2 preserves mtime; works cross-drive
            logger.info("Version saved: %s (%.2f MiB)", dest.name,
                        dest.stat().st_size / (1024 * 1024))

            self.prune(vault_path)
            return dest

        except OSError as exc:
            # Disk full, permissions error, etc.
            logger.warning("save_version failed for %s: %s", vault_path.name, exc)
            return None
        except Exception as exc:
            logger.error("save_version unexpected error for %s: %s", vault_path.name, exc)
            return None

    def list_versions(self, vault_path: Path) -> List[VersionEntry]:
        """
        Return all saved versions for a given vault, sorted oldest-first.

        Returns an empty list if the vault has no versions or if the
        versions directory does not exist yet.
        """
        vault_path = Path(vault_path)
        vault_dir = self._vault_versions_dir(vault_path)

        if not vault_dir.exists():
            return []

        entries: List[VersionEntry] = []
        for p in vault_dir.iterdir():
            if not p.is_file():
                continue
            ts = self._parse_timestamp(p, vault_path.stem)
            if ts is None:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            entries.append(VersionEntry(path=p, timestamp=ts, size_bytes=size))

        entries.sort(key=lambda e: e.timestamp)
        return entries

    def prune(self, vault_path: Path) -> None:
        """
        Enforce both limits for the given vault, then enforce the global
        total-size limit across all vaults.

        Step 1 (per-vault count) runs first — it's fast and avoids a full
        directory scan in most cases. Step 2 (global size) runs after.
        """
        vault_path = Path(vault_path)
        self._prune_per_vault(vault_path)
        self._prune_global_size()

    def prune_all(self) -> None:
        """
        Sweep the entire versions root, enforce per-vault count on every
        known vault, then enforce the global size limit.

        Called on application startup in a background thread.
        """
        if not self.versions_root.exists():
            return
        try:
            for subdir in self.versions_root.iterdir():
                if subdir.is_dir():
                    # Reconstruct a synthetic vault_path just for naming purposes
                    synthetic = subdir / f"{subdir.name}.vault"
                    self._prune_per_vault_by_dir(subdir)
            self._prune_global_size()
        except Exception as exc:
            logger.warning("prune_all encountered an error: %s", exc)

    def restore_as_copy(self, version_entry: VersionEntry, vault_path: Path) -> Path:
        """
        Copy a version file beside the current vault with a timestamp suffix.

        The current vault file is NEVER touched.

        Returns:
            Path to the newly created restore copy.

        Raises:
            OSError: If the copy fails (disk full, permissions, etc.).
        """
        vault_path = Path(vault_path)
        ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        dest_name = f"{vault_path.stem}__restored_{ts}{vault_path.suffix}"
        dest = vault_path.parent / dest_name

        counter = 1
        orig_dest = dest
        while dest.exists():
            dest = vault_path.parent / f"{orig_dest.stem}_{counter}{vault_path.suffix}"
            counter += 1

        shutil.copy2(version_entry.path, dest)
        logger.info("Restored version as copy: %s", dest.name)
        return dest

    def replace_current(self, version_entry: VersionEntry, vault_path: Path) -> None:
        """
        Atomically replace the current vault with the selected version.

        Uses write-temp-then-replace for atomicity. The temp file is
        written into the same directory as the current vault, ensuring
        the final os.replace() is on the same filesystem (atomic).

        Raises:
            OSError: If the copy or replace fails.
        """
        vault_path = Path(vault_path)
        parent = vault_path.parent

        fd, tmp_name = tempfile.mkstemp(
            dir=parent,
            prefix=".rpm_restore_",
            suffix=".tmp"
        )
        tmp = Path(tmp_name)
        try:
            os.close(fd)
            shutil.copy2(version_entry.path, tmp)
            tmp.replace(vault_path)   # atomic on POSIX; near-atomic on Windows NTFS
            logger.info("Replaced current vault with version: %s", version_entry.path.name)
        except Exception:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            raise

    def delete_version(self, version_entry: VersionEntry) -> None:
        """
        Permanently delete a single version file.

        Raises:
            OSError: If the deletion fails.
        """
        version_entry.path.unlink()
        logger.info("Deleted version: %s", version_entry.path.name)

        # Clean up the per-vault subdirectory if it's now empty
        try:
            parent = version_entry.path.parent
            if parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
        except Exception:
            pass  # Non-critical cleanup

    # --------------------------------------------------------------------------
    # INTERNAL HELPERS
    # --------------------------------------------------------------------------

    def _vault_versions_dir(self, vault_path: Path) -> Path:
        """Return the per-vault subdirectory inside the versions root."""
        # Normalise: strip leading dots and spaces for filesystem safety
        resolved_path = vault_path.resolve()
        stem = resolved_path.stem.strip(". ") or "unnamed"

        # F3 FIX: Append a short hash of the full resolved path to prevent
        # collisions between vaults with the same name in different directories.
        path_hash = hashlib.sha256(str(resolved_path).encode('utf-8')).hexdigest()[:8]

        return self.versions_root / f"{stem}_{path_hash}"

    def _parse_timestamp(self, file_path: Path, vault_stem: str) -> Optional[datetime]:
        """
        Extract the timestamp from a version filename.

        Expected format: <vault_stem>__<YYYY-MM-DDTHH-MM-SS>[_N]<.vault>
        Returns None if the filename doesn't match our convention.
        """
        name = file_path.stem  # e.g. "secrets__2026-05-20T21-04-00"
        prefix = vault_stem + "__"
        if not name.startswith(prefix):
            return None
        ts_part = name[len(prefix):]
        # Strip optional collision counter suffix (_1, _2, …)
        if "_" in ts_part[16:]:   # timestamp is always 19 chars
            ts_part = ts_part[:19]
        try:
            return datetime.strptime(ts_part[:19], _TS_FMT)
        except ValueError:
            return None

    def _prune_per_vault(self, vault_path: Path) -> None:
        """Delete oldest versions until count ≤ max_versions_per_vault."""
        vault_path = Path(vault_path)
        vault_dir = self._vault_versions_dir(vault_path)
        if not vault_dir.exists():
            return
        self._prune_per_vault_by_dir(vault_dir)

    def _prune_per_vault_by_dir(self, vault_dir: Path) -> None:
        """Delete oldest versions in a specific per-vault subdirectory."""
        # Collect all version files in this subdirectory sorted by mtime (oldest first)
        files = sorted(
            [p for p in vault_dir.iterdir() if p.is_file()],
            key=lambda p: p.stat().st_mtime
        )
        excess = len(files) - self.max_versions_per_vault
        if excess <= 0:
            return  # Guard: negative slice would incorrectly delete newest files
        for f in files[:excess]:
            try:
                f.unlink()
                logger.info("Pruned version (count limit): %s", f.name)
            except OSError as exc:
                logger.warning("Failed to prune version %s: %s", f.name, exc)

    def _prune_global_size(self) -> None:
        """
        Delete oldest version files globally until total size ≤ max_total_size_bytes.

        Gathers all version files across ALL per-vault subdirectories,
        sorts by mtime (oldest first), and deletes until under the limit.
        """
        if not self.versions_root.exists():
            return

        # Collect all files with sizes and mtimes
        all_files: List[tuple] = []  # (mtime, size, path)
        total_size = 0
        try:
            for subdir in self.versions_root.iterdir():
                if not subdir.is_dir():
                    continue
                for p in subdir.iterdir():
                    if not p.is_file():
                        continue
                    try:
                        st = p.stat()
                        all_files.append((st.st_mtime, st.st_size, p))
                        total_size += st.st_size
                    except OSError:
                        continue
        except OSError as exc:
            logger.warning("_prune_global_size: cannot scan versions root: %s", exc)
            return

        if total_size <= self.max_total_size_bytes:
            return  # Under the limit, nothing to do

        # Sort oldest-first
        all_files.sort(key=lambda t: t[0])

        for mtime, size, p in all_files:
            if total_size <= self.max_total_size_bytes:
                break
            try:
                p.unlink()
                total_size -= size
                logger.info("Pruned version (size limit): %s", p.name)
                # Clean up empty per-vault dirs
                try:
                    parent = p.parent
                    if not any(parent.iterdir()):
                        parent.rmdir()
                except Exception:
                    pass
            except OSError as exc:
                logger.warning("Failed to prune version %s: %s", p.name, exc)
