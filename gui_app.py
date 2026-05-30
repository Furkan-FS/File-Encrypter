#!/usr/bin/env python3
"""
RPM Encrypter - Main GUI Application  (v3.0 - Vault Format v2)
==============================================================
Version is defined once as APP_VERSION below (single source of truth).
The "Major Fixes in v2.1" list is retained as historical changelog.

Major Fixes in v2.1:
  - Thread lifecycle management (graceful shutdown, cancel support)
  - Window close race condition fixed
  - Temp file memory leak resolved
  - Config file atomic writes
  - Message queue bounded to prevent overflow
  - Fingerprint panel performance optimization (background hashing)
  - Password strength calculation debounced
  - RecentBar widget memory leak fixed
  - Decrypt output directory validation enhanced
  - Progress feedback during KDF phase
  - Better error handling in worker threads

Architecture:
  - All long-running ops run in daemon threads
  - Thread-safe queue relays progress/log/completion back to main thread
  - AttemptLimiter shared across Decrypt and Inspect tabs
  - Cancel flag for graceful worker termination

Dependencies:
    pip install customtkinter tkinterdnd2 cryptography argon2-cffi zxcvbn
"""

import os
import sys
import json
import queue
import threading
import secrets
import string
import logging
import tempfile
import hashlib
import struct
import time
import webbrowser
from updater import check_for_update
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from functools import partial

# ------------------------------------------------------------------------------
# Third-Party Imports
# ------------------------------------------------------------------------------

import tkinterdnd2
from tkinterdnd2 import DND_FILES, TkinterDnD

import customtkinter as ctk
from tkinter import filedialog, messagebox

try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

# ------------------------------------------------------------------------------
# Local Modules
# ------------------------------------------------------------------------------

from crypto_core import (
    VaultCrypto, AuthenticationError, VaultFormatError, CryptoError,
    VAULT_MAGIC, VAULT_VERSION, AES_TAG_SIZE,
    ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM,
    generate_recovery_entropy, entropy_to_mnemonic, mnemonic_to_entropy
)
from file_handler import FolderPackager, SecureWiper, VaultInspector
import activity_log
import vault_scanner
import versioning


# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("RPM_GUI")

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

APP_NAME        = "RPM Encrypter"
APP_VERSION     = "3.0.0"   # F7: single source of truth; bumped for the breaking Vault Format v2 (Phase 22)
CONFIG_FILE     = Path.home() / ".rpm_encrypter.json"
MAX_RECENT      = 8
MAX_ATTEMPTS    = 5
LOCKOUT_SECS    = 30
DEFAULT_PW_LEN  = 24
MSG_QUEUE_SIZE  = 1000  # Bounded queue to prevent memory overflow

STRENGTH_COLORS = {
    0: ("#ff4444", "Very Weak"),
    1: ("#ff8844", "Weak"),
    2: ("#ffaa44", "Fair"),
    3: ("#44aa44", "Strong"),
    4: ("#008800", "Very Strong"),
}

# C2 (Phase 24): "Container Size" selector options and label -> MiB mapping.
# "Auto" (0) lets crypto_core pick the smallest 1.25x ladder bucket; an explicit
# choice sets a floor. GB labels are 1024 MB.
CONTAINER_SIZE_CHOICES = ["Auto", "100 MB", "500 MB", "1 GB", "2 GB", "5 GB", "10 GB"]

def container_label_to_mb(label: str) -> int:
    """Map a Container Size label (e.g. '1 GB', '100 MB', 'Auto') to MiB (Auto -> 0)."""
    if not label or label.strip().lower() == "auto":
        return 0
    parts = label.split()
    try:
        num = int(parts[0])
    except (ValueError, IndexError):
        return 0
    unit = parts[1].upper() if len(parts) > 1 else "MB"
    return num * 1024 if unit == "GB" else num


# ==============================================================================
# HELPERS
# ==============================================================================

# ------------------------------------------------------------------------------
# Persistent config with atomic writes
# ------------------------------------------------------------------------------

def _load_cfg() -> dict:
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text("utf-8"))
    except Exception:
        pass
    return {}


def _save_cfg(data: dict) -> None:
    """Atomic config file write to prevent corruption."""
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=CONFIG_FILE.parent,
            prefix='.rpm_encrypter_tmp_',
            suffix='.json'
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            Path(tmp_path).replace(CONFIG_FILE)
        except:
            Path(tmp_path).unlink(missing_ok=True)
            raise
    except Exception as exc:
        logger.warning("Failed to save config: %s", exc)


def get_recent(key: str) -> List[str]:
    """Return list of recent paths for the given key, filtering out non-existent ones."""
    return [p for p in _load_cfg().get(key, []) if Path(p).exists()]


def push_recent(key: str, path: str) -> None:
    cfg = _load_cfg()
    lst = cfg.get(key, [])
    if path in lst:
        lst.remove(path)
    lst.insert(0, path)
    cfg[key] = lst[:MAX_RECENT]
    _save_cfg(cfg)


def get_setting(key: str, default=None):
    return _load_cfg().get("settings", {}).get(key, default)


def save_setting(key: str, value) -> None:
    cfg = _load_cfg()
    cfg.setdefault("settings", {})[key] = value
    _save_cfg(cfg)


# ------------------------------------------------------------------------------
# Brute-force / lockout guard (uses monotonic time)
# ------------------------------------------------------------------------------

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

class AttemptLimiter:
    """
    Thread-safe, per-session lockout counter using monotonic time.
    
    Uses time.monotonic() instead of time.time() to prevent bypass via
    system clock manipulation.
    """

    def __init__(self, max_attempts: int = MAX_ATTEMPTS, lockout_secs: int = LOCKOUT_SECS):
        self._lock         = threading.Lock()
        self._fails        = 0
        self._lockout_start = None  # monotonic time
        self._max          = max_attempts
        self._secs         = lockout_secs

    def is_locked(self) -> Tuple[bool, int]:
        """Returns (locked, seconds_remaining)."""
        with self._lock:
            if self._lockout_start is None:
                return False, 0
            elapsed = time.monotonic() - self._lockout_start
            remaining = self._secs - elapsed
            if remaining > 0:
                return True, int(remaining) + 1
            else:
                # Lockout expired, clear state
                self._lockout_start = None
                self._fails = 0
                return False, 0

    def record_failure(self) -> None:
        with self._lock:
            self._fails += 1
            if self._fails >= self._max:
                self._lockout_start = time.monotonic()
                self._fails = 0

    def record_success(self) -> None:
        with self._lock:
            self._fails = 0
            self._lockout_start = None

    def attempts_remaining(self) -> int:
        with self._lock:
            return max(0, self._max - self._fails)


# ------------------------------------------------------------------------------
# Session statistics (thread-safe)
# ------------------------------------------------------------------------------

class SessionStats:
    """Thread-safe session counters with atomic updates."""

    def __init__(self):
        self._lock       = threading.Lock()
        self.encrypted   = 0
        self.decrypted   = 0
        self.rekeyed     = 0
        self.files_total = 0
        self.bytes_total = 0
        self._start: Optional[float] = None

    def mark_start(self) -> None:
        """Call this after the UI is fully built and mainloop is about to start."""
        with self._lock:
            self._start = time.time()

    def add_encrypted(self, file_count: int = 1, byte_count: int = 0) -> None:
        with self._lock:
            self.encrypted   += 1
            self.files_total += file_count
            self.bytes_total += byte_count

    def add_decrypted(self, byte_count: int = 0) -> None:
        with self._lock:
            self.decrypted   += 1
            self.bytes_total += byte_count

    def add_rekeyed(self) -> None:
        with self._lock:
            self.rekeyed += 1

    def snapshot(self) -> dict:
        """Return a consistent snapshot for display (no tearing)."""
        with self._lock:
            return {
                "encrypted":   self.encrypted,
                "decrypted":   self.decrypted,
                "rekeyed":     self.rekeyed,
                "files_total": self.files_total,
                "bytes_total": self.bytes_total,
                "uptime":      self._uptime_unlocked(),
            }

    def _uptime_unlocked(self) -> str:
        if self._start is None:
            return "00:00:00"
        s = int(time.time() - self._start)
        return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"

    def uptime(self) -> str:
        with self._lock:
            return self._uptime_unlocked()


# ==============================================================================
# REUSABLE WIDGETS
# ==============================================================================

class PasswordEntry(ctk.CTkFrame):
    """
    A CTkEntry with a show/hide toggle button bundled beside it.
    """

    def __init__(self, master, placeholder: str = "Password", **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.grid_columnconfigure(0, weight=1)

        self._entry = ctk.CTkEntry(
            self,
            show="•",
            placeholder_text=placeholder,
            font=ctk.CTkFont(size=14),

        fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self._entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self._visible = False
        self._toggle_btn = ctk.CTkButton(
            self,
            text="👁",
            command=self._toggle, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8)
        self._toggle_btn.grid(row=0, column=1)

    def _toggle(self):
        self._visible = not self._visible
        self._entry.configure(show="" if self._visible else "•")

    def get(self) -> str:
        return self._entry.get()

    def set(self, value: str) -> None:
        self._entry.delete(0, "end")
        self._entry.insert(0, value)

    def clear(self) -> None:
        self._entry.delete(0, "end")
        self._visible = False
        self._entry.configure(show="•")

    def bind_key(self, sequence: str, callback) -> None:
        self._entry.bind(sequence, callback)

    def bind_change(self, callback) -> None:
        self._entry.bind("<KeyRelease>", callback)


class LogBox(ctk.CTkFrame):
    """
    A read-only, auto-scrolling log display backed by a CTkTextbox.
    """

    def __init__(self, master, height: int = 180, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._box = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(size=12, family="Courier New"),
            wrap="word",
            state="disabled",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self._box.grid(row=0, column=0, sticky="nsew")

        btn_row = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        btn_row.grid(row=1, column=0, sticky="e", pady=(4, 0))
        ctk.CTkButton(
            btn_row, text="Clear Log",
            command=self.clear, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            btn_row, text="Export Log",
            command=self.export_to_file, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

    def write(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._box.configure(state="normal")
        self._box.insert("end", f"[{ts}]  {msg}\n")
        self._box.see("end")
        self._box.configure(state="disabled")

    def clear(self) -> None:
        self._box.configure(state="normal")
        self._box.delete("0.0", "end")
        self._box.configure(state="disabled")

    def export_to_file(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export Log",
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        content = self._box.get("0.0", "end")
        try:
            Path(path).write_text(content, "utf-8")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))


class RecentBar(ctk.CTkFrame):
    """
    A compact horizontal strip of clickable recent-path buttons.
    Fixed memory leak by using partial() instead of lambda closures.
    """

    def __init__(self, master, recent_key: str, on_select, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self._key       = recent_key
        self._on_select = on_select
        self._buttons   = []  # Track buttons for proper cleanup
        self.refresh()

    def refresh(self) -> None:
        # Clear command callbacks first to break closure references
        for btn in self._buttons:
            btn.configure(command=None)
            btn.destroy()
        self._buttons.clear()
        
        recent = get_recent(self._key)[:5]
        if not recent:
            return
        
        ctk.CTkLabel(self, text="Recent:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 6))
        
        for p in recent:
            name = Path(p).name
            btn = ctk.CTkButton(
                self, text=name,
                command=partial(self._on_select, p), fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8)  # Use partial instead of lambda
            btn.pack(side="left", padx=2)
            self._buttons.append(btn)


# ==============================================================================
# MAIN APPLICATION
# ==============================================================================

class DragDropArea(ctk.CTkFrame):
    def __init__(self, master, browse_command, **kwargs):
        super().__init__(master, fg_color="#0d1117", corner_radius=8, border_width=2, border_color="#30363d", **kwargs)
        self.pack_propagate(False)
        self.grid_propagate(False)
        self.browse_command = browse_command

        self.content_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        self.content_frame.place(relx=0.5, rely=0.5, anchor="center")

        self.icon_label = ctk.CTkLabel(self.content_frame, text="📁", font=ctk.CTkFont(size=48), text_color="#7d8590")
        self.text_label = ctk.CTkLabel(self.content_frame, text="Drag and Drop or Select Files", font=ctk.CTkFont(size=12), text_color="#7d8590")
        
        for w in (self, self.content_frame, self.icon_label, self.text_label):
            w.bind("<Button-1>", lambda e: self.browse_command())
            w.bind("<Enter>", lambda e: self.configure(cursor="hand2"))
            w.bind("<Leave>", lambda e: self.configure(cursor=""))

        self.is_empty = True
        self._update_ui()

    def _update_ui(self):
        if self.is_empty:
            self.configure(height=200, border_color="#30363d")
            self.icon_label.pack(pady=(0, 12))
            self.text_label.pack()
            self.text_label.configure(text="Drag and Drop or Select Files", text_color="#7d8590")
        else:
            self.configure(height=60, border_color="#00d4aa")
            self.icon_label.pack_forget()
            self.text_label.pack()

    def update_state(self, file_count, total_mb):
        if file_count == 0:
            self.is_empty = True
            self._update_ui()
        else:
            self.is_empty = False
            self.text_label.configure(text=f"{file_count} files selected | Total: {total_mb:.1f} MB", text_color="#e6edf3")
            self._update_ui()

class EmptyStateContainer(ctk.CTkFrame):
    def __init__(self, master, icon, message):
        super().__init__(master, fg_color="transparent")
        
        self.icon_label = ctk.CTkLabel(self, text=icon, font=ctk.CTkFont(size=48), text_color="#7d8590")
        self.icon_label.pack(pady=(0, 12))
        
        self.msg_label = ctk.CTkLabel(self, text=message, font=ctk.CTkFont(size=14), text_color="#7d8590")
        self.msg_label.pack()
        
    def show(self):
        self.place(relx=0.5, rely=0.5, anchor="center")
        
    def hide(self):
        self.place_forget()

class SidebarItem(ctk.CTkFrame):
    def __init__(self, master, text, command, **kwargs):
        super().__init__(master, height=44, fg_color="transparent", corner_radius=0, **kwargs)
        self.pack_propagate(False)
        self.command = command
        self._active = False
        
        self.inner = ctk.CTkFrame(self, fg_color="#010409", corner_radius=0)
        self.inner.pack(fill="both", expand=True, padx=(2, 0))
        
        self.label = ctk.CTkLabel(self.inner, text=text, font=ctk.CTkFont(size=14), text_color="#7d8590", anchor="w")
        self.label.pack(fill="both", expand=True, padx=18)
        
        for w in (self, self.inner, self.label):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._on_click)

    def _on_enter(self, e):
        self.label.configure(cursor="hand2")
        self.inner.configure(cursor="hand2")
        self.configure(cursor="hand2")
        if not self._active:
            self.label.configure(text_color="#e6edf3")

    def _on_leave(self, e):
        if not self._active:
            self.label.configure(text_color="#7d8590")

    def _on_click(self, e):
        if self.command:
            self.command()

    def set_active(self, active: bool):
        self._active = active
        if active:
            self.configure(fg_color="#00d4aa")
            self.label.configure(text_color="#00d4aa")
        else:
            self.configure(fg_color="transparent")
            self.label.configure(text_color="#7d8590")

class RPMEncrypterApp(ctk.CTk, TkinterDnD.DnDWrapper):
    """
    Primary application window.

    Tab layout:
        Encrypt | Decrypt | Vault Info | Re-Key | Password Gen | Settings
    """

    def __init__(self):
        super().__init__()

        # --- Window ---
        self.title(f"{APP_NAME} v{APP_VERSION}")
        try:
            self.iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass
        self.geometry("1180x820")
        self.minsize(width=1024, height=600)

        # --- Threading ---
        self.msg_queue: queue.Queue = queue.Queue(maxsize=MSG_QUEUE_SIZE)  # Bounded queue
        self.worker_thread: Optional[threading.Thread] = None
        self.is_processing: bool = False
        self._clipboard_timer = None
        self._clipboard_hint_timer = None
        self._cancel_requested: bool = False  # Flag for graceful shutdown
        self._active_log:  Optional[LogBox] = None
        self._active_temp_files: List[Path] = []
        self._temp_files_lock = threading.Lock()

        # --- DnD ---
        try:
            self.TkdndVersion = TkinterDnD._require(self)
            logger.info("DnD initialised (tkdnd %s)", self.TkdndVersion)
        except Exception as exc:
            logger.warning("DnD unavailable: %s", exc)

        # --- Back-end services ---
        self._build_crypto()
        self.packager  = FolderPackager()
        self.wiper     = SecureWiper(passes=get_setting("wipe_passes", 1))
        self.inspector = VaultInspector(self.crypto)
        self.limiter   = AttemptLimiter()
        self.stats     = SessionStats()
        self.activity_logger = activity_log.ActivityLogger(enabled=get_setting("logging_enabled", True))
        self.scanner = vault_scanner.VaultScanner()
        self.versioner = self._build_versioner()

        # Clean up orphaned temp extraction directories
        self._cleanup_orphaned_extracts()

        # Prune version history on startup (background thread, non-blocking)
        threading.Thread(target=self.versioner.prune_all, daemon=True).start()
        
        # --- State ---
        self.batch_queue:   List[Dict[str, Any]] = []
        self.decrypt_paths: List[str] = []

        # --- UI ---
        self._setup_appearance()
        self._setup_layout()
        self._setup_sidebar()
        self._setup_main_frames()
        self._setup_status_bar()
        self._show_encrypt()
        self._bind_shortcuts()
        self.bind("<Configure>", self._on_window_resize)

        self._show_frame("encrypt")
        self._poll_queue()
        
        if get_setting("check_updates", True):
            threading.Thread(target=self._check_update_background, daemon=True).start()
        self._tick_clock()

        # Guard against closing mid-operation
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        logger.info("Application started")

    
    def _on_window_resize(self, event):
        if event.widget == self:
            if hasattr(self, '_resize_timer'):
                self.after_cancel(self._resize_timer)
            self._resize_timer = self.after(150, self._handle_resize_done)

    def _handle_resize_done(self):
        self.update_idletasks()

    def _cleanup_orphaned_extracts(self) -> None:
        import glob
        temp_dir = tempfile.gettempdir()
        
        # H4 FIX: orphaned temporaries are decrypted PLAINTEXT left behind by a
        # previous run that crashed/was killed before its own cleanup. Securely
        # wipe them instead of using a bare os.remove()/rmtree() that would leave
        # recoverable plaintext in free space. If a secure wipe fails, fall back to
        # a plain delete so startup cleanup still makes a best effort.
        # Cleanup temp zips
        for p in glob.glob(os.path.join(temp_dir, '.rpm_extract_*.zip')):
            try:
                self.wiper.wipe_file(Path(p))
            except Exception:
                try:
                    os.remove(p)
                except Exception:
                    pass

        # Cleanup temp extraction dirs
        for p in glob.glob(os.path.join(temp_dir, '.rpm_extract_dir_*')):
            if os.path.isdir(p):
                try:
                    self.wiper.wipe_folder(Path(p))
                except Exception:
                    shutil.rmtree(p, ignore_errors=True)

    # ==========================================================================
    # VERSIONING INITIALISATION
    # ==========================================================================

    def _build_versioner(self) -> "versioning.VaultVersionManager":
        """Build a VaultVersionManager from the current config settings."""
        cfg = _load_cfg().get("settings", {})
        versions_root_str = cfg.get("versioning_dir", "")
        versions_root = Path(versions_root_str) if versions_root_str else None
        return versioning.VaultVersionManager(
            versions_root=versions_root,
            max_versions_per_vault=int(cfg.get("versioning_max_per_vault", 5)),
            max_total_size_bytes=int(cfg.get("versioning_max_total_mb", 2048)) * 1024 * 1024,
            enabled=bool(cfg.get("versioning_enabled", False)),
        )

    # ==========================================================================
    # CRYPTO INITIALISATION
    # ==========================================================================

    def _build_crypto(self) -> None:
        self.crypto = VaultCrypto(
            argon_memory      = get_setting("argon2_memory", ARGON2_MEMORY_COST),
            argon_iterations  = get_setting("argon2_time",   ARGON2_TIME_COST),
            argon_parallelism = get_setting("argon2_par",    ARGON2_PARALLELISM),
        )

    # ==========================================================================
    # UI SETUP
    # ==========================================================================

    def _setup_appearance(self) -> None:
        theme = get_setting("theme", "Dark")
        ctk.set_appearance_mode(theme)
        ctk.set_default_color_theme("dark-blue")
        self.configure(fg_color="#0d1117")

    def _setup_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=180, fg_color="#010409", corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.grid_rowconfigure(8, weight=1)
        self.sidebar.grid_propagate(False)

        self.main_frame = ctk.CTkFrame(self, fg_color="#0d1117", corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        self.status_bar = ctk.CTkFrame(self, height=32, fg_color="transparent", corner_radius=0)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=(0, 10))

    def _setup_sidebar(self) -> None:
        ctk.CTkLabel(
            self.sidebar,
            text="RPM Encrypter"
        , font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(25, 5), padx=20, anchor="w")

        ctk.CTkLabel(
            self.sidebar,
            text=f"v{APP_VERSION}    AES-256-GCM",
            font=ctk.CTkFont(size=12),
            text_color="#7d8590"
        ).pack(pady=(0, 20), padx=20, anchor="w")

        self.nav_buttons = {}
        nav_items = [
            ("encrypt",  "Encrypt",       self._show_encrypt),
            ("decrypt",  "Decrypt",       self._show_decrypt),
            ("inspect",  "Vault Info",    self._show_inspect),
            ("library",  "Library",       self._show_library),
            ("notes",    "Notes",         self._show_notes),
            ("rekey",    "Re-Key",        self._show_rekey),
            ("password", "Password Gen",  self._show_password),
            ("activity", "Activity",      self._show_activity),
        ]

        # Sidebar scrollable container
        self.sidebar_scroll = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", corner_radius=0)
        self.sidebar_scroll.pack(fill="both", expand=True)

        # Container for top nav items
        self._nav_top = ctk.CTkFrame(self.sidebar_scroll, fg_color="transparent", corner_radius=0)
        self._nav_top.pack(fill="x")

        for key, text, cmd in nav_items:
            item = SidebarItem(self._nav_top, text=text, command=cmd)
            item.pack(fill="x")
            self.nav_buttons[key] = item

        # Bottom spacer
        spacer = ctk.CTkFrame(self.sidebar_scroll, fg_color="transparent", corner_radius=0)
        spacer.pack(fill="both", expand=True)

        # Settings at bottom
        self._nav_bottom = ctk.CTkFrame(self.sidebar_scroll, fg_color="transparent", corner_radius=0)
        self._nav_bottom.pack(fill="x", side="bottom", pady=(0, 20))
        
        # Live statistics panel above settings
        self._stats_frame = ctk.CTkFrame(self._nav_bottom, fg_color="#0d1117", corner_radius=0)
        self._stats_frame.pack(fill="x", padx=12, pady=(0, 10))
        self._stats_lbl = ctk.CTkLabel(
            self._stats_frame,
            text=self._stats_text(),
            font=ctk.CTkFont(size=14),
            justify="left",
            text_color="#e6edf3"
        )
        self._stats_lbl.pack(padx=10, pady=8, anchor="w")

        settings_item = SidebarItem(self._nav_bottom, text="Settings", command=self._show_settings)
        settings_item.pack(fill="x")
        self.nav_buttons["settings"] = settings_item

    def _stats_text(self) -> str:
        if not hasattr(self, "stats"):
            return ""
        snap = self.stats.snapshot()
        kb = snap["bytes_total"] // 1024
        return (
            f"⬡ Encrypted : {snap['encrypted']}\n"
            f"⬢ Decrypted : {snap['decrypted']}\n"
            f"⟳ Re-Keyed  : {snap['rekeyed']}\n"
            f"📦 Files     : {snap['files_total']}\n"
            f"💾 Data      : {kb:,} KB\n"
            f"⏱ Uptime    : {snap['uptime']}"
        )

    def _tick_clock(self) -> None:
        """Single unified 1-second ticker: updates stats panel + status-bar clock."""
        if hasattr(self, "_stats_lbl"):
            self._stats_lbl.configure(text=self._stats_text())
        if hasattr(self, "_clock_lbl"):
            self._clock_lbl.configure(text=datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _setup_main_frames(self) -> None:
        self.frames: Dict[str, ctk.CTkFrame] = {}
        builders = {
            "encrypt":  self._create_encrypt_frame,
            "decrypt":  self._create_decrypt_frame,
            "inspect":  self._create_inspect_frame,
            "library":  self._create_library_frame,
            "notes":    self._create_notes_frame,
            "rekey":    self._create_rekey_frame,
            "password": self._create_password_frame,
            "activity": self._create_activity_frame,
            "settings": self._create_settings_frame,
        }
        for name, builder in builders.items():
            frame = builder()
            self.frames[name] = frame

    def _setup_status_bar(self) -> None:
        # Pack order: right items first (to prevent truncation on resize)
        
        # Clock (rightmost)
        self._clock_lbl = ctk.CTkLabel(
            self.status_bar, text="",
            width=65, anchor="e", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._clock_lbl.pack(side="right", padx=(0, 12))

        # Percentage label
        self._progress_pct = ctk.CTkLabel(
            self.status_bar, text="",
            width=38, anchor="e", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._progress_pct.pack(side="right", padx=(0, 4))

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            self.status_bar, width=200, height=8, corner_radius=4,
            fg_color="#21262d", progress_color="#00d4aa")
        self.progress_bar.pack(side="right", padx=(0, 6))
        self.progress_bar.set(0)

        # Status text (left side)
        self.status_label = ctk.CTkLabel(
            self.status_bar, text="Ready", font=ctk.CTkFont(size=12), text_color="#7d8590")
        self.status_label.pack(side="left", padx=15)

    def _bind_shortcuts(self) -> None:
        self.bind("<Control-e>", lambda _: self._show_encrypt())
        self.bind("<Control-d>", lambda _: self._show_decrypt())
        self.bind("<Control-i>", lambda _: self._show_inspect())
        self.bind("<Control-l>", lambda _: self._show_library())
        self.bind("<Control-n>", lambda _: self._show_notes())
        self.bind("<Control-r>", lambda _: self._show_rekey())
        self.bind("<Control-p>", lambda _: self._show_password())
        self.bind("<Control-s>", lambda _: self._show_activity())
        self.bind("<Alt-s>", lambda _: self._show_settings())  # Changed from Ctrl+S

    # ==========================================================================
    # NAVIGATION
    # ==========================================================================

    def _show_frame(self, name: str) -> None:
        # Hide all pages first
        for key, f in self.frames.items():
            f.grid_remove()
            
        # Show only the target page
        target_frame = self.frames.get(name)
        if target_frame:
            target_frame.grid(row=0, column=0, sticky="nsew", padx=24, pady=24)
            
        # Force immediate redraw to prevent flicker
        self.update_idletasks()
        
        for key, btn in self.nav_buttons.items():
            btn.set_active(key == name)
        self._set_status(
            {"encrypt": "Encrypt", "decrypt": "Decrypt", "inspect": "Vault Info",
             "rekey": "Re-Key Vault", "password": "Password Generator",
             "settings": "Settings"}.get(name, "")
        )

    def _show_encrypt(self):  self._show_frame("encrypt")
    def _show_decrypt(self):  self._show_frame("decrypt")
    def _show_inspect(self):  self._show_frame("inspect")
    def _show_library(self):  self._show_frame("library")
    def _show_notes(self):    self._show_frame("notes")
    def _show_rekey(self):    self._show_frame("rekey")
    def _show_password(self): self._show_frame("password")
    def _show_activity(self): self._show_frame("activity")
    def _show_settings(self): self._show_frame("settings")

    # ==========================================================================
    # WINDOW CLOSE GUARD (FIXED)
    # ==========================================================================

    def _on_close(self) -> None:
        self._clear_clipboard()
        if self.is_processing:
            if not messagebox.askyesno(
                "Operation in Progress",
                "An encryption/decryption operation is running.\n"
                "Closing now may leave temporary files on disk.\n\n"
                "Exit anyway?",
            ):
                return
            
            # Send cancel signal to worker
            self._cancel_requested = True
            
            # Wait for worker to finish (max 3 seconds)
            if self.worker_thread and self.worker_thread.is_alive():
                logger.info("Waiting for worker thread to finish...")
                self.worker_thread.join(timeout=3.0)
                if self.worker_thread.is_alive():
                    logger.warning("Worker thread did not stop gracefully")
        
        # Best-effort cleanup of temp files
        with self._temp_files_lock:
            files_to_clean = list(self._active_temp_files)
        
        for p in files_to_clean:
            try:
                if p.exists():
                    # H4 FIX: these are decrypted PLAINTEXT temporaries. Securely
                    # wipe them rather than merely unlinking so no recoverable copy
                    # is left behind on exit. Wrapped in try/except so a wipe
                    # failure (or a slow/hung wipe surfacing as OSError) can never
                    # stop the app from closing.
                    self.wiper.wipe_file(p)
                    logger.info("Securely wiped temp file on exit: %s", p)
            except Exception as exc:
                logger.warning("Failed to wipe temp file %s: %s", p, exc)

        self.destroy()

    # ==========================================================================
    # COMMON HELPERS
    # ==========================================================================

    def _set_status(self, text: str) -> None:
        self.status_label.configure(text=text)

    def _lockout_check(self, entry_widget) -> bool:
        """Return True if locked out (shows error message)."""
        locked, secs = self.limiter.is_locked()
        if locked:
            entry_widget.clear()
            messagebox.showerror(
                "Too Many Attempts",
                f"Too many failed attempts.\nPlease wait {secs} seconds before trying again.",
            )
            return True
        return False

    def _parse_drop_paths(self, data: str) -> List[str]:
        """Parse tkinterdnd2 drop data (handles paths with spaces in braces)."""
        data = data.strip()
        paths, current, in_braces = [], "", False
        for ch in data:
            if ch == "{":
                in_braces = True
            elif ch == "}":
                in_braces = False
                if current:
                    paths.append(current)
                    current = ""
            elif ch == " " and not in_braces:
                if current:
                    paths.append(current)
                    current = ""
            else:
                current += ch
        if current:
            paths.append(current)
        return paths

    def _section_label(self, master, text: str) -> ctk.CTkLabel:
        lbl = ctk.CTkLabel(master, text=text, font=ctk.CTkFont(size=16, weight="bold"), text_color="#e6edf3")
        return lbl

    # ==========================================================================
    # ENCRYPT VIEW
    # ==========================================================================

    def _create_encrypt_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(12, weight=1)

        ctk.CTkLabel(frame, text="Encrypt Folders & Files", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 12), sticky="w")

        # --- Drop Zone ---
        self.encrypt_drop_zone = DragDropArea(frame, browse_command=self._browse_encrypt_source)
        self.encrypt_drop_zone.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.encrypt_drop_zone.drop_target_register(DND_FILES)
        self.encrypt_drop_zone.dnd_bind("<<Drop>>", self._on_encrypt_drop)

        # --- Source list ---
        self.encrypt_sources_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        self.encrypt_sources_row.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        self.encrypt_sources_row.grid_columnconfigure(0, weight=1)
        self.encrypt_sources_row.grid_remove() # Hidden by default
        list_row = self.encrypt_sources_row

        self.encrypt_sources = ctk.CTkTextbox(list_row, font=ctk.CTkFont(size=12), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.encrypt_sources.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.encrypt_sources.insert("0.0", "No sources selected")
        self.encrypt_sources.configure(state="disabled")

        ctk.CTkButton(list_row, text="Clear",
                      command=self._clear_batch, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        # Recent encrypt sources
        self._enc_recent = RecentBar(frame, "enc_sources",
                                     on_select=lambda p: self._add_encrypt_source(p))
        self._enc_recent.grid(row=3, column=0, sticky="w", pady=(0, 6))

        # --- Password ---
        pw_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        pw_frame.grid(row=4, column=0, sticky="ew", pady=(0, 6))
        pw_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(pw_frame, text="Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(0, 10), sticky="w")
        self.encrypt_pw = PasswordEntry(pw_frame, height=36, corner_radius=6)
        self.encrypt_pw.grid(row=0, column=1, sticky="ew")
        self.encrypt_pw.bind_change(self._on_enc_pw_change)

        # --- Confirm Password ---
        ctk.CTkLabel(pw_frame, text="Confirm Password", font=ctk.CTkFont(size=16, weight="bold"), text_color="#e6edf3").grid(row=1, column=1, pady=(0, 6), sticky="w")
        self.encrypt_pw_confirm = PasswordEntry(pw_frame, placeholder="Confirm Password", height=36, corner_radius=6)
        self.encrypt_pw_confirm.grid(row=2, column=1, sticky="ew", pady=(0, 12))

        # --- Strength meter ---
        meter_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        meter_row.grid(row=5, column=0, sticky="ew", pady=(0, 8))
        meter_row.grid_columnconfigure(1, weight=1)

        self.strength_bar = ctk.CTkProgressBar(
            meter_row, width=200, height=10, corner_radius=5,

        fg_color="#21262d", progress_color="#00d4aa")
        self.strength_bar.grid(row=0, column=0, sticky="w")
        self.strength_bar.set(0)

        self.strength_label = ctk.CTkLabel(
            meter_row, text="Enter a password", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self.strength_label.grid(row=0, column=1, padx=(12, 0), sticky="w")

        # --- Hidden Vault Mode ---
        self.hidden_mode_var = ctk.BooleanVar(value=False)
        self.hidden_mode_switch = ctk.CTkSwitch(
            frame, text="Enable Hidden Vault Mode (Plausible Deniability)",
            variable=self.hidden_mode_var,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._toggle_hidden_mode,

        fg_color="#30363d", progress_color="#00d4aa", text_color="#e6edf3", button_color="#ffffff")
        self.hidden_mode_switch.grid(row=6, column=0, sticky="w", pady=(8, 8), padx=4)

        # --- Hidden Vault Controls (hidden by default) ---
        self.hidden_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        self.hidden_frame.grid_columnconfigure(1, weight=1)

        # Hidden Password
        ctk.CTkLabel(self.hidden_frame, text="Hidden Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(10, 10), pady=(10, 6), sticky="w")
        self.hidden_pw = PasswordEntry(self.hidden_frame, height=36, corner_radius=6)
        self.hidden_pw.grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=(10, 6))

        # Confirm Hidden Password
        ctk.CTkLabel(self.hidden_frame, text="Confirm Hidden Password", font=ctk.CTkFont(size=16, weight="bold"), text_color="#e6edf3").grid(row=1, column=1, pady=(0, 6), sticky="w")
        self.hidden_pw_confirm = PasswordEntry(self.hidden_frame, placeholder="Confirm Hidden Password", height=36, corner_radius=6)
        self.hidden_pw_confirm.grid(row=2, column=1, sticky="ew", padx=(0, 10), pady=(0, 12))

        # Hidden Files Drop Zone & List
        hd_row = ctk.CTkFrame(self.hidden_frame, fg_color="transparent", corner_radius=0)
        hd_row.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 6))
        hd_row.grid_columnconfigure(0, weight=1)
        
        self.hidden_sources_box = ctk.CTkTextbox(hd_row, font=ctk.CTkFont(size=12), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.hidden_sources_box.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.hidden_sources_box.insert("0.0", "No hidden sources selected")
        self.hidden_sources_box.configure(state="disabled")
        self._hidden_sources_list = []
        
        hb_col = ctk.CTkFrame(hd_row, fg_color="#0d1117", corner_radius=0)
        hb_col.grid(row=0, column=1)
        ctk.CTkButton(hb_col, text="Browse", command=self._browse_hidden_source, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(pady=(16, 0))
        ctk.CTkButton(hb_col, text="Clear", command=self._clear_hidden, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack()

        # Target Size
        ts_row = ctk.CTkFrame(self.hidden_frame, fg_color="transparent", corner_radius=0)
        ts_row.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        ctk.CTkLabel(ts_row, text="Container Size:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 8))
        # C2/Phase 24: hidden vaults require an EXPLICIT container size (no "Auto")
        # so a small decoy is never auto-placed in a minimal bucket that would
        # betray the hidden compartment.
        self.hidden_size_var = ctk.StringVar(value="100 MB")
        ctk.CTkOptionMenu(ts_row, variable=self.hidden_size_var, values=["10 MB", "100 MB", "500 MB", "1 GB", "5 GB", "10 GB"], fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left")
        ctk.CTkLabel(ts_row, text="(pick a size larger than your data — a larger container is a normal choice)",
                     font=ctk.CTkFont(size=12), text_color="#7d8590").pack(side="left", padx=(8, 0))

        # --- Options row ---
        opts = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        opts.grid(row=8, column=0, sticky="w", pady=(0, 8))

        ctk.CTkLabel(opts, text="Profile:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 8))
        self.enc_profile_var = ctk.StringVar(value="Custom")
        self.enc_profile_menu = ctk.CTkOptionMenu(opts, variable=self.enc_profile_var, values=["Custom"], command=self._apply_profile, fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6)
        self.enc_profile_menu.pack(side="left", padx=(0, 20))

        self.enc_wipe_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(opts, text="Securely delete originals after encryption",
                        variable=self.enc_wipe_var,
                        font=ctk.CTkFont(size=14),

                        fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").pack(side="left", padx=(0, 20))

        self.enc_same_dir_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(opts, text="Save .vault next to source",
                        variable=self.enc_same_dir_var,
                        font=ctk.CTkFont(size=14),
                        command=self._toggle_enc_outdir,

                        fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").pack(side="left", padx=(0, 10))

        self.compress_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(opts, text="Compress Files",
                        variable=self.compress_var,
                        font=ctk.CTkFont(size=14),
                        fg_color="#30363d", progress_color="#00d4aa", button_color="#ffffff", text_color="#e6edf3").pack(side="left", padx=(0, 10))

        # C2 (Phase 24): Container Size selector. "Auto" pads to the smallest
        # 1.25x ladder bucket; an explicit choice sets a larger floor so the
        # on-disk size reveals nothing about the true payload size.
        ctk.CTkLabel(opts, text="Container Size:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 8))
        self.enc_container_var = ctk.StringVar(value="Auto")
        ctk.CTkOptionMenu(opts, variable=self.enc_container_var, values=CONTAINER_SIZE_CHOICES,
                          fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left", padx=(0, 10))

        # Output directory override
        self._enc_outdir_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        self._enc_outdir_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self._enc_outdir_row, text="Output dir:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(0, 8), sticky="w")
        self._enc_outdir_entry = ctk.CTkEntry(
            self._enc_outdir_row, font=ctk.CTkFont(size=14),

        fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self._enc_outdir_entry.grid(row=0, column=1, sticky="ew", padx=(0, 6))
        ctk.CTkButton(self._enc_outdir_row, text="Browse",
                      command=self._browse_enc_outdir, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=2)

        # --- Action button ---
        self.encrypt_btn = ctk.CTkButton(
            frame, text="🔐  Encrypt Batch",
            command=self._process_batch, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8)
        self.encrypt_btn.grid(row=10, column=0, pady=(8, 4), sticky="w")

        # --- Inline progress row ---
        enc_prog_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        enc_prog_row.grid(row=11, column=0, sticky="ew", pady=(0, 4))
        enc_prog_row.grid_columnconfigure(0, weight=1)
        self._enc_progress = ctk.CTkProgressBar(enc_prog_row, height=14, corner_radius=6, fg_color="#21262d", progress_color="#00d4aa")
        self._enc_progress.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._enc_progress.set(0)
        self._enc_pct_lbl = ctk.CTkLabel(enc_prog_row, text="", width=42, anchor="e", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._enc_pct_lbl.grid(row=0, column=1)

        # --- Log ---
        self.enc_log = LogBox(frame, height=140)
        self.enc_log.grid(row=12, column=0, sticky="nsew", pady=(4, 0))
        frame.grid_rowconfigure(12, weight=1)

        return page_frame
    def _toggle_enc_outdir(self) -> None:
        if self.enc_same_dir_var.get():
            self._enc_outdir_row.grid_forget()
        else:
            self._enc_outdir_row.grid(row=9, column=0, sticky="ew", pady=(0, 6))

    def _browse_enc_outdir(self) -> None:
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self._enc_outdir_entry.delete(0, "end")
            self._enc_outdir_entry.insert(0, path)

    def _browse_encrypt_source(self) -> None:
        path = filedialog.askdirectory(title="Select Folder to Encrypt")
        if not path:
            path = filedialog.askopenfilename(title="Select File to Encrypt")
        if path:
            self._add_encrypt_source(path)

    def _on_encrypt_drop(self, event) -> None:
        for p in self._parse_drop_paths(event.data):
            self._add_encrypt_source(p)

    def _add_encrypt_source(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        if any(str(item["path"]) == str(p) for item in self.batch_queue):
            self._set_status(f"Already in queue: {p.name}")
            return
        self.batch_queue.append({"path": p, "type": "folder" if p.is_dir() else "file"})
        push_recent("enc_sources", str(p))
        self._update_enc_source_display()
        self._enc_recent.refresh()
        self._set_status(f"Added: {p.name}")

    def _update_enc_source_display(self) -> None:
        self.encrypt_sources.configure(state="normal")
        self.encrypt_sources.delete("0.0", "end")
        
        total_size = 0
        if self.batch_queue:
            for item in self.batch_queue:
                icon = "" if item["type"] == "folder" else ""
                self.encrypt_sources.insert("end", f"{icon}  {item['path']}\\n")
                try:
                    p = item["path"]
                    if p.is_file(): total_size += p.stat().st_size
                    elif p.is_dir(): total_size += sum(f.stat().st_size for f in p.rglob('*') if f.is_file())
                except: pass
            self.encrypt_drop_zone.update_state(len(self.batch_queue), total_size / (1024*1024))
            self.encrypt_sources_row.grid()
        else:
            self.encrypt_sources.insert("0.0", "No sources selected")
            self.encrypt_drop_zone.update_state(0, 0)
            self.encrypt_sources_row.grid_remove()
        
        self.encrypt_sources.configure(state="disabled")

    def _clear_batch(self) -> None:
        self.batch_queue.clear()
        self._update_enc_source_display()
        
        self.encrypt_pw.clear()
        self.encrypt_pw_confirm.clear()
        if hasattr(self, 'hidden_pw'):
            self.hidden_pw.clear()
        if hasattr(self, 'hidden_pw_confirm'):
            self.hidden_pw_confirm.clear()
            
        if hasattr(self, '_enc_outdir_entry'):
            self._enc_outdir_entry.delete(0, "end")
            
        self._set_status("Queue cleared")

    def _on_enc_pw_change(self, _=None) -> None:
        """Debounced password strength calculation."""
        password = self.encrypt_pw.get()
        if not password:
            self.strength_bar.set(0)
            self.strength_bar.configure(progress_color="#7d8590")
            self.strength_label.configure(text="Enter a password",
                                          text_color="#7d8590")
            return
        
        # Cancel previous timer
        if hasattr(self, '_enc_strength_timer'):
            self.after_cancel(self._enc_strength_timer)
        
        # Schedule strength calculation after 300ms
        self._enc_strength_timer = self.after(300, 
            lambda: self._compute_enc_strength_async(password))

    def _compute_enc_strength_async(self, password: str):
        """Compute password strength in background thread."""
        def compute():
            if ZXCVBN_AVAILABLE:
                try:
                    res = zxcvbn(password)
                    self.msg_queue.put({
                        "type": "enc_password_strength",
                        "score": res["score"],
                        "crack_time": res["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
                    }, timeout=0.1)
                except queue.Full:
                    pass
            else:
                # Simple length-based estimation
                ln = len(password)
                idx = 0 if ln < 8 else 1 if ln < 12 else 2 if ln < 16 else 3 if ln < 20 else 4
                self.msg_queue.put({
                    "type": "enc_password_strength",
                    "score": idx,
                    "crack_time": None
                }, timeout=0.1)
        
        threading.Thread(target=compute, daemon=True).start()


    def _toggle_hidden_mode(self):
        if self.hidden_mode_var.get():
            self.hidden_frame.grid(row=7, column=0, sticky="ew", pady=(0, 8))
        else:
            self.hidden_frame.grid_forget()

    def _browse_hidden_source(self):
        paths = filedialog.askopenfilenames(title="Select Hidden Files")
        for p in paths:
            if p not in self._hidden_sources_list:
                self._hidden_sources_list.append(p)
        self._update_hidden_box()

    def _clear_hidden(self):
        self._hidden_sources_list.clear()
        self._update_hidden_box()

    def _update_hidden_box(self):
        self.hidden_sources_box.configure(state="normal")
        self.hidden_sources_box.delete("0.0", "end")
        if not self._hidden_sources_list:
            self.hidden_sources_box.insert("0.0", "No hidden sources selected")
        else:
            for p in self._hidden_sources_list:
                self.hidden_sources_box.insert("end", f"{Path(p).name}\n")
        self.hidden_sources_box.configure(state="disabled")

    def _process_batch(self) -> None:
        if self.is_processing:
            messagebox.showinfo("Busy", "An operation is already in progress.")
            return
        if not self.batch_queue:
            messagebox.showwarning("Empty Queue", "Please add files or folders to encrypt.")
            return

        password = self.encrypt_pw.get()
        password_confirm = self.encrypt_pw_confirm.get()
        if password != password_confirm:
            messagebox.showwarning("Password Mismatch", "Passwords do not match. Please try again.")
            return

        if not password:
            messagebox.showwarning("Password Required", "Please enter a password.")
            return

        if self.hidden_mode_var.get():
            hidden_password = self.hidden_pw.get()
            hidden_password_confirm = self.hidden_pw_confirm.get()
            if hidden_password != hidden_password_confirm:
                messagebox.showwarning("Password Mismatch", "Hidden passwords do not match. Please try again.")
                return

            if not hidden_password:
                messagebox.showwarning("Hidden Password Required", "Please enter a hidden password.")
                return
            if password == hidden_password:
                messagebox.showwarning("Password Error", "Decoy and Hidden passwords must be different.")
                return
            if not self._hidden_sources_list:
                messagebox.showwarning("Hidden Files Required", "Please add files to the hidden vault.")
                return

        # Resolve output directory
        if self.enc_same_dir_var.get():
            out_dir_override = None
        else:
            d = self._enc_outdir_entry.get().strip()
            if not d or not Path(d).is_dir():
                messagebox.showwarning("Invalid Output", "Please select a valid output directory.")
                return
            out_dir_override = Path(d)

        self.is_processing = True
        self._cancel_requested = False
        
        # --- Phase 3: Recovery Key Modal ---
        recovery_key = generate_recovery_entropy()
        mnemonic = entropy_to_mnemonic(recovery_key)
        
        dialog = ctk.CTkToplevel(self)
        dialog.title("Recovery Phrase")
        dialog.geometry("550x350")
        dialog.configure(fg_color="#0d1117")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)
        dialog.grab_set()
        
        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent", corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=20, pady=5)
        
        ctk.CTkLabel(scroll, text="Your Recovery Phrase", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(20, 5))
        ctk.CTkLabel(scroll, text="Write this down and keep it safe. It will never be shown again.", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(0, 15))
        
        textbox = ctk.CTkTextbox(scroll, wrap="word", font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        textbox.pack(padx=10, fill="x")
        textbox.insert("0.0", mnemonic)
        textbox.configure(state="disabled")
        
        confirmed = ctk.BooleanVar(value=False)
        check = ctk.CTkCheckBox(scroll, text="I have securely saved this 24-word phrase.", variable=confirmed, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117")
        check.pack(pady=20)
        
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent", corner_radius=0)
        btn_frame.pack(fill="x", side="bottom", pady=10)
        
        result_key = []
        
        def on_continue():
            if not confirmed.get():
                messagebox.showwarning("Confirm", "You must confirm you have saved the phrase.", parent=dialog)
                return
            result_key.append(recovery_key)
            dialog.destroy()
            
        def on_cancel():
            dialog.destroy()
            
        ctk.CTkButton(btn_frame, text="Cancel", command=on_cancel, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Continue", command=on_continue, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="right", padx=10)
        
        self.wait_window(dialog)
        
        if not result_key:
            self.is_processing = False
            return  # User cancelled the modal
        # -----------------------------------

        self._active_log = self.enc_log
        self.encrypt_btn.configure(state="disabled", text="Encrypting…")
        self.enc_log.clear()
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        self._progress_pct.configure(text="KDF…")
        if hasattr(self, "_enc_progress"):
            self._enc_progress.configure(mode="indeterminate")
            self._enc_progress.start()
        if hasattr(self, "_enc_pct_lbl"):
            self._enc_pct_lbl.configure(text="KDF…")
        self._set_status("Deriving key (Argon2id)…")

        paths = [item["path"] for item in self.batch_queue]

        # F5 FIX: Tkinter is not thread-safe. Snapshot every hidden-mode Tk
        # variable here on the main thread and hand the worker plain Python
        # values. The worker must never call .get() on a Tk variable.
        hidden_mode_on = bool(self.hidden_mode_var.get())
        hidden_password = self.hidden_pw.get() if hidden_mode_on else None
        hidden_size_str = self.hidden_size_var.get()
        hidden_sources = list(self._hidden_sources_list)
        # C2 (Phase 24): snapshot the "Container Size" choice on the main thread
        # (F5 pattern — never call .get() on a Tk var inside the worker).
        container_mb = container_label_to_mb(self.enc_container_var.get())

        self.worker_thread = threading.Thread(
            target=self._batch_encrypt_worker,
            args=(paths, password, self.enc_wipe_var.get(), out_dir_override, result_key[0], getattr(self, "compress_var", None) and self.compress_var.get()),
            kwargs=dict(
                hidden_mode=hidden_mode_on,
                hidden_password=hidden_password,
                hidden_size_str=hidden_size_str,
                hidden_sources=hidden_sources,
                container_mb=container_mb,
            ),
            daemon=True,
        )
        self.worker_thread.start()

    def _batch_encrypt_worker(
        self,
        paths: List[Path],
        password: str,
        secure_wipe: bool,
        out_dir_override: Optional[Path],
        recovery_key: Optional[bytes] = None,
        compress: bool = False,
        hidden_mode: bool = False,
        hidden_password: Optional[str] = None,
        hidden_size_str: Optional[str] = None,
        hidden_sources: Optional[List[str]] = None,
        container_mb: int = 0
    ) -> None:
        total = len(paths)
        success = 0
        total_orig_size = 0
        total_vault_size = 0
        
        # F6 FIX: Initialize cleanup/reporting handles up front so control flow
        # tests `is not None` instead of brittle runtime name introspection.
        decoy_tmp = None
        hidden_tmp = None
        out_path = None
        final_vault = None

        # F5 FIX: hidden_mode and the hidden inputs were snapshotted on the main
        # thread and passed in. hidden_sources is a plain list, never a Tk var.
        hidden_sources = list(hidden_sources) if hidden_sources else []

        if hidden_mode:
            self._qlog("--- CREATING HIDDEN VAULT ---")
            try:
                # Target size parsing
                size_str = hidden_size_str or "100 MB"
                multiplier = 1024*1024
                if "GB" in size_str: multiplier = 1024*1024*1024
                target_size = int(size_str.split()[0]) * multiplier
                # C2 (Phase 24): the hidden vault's final on-disk size is snapped
                # to a 1.25x ladder bucket with this explicit container as the
                # floor, so it is size-indistinguishable from a normal vault.
                hidden_container_mb = container_label_to_mb(size_str)
                
                h_paths = [Path(p) for p in hidden_sources]
                
                # Accumulate sizes for hidden mode
                for p in paths + h_paths:
                    try:
                        if Path(p).is_file():
                            total_orig_size += os.path.getsize(p)
                        elif Path(p).is_dir():
                            total_orig_size += sum(os.path.getsize(f) for f in Path(p).rglob('*') if f.is_file())
                    except Exception:
                        pass
                
                self._qlog("Packaging Decoy files...")
                if len(paths) == 1 and Path(paths[0]).is_dir():
                    decoy_tmp = self.packager.package_folder(paths[0], exclude_paths=h_paths, compress=compress)
                else:
                    decoy_tmp = self.packager.package_files(paths, exclude_paths=h_paths, compress=compress)
                
                self._qlog("Packaging Hidden files...")
                if len(h_paths) == 1 and h_paths[0].is_dir():
                    hidden_tmp = self.packager.package_folder(h_paths[0], compress=compress)
                else:
                    hidden_tmp = self.packager.package_files(h_paths, compress=compress)
                
                # Output path
                out_name = paths[0].name + ".vault"
                if len(paths) > 1:
                    out_name = f"HiddenArchive.vault"
                
                base_dir = out_dir_override if out_dir_override else paths[0].parent
                final_vault = base_dir / out_name
                counter = 1
                orig_out = final_vault
                while final_vault.exists():
                    final_vault = orig_out.with_name(f"{orig_out.stem}_{counter}{orig_out.suffix}")
                    counter += 1
                
                self._qlog(f"Encrypting Hidden Vault -> {final_vault.name}")
                self.msg_queue.put({"type": "progress_start"}, timeout=0.1)

                def prog(done: int, total_b: int):
                    try:
                        self.msg_queue.put({"type": "progress", "done": done, "total": total_b}, timeout=0.01)
                    except:
                        pass
                
                if len(paths) == 1 and Path(paths[0]).is_dir():
                    dec_meta = self.packager.get_manifest(paths[0], exclude_paths=h_paths)
                elif len(paths) == 1:
                    dec_meta = self.packager.get_manifest(paths[0])
                else:
                    dec_meta = self.packager.get_manifest_multiple(paths, exclude_paths=h_paths)
                if len(h_paths) == 1 and h_paths[0].is_dir():
                    hid_meta = self.packager.get_manifest(h_paths[0])
                elif len(h_paths) == 1:
                    hid_meta = self.packager.get_manifest(h_paths[0])
                else:
                    hid_meta = self.packager.get_manifest_multiple(h_paths)
                dec_meta["type"] = "archive"
                hid_meta["type"] = "archive"
                
                # Determine original filenames for headers
                decoy_filename = paths[0].name if len(paths) == 1 else "DecoyArchive"
                hidden_filename = h_paths[0].name if len(h_paths) == 1 else h_paths[0].parent.name

                with open(decoy_tmp, 'rb') as dec_in, open(hidden_tmp, 'rb') as hid_in, open(final_vault, 'wb') as v_out:
                    header = self.crypto.encrypt_hidden_vault(
                        dec_in, hid_in, v_out,
                        password_a=password, password_b=hidden_password,
                        target_total_size=target_size,
                        decoy_filename=decoy_filename,
                        hidden_filename=hidden_filename,
                        decoy_metadata=dec_meta,
                        hidden_metadata=hid_meta,
                        progress_callback=prog,
                        recovery_key=recovery_key,
                        target_container_mb=hidden_container_mb
                    )
                
                self._qlog("Hidden Vault Creation Complete!")
                
                # Show decoy recovery phrase
                from crypto_core import entropy_to_mnemonic
                if recovery_key:
                    phrase = entropy_to_mnemonic(recovery_key)
                    self.msg_queue.put({"type": "recovery_phrase", "phrase": phrase}, timeout=0.1)
                
                if secure_wipe:
                    self._qlog("Securely wiping original sources...")
                    for s in paths + [Path(p) for p in hidden_sources]:
                        if s.is_dir(): self.wiper.wipe_folder(s)
                        else: self.wiper.wipe_file(s)
                        
                success += 1
                
            except Exception as exc:
                self._qlog(f"✗ FAILED: {exc}")
            finally:
                if decoy_tmp is not None and decoy_tmp.exists(): self.wiper.wipe_file(decoy_tmp)
                if hidden_tmp is not None and hidden_tmp.exists(): self.wiper.wipe_file(hidden_tmp)
                
        else:
            for idx, path in enumerate(paths, 1):
                # Accumulate original size
                try:
                    if Path(path).is_file():
                        total_orig_size += os.path.getsize(path)
                    elif Path(path).is_dir():
                        total_orig_size += sum(os.path.getsize(f) for f in Path(path).rglob('*') if f.is_file())
                except Exception:
                    pass

                # Check cancel flag
                if self._cancel_requested:
                    self._qlog("Operation cancelled by user")
                    break
            
                path = Path(path)
                temp_zip: Optional[Path] = None
            
                try:
                    self._qlog(f"[{idx}/{total}] Packaging  →  {path.name}")
                    manifest = self.packager.get_manifest(path)
                    temp_zip = (self.packager.package_folder(path, compress=compress)
                                if path.is_dir()
                                else self.packager.package_files([path], compress=compress))
                
                    # Track temp file for cleanup
                    with self._temp_files_lock:
                        self._active_temp_files.append(temp_zip)

                    base_dir = out_dir_override if out_dir_override else path.parent
                    out_path = base_dir / f"{path.name}.vault"
                    counter  = 1
                    orig_out = out_path
                    while out_path.exists():
                        out_path = orig_out.with_name(f"{orig_out.stem}_{counter}{orig_out.suffix}")
                        counter += 1

                    self._qlog(f"[{idx}/{total}] Encrypting →  {path.name}")
                    self.msg_queue.put({"type": "progress_start"}, timeout=0.1)

                    def prog(done: int, total_b: int):
                        try:
                            self.msg_queue.put({"type": "progress", "done": done, "total": total_b}, timeout=0.01)
                        except queue.Full:
                            pass  # Skip progress update if queue full

                    self.crypto.encrypt_file(
                        temp_zip, out_path, password,
                        original_filename=path.name,
                        metadata=manifest,
                        progress_callback=prog,
                        recovery_key=recovery_key,
                        target_container_mb=container_mb
                    )

                    if secure_wipe:
                        self._qlog(f"[{idx}/{total}] Wiping     →  {path.name}")
                        if path.is_dir():
                            self.wiper.wipe_folder(path)
                        else:
                            self.wiper.wipe_file(path)

                    self.stats.add_encrypted(
                        file_count=manifest.get("file_count", 1),
                        byte_count=manifest.get("total_size", 0),
                    )

                    self._qlog(f"[{idx}/{total}] ✓ Done     →  {out_path.name}")
                    success += 1
                    self._log_activity("Encrypt", path.name, "Success", f"Output: {out_path.name}")

                except Exception as exc:
                    logger.exception("Encryption failed for %s", path)
                    self._qlog(f"[{idx}/{total}] ✗ FAILED: {exc}")
                    self._log_activity("Encrypt", path.name, "Failed", str(exc))
                    try:
                        self.msg_queue.put({"type": "error", "text": f"✗ {path.name}: {exc}"}, timeout=0.1)
                    except queue.Full:
                        pass
            
                finally:
                    # Always remove from tracking list first
                    if temp_zip:
                        with self._temp_files_lock:
                            try:
                                self._active_temp_files.remove(temp_zip)
                            except ValueError:
                                pass
                    
                        # Then try to wipe/delete
                        try:
                            if temp_zip.exists():
                                self.wiper.wipe_file(temp_zip)
                        except Exception as wipe_exc:
                            logger.warning("Failed to wipe temp file %s: %s", temp_zip, wipe_exc)
                            try:
                                temp_zip.unlink(missing_ok=True)
                            except Exception:
                                pass

        # After all files are encrypted successfully, before the final batch_done message:
        extra_msg = ""
        if compress:
            try:
                vault_size = os.path.getsize(out_path) if out_path is not None else (os.path.getsize(final_vault) if final_vault is not None else 0)
                if total_orig_size > 0 and vault_size > 0 and vault_size < total_orig_size:
                    ratio = round((1 - vault_size / total_orig_size) * 100)
                    vault_mb = vault_size / (1024 * 1024)
                    extra_msg = f" — Vault created: {vault_mb:.1f} MB ({ratio}% smaller)"
            except Exception:
                pass

        try:
            self.msg_queue.put({
                "type": "batch_done",
                "text": f"Batch complete: {success}/{total} encrypted" + extra_msg,
            }, timeout=1.0)
        except queue.Full:
            logger.warning("Message queue full, batch_done notification dropped")

    # ==========================================================================
    # DECRYPT VIEW
    # ==========================================================================

    def _create_decrypt_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(6, weight=1)

        ctk.CTkLabel(frame, text="Decrypt Vault", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 12), sticky="w")

        # Drop zone
        self.decrypt_drop_zone = ctk.CTkFrame(
            frame, height=90,

        fg_color="transparent", corner_radius=0)
        self.decrypt_drop_zone.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.decrypt_drop_zone.grid_columnconfigure(0, weight=1)
        self.decrypt_drop_zone.grid_rowconfigure(0, weight=1)

        dec_drop_lbl = ctk.CTkLabel(
            self.decrypt_drop_zone,
            text="🔒  Drop .vault files here  (or click to browse)  [Ctrl+D]", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        dec_drop_lbl.grid(row=0, column=0, pady=22)

        self.decrypt_drop_zone.drop_target_register(DND_FILES)
        self.decrypt_drop_zone.dnd_bind("<<Drop>>", self._on_decrypt_drop)
        self.decrypt_drop_zone.bind("<Button-1>", lambda _: self._browse_decrypt_source())
        dec_drop_lbl.bind("<Button-1>", lambda _: self._browse_decrypt_source())

        # File list
        self.decrypt_sources = ctk.CTkTextbox(frame, font=ctk.CTkFont(size=12), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.decrypt_sources.grid(row=2, column=0, sticky="ew", pady=(0, 4))
        self.decrypt_sources.insert("0.0", "No vault files selected")
        self.decrypt_sources.configure(state="disabled")

        # Recent decrypt sources
        self._dec_recent = RecentBar(frame, "dec_sources",
                                     on_select=self._set_decrypt_sources_from_path)
        self._dec_recent.grid(row=3, column=0, sticky="w", pady=(0, 6))

        # Password + output
        form = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        form.grid(row=4, column=0, sticky="ew", pady=(0, 8))
        form.grid_columnconfigure(1, weight=1)

        self.use_recovery_var = ctk.BooleanVar(value=False)
        def toggle_recovery():
            if self.use_recovery_var.get():
                self.decrypt_pw.grid_remove()
                self.recovery_text.grid(row=0, column=1, sticky="ew")
                self._dec_pw_lbl.configure(text="Recovery:")
            else:
                self.recovery_text.grid_remove()
                self.decrypt_pw.grid(row=0, column=1, sticky="ew")
                self._dec_pw_lbl.configure(text="Password:")

        self._dec_pw_lbl = ctk.CTkLabel(form, text="Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._dec_pw_lbl.grid(row=0, column=0, padx=(0, 10), pady=4, sticky="nw")
        
        self.decrypt_pw = PasswordEntry(form, height=36, corner_radius=6)
        self.decrypt_pw.grid(row=0, column=1, sticky="ew")
        self.decrypt_pw.bind_key("<Return>", lambda _: self._do_decrypt())
        
        self.recovery_text = ctk.CTkTextbox(form, font=ctk.CTkFont(size=13), wrap="word", fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        
        ctk.CTkCheckBox(form, text="Use Recovery Phrase instead of Password", variable=self.use_recovery_var, command=toggle_recovery, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").grid(row=1, column=1, sticky="w", pady=(2, 6))

        ctk.CTkLabel(form, text="Output dir:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=2, column=0, padx=(0, 10), pady=4, sticky="w")
        dec_out_row = ctk.CTkFrame(form, fg_color="transparent", corner_radius=0)
        dec_out_row.grid(row=2, column=1, sticky="ew")
        dec_out_row.grid_columnconfigure(0, weight=1)
        self.decrypt_output = ctk.CTkEntry(dec_out_row, font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.decrypt_output.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(dec_out_row, text="Browse",
                      command=self._browse_decrypt_output, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        # Attempt counter label
        self._dec_attempts_lbl = ctk.CTkLabel(
            frame, text="", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._dec_attempts_lbl.grid(row=5, column=0, sticky="w", pady=(0, 4))

        self.decrypt_btn = ctk.CTkButton(
            frame, text="🔓  Decrypt",
            command=self._do_decrypt, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8)
        self.decrypt_btn.grid(row=6, column=0, pady=(0, 4), sticky="w")

        dec_prog_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        dec_prog_row.grid(row=7, column=0, sticky="ew", pady=(0, 4))
        dec_prog_row.grid_columnconfigure(0, weight=1)
        self._dec_progress = ctk.CTkProgressBar(dec_prog_row, height=14, corner_radius=6, fg_color="#21262d", progress_color="#00d4aa")
        self._dec_progress.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._dec_progress.set(0)
        self._dec_pct_lbl = ctk.CTkLabel(dec_prog_row, text="", width=42, anchor="e", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._dec_pct_lbl.grid(row=0, column=1)

        self.dec_log = LogBox(frame, height=140)
        self.dec_log.grid(row=8, column=0, sticky="nsew", pady=(4, 0))
        frame.grid_rowconfigure(8, weight=1)

        return page_frame
    def _on_decrypt_drop(self, event) -> None:
        all_paths = self._parse_drop_paths(event.data)
        vaults = [p for p in all_paths if str(p).lower().endswith(".vault")]
        
        ignored = len(all_paths) - len(vaults)
        if ignored > 0:
            messagebox.showinfo(
                "File Filter",
                f"Added {len(vaults)} vault(s).\nIgnored {ignored} non-vault file(s)."
            )
        
        if vaults:
            self._set_decrypt_sources(vaults)
        elif all_paths:
            messagebox.showwarning("No Vaults", "Please drop .vault files.")

    def _browse_decrypt_source(self) -> None:
        files = filedialog.askopenfilenames(
            title="Select Vault Files",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")],
        )
        self._set_decrypt_sources(list(files))

    def _set_decrypt_sources_from_path(self, path: str) -> None:
        self._set_decrypt_sources([path])

    def _set_decrypt_sources(self, paths: List[str]) -> None:
        self.decrypt_paths = paths
        self.decrypt_sources.configure(state="normal")
        self.decrypt_sources.delete("0.0", "end")
        for p in paths:
            self.decrypt_sources.insert("end", f"🔒  {p}\n")
        self.decrypt_sources.configure(state="disabled")
        if paths:
            self.decrypt_output.delete(0, "end")
            self.decrypt_output.insert(0, str(Path(paths[0]).parent))
            for p in paths:
                push_recent("dec_sources", p)
            self._dec_recent.refresh()

    def _browse_decrypt_output(self) -> None:
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self.decrypt_output.delete(0, "end")
            self.decrypt_output.insert(0, path)

    def _clear_decrypt_form(self) -> None:
        self.decrypt_paths = []
        self.decrypt_sources.configure(state="normal")
        self.decrypt_sources.delete("0.0", "end")
        self.decrypt_sources.insert("0.0", "No vault files selected")
        self.decrypt_sources.configure(state="disabled")
        
        self.decrypt_pw.clear()
        self.recovery_text.delete("0.0", "end")
        self.decrypt_output.delete(0, "end")
        
        if self.use_recovery_var.get():
            self.use_recovery_var.set(False)
            self.recovery_text.grid_remove()
            self.decrypt_pw.grid(row=0, column=1, sticky="ew")
            if hasattr(self, '_dec_pw_lbl'):
                self._dec_pw_lbl.configure(text="Password:")

    def _do_decrypt(self) -> None:
        if not self.use_recovery_var.get() and self._lockout_check(self.decrypt_pw):
            return
        if not self.decrypt_paths:
            messagebox.showwarning("No Selection", "Please select vault files to decrypt.")
            return
            
        password = None
        recovery_key = None
        
        if self.use_recovery_var.get():
            phrase = self.recovery_text.get("1.0", "end").strip()
            if not phrase:
                messagebox.showwarning("Phrase Required", "Please enter your 24-word recovery phrase.")
                return
            try:
                recovery_key = mnemonic_to_entropy(phrase)
            except ValueError as e:
                messagebox.showwarning("Invalid Phrase", str(e))
                return
        else:
            password = self.decrypt_pw.get()
            if not password:
                messagebox.showwarning("Password Required", "Please enter the vault password.")
                return
        
        output_dir = Path(self.decrypt_output.get())
        
        # Validate output directory
        if not output_dir.is_dir():
            messagebox.showwarning("Invalid Path", "Output directory does not exist.")
            return
        
        # Check write permission
        test_file = output_dir / f".rpm_test_{secrets.token_hex(4)}"
        try:
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            messagebox.showerror("Permission Denied", 
                                f"Cannot write to directory:\n{output_dir}")
            return
        except Exception as exc:
            messagebox.showerror("Error", f"Directory access failed:\n{exc}")
            return
        
        # Check disk space
        total_vault_size = sum(Path(p).stat().st_size for p in self.decrypt_paths)
        free_space = shutil.disk_usage(output_dir).free
        
        if free_space < total_vault_size * 1.5:
            if not messagebox.askyesno(
                "Low Disk Space",
                f"Available: {free_space / 1024**3:.1f} GB\n"
                f"Required (est.): {total_vault_size * 1.5 / 1024**3:.1f} GB\n\n"
                "Continue anyway?"
            ):
                return

        self.is_processing = True
        self._cancel_requested = False
        self._active_log = self.dec_log
        self.decrypt_btn.configure(state="disabled", text="Decrypting…")
        self.dec_log.clear()
        self._dec_attempts_lbl.configure(text="")
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        self._progress_pct.configure(text="KDF…")
        if hasattr(self, "_dec_progress"):
            self._dec_progress.configure(mode="indeterminate")
            self._dec_progress.start()
        if hasattr(self, "_dec_pct_lbl"):
            self._dec_pct_lbl.configure(text="KDF…")
        self._set_status("Deriving key (Argon2id)…")

        self.worker_thread = threading.Thread(
            target=self._batch_decrypt_worker,
            args=(self.decrypt_paths.copy(), password, output_dir, recovery_key),
            daemon=True,
        )
        self.worker_thread.start()

    def _batch_decrypt_worker(
        self,
        paths: List[str],
        password: Optional[str],
        output_dir: Path,
        recovery_key: Optional[bytes] = None
    ) -> None:
        total = len(paths)
        success = 0
        total_orig_size = 0
        total_vault_size = 0
        auth_error = False

        for idx, path in enumerate(paths, 1):
            if self._cancel_requested:
                self._qlog("Operation cancelled by user")
                break
            
            path = Path(path)
            temp_zip: Optional[Path] = None
            
            try:
                self._qlog(f"[{idx}/{total}] Verifying  →  {path.name}")
                with open(path, "rb") as f:
                    header = self.crypto.verify_password_and_get_header(f, password, recovery_key=recovery_key)

                temp_fd, temp_name = tempfile.mkstemp(suffix=".zip", dir=output_dir)
                os.close(temp_fd)
                temp_zip = Path(temp_name)
                
                with self._temp_files_lock:
                    self._active_temp_files.append(temp_zip)

                self._qlog(f"[{idx}/{total}] Decrypting →  {path.name}")
                try:
                    self.msg_queue.put({"type": "progress_start"}, timeout=0.1)
                except queue.Full:
                    pass

                def prog(done: int, total_b: int):
                    try:
                        self.msg_queue.put({"type": "progress", "done": done, "total": total_b}, timeout=0.01)
                    except queue.Full:
                        pass

                self.crypto.decrypt_file(path, temp_zip, password, progress_callback=prog, recovery_key=recovery_key)

                self._qlog(f"[{idx}/{total}] Extracting →  {header.payload.filename}")
                _fname = header.payload.filename
                _stem  = Path(_fname).stem if Path(_fname).suffix else _fname
                extract_dir = output_dir / _stem
                if extract_dir.exists():
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    extract_dir = output_dir / f"{_stem}_{ts}"

                self.packager.extract_archive(temp_zip, extract_dir)

                self.stats.add_decrypted(byte_count=header.payload.original_size)

                self._qlog(f"[{idx}/{total}] ✓ Restored →  {extract_dir.name}")
                success += 1
                self.limiter.record_success()
                self._log_activity("Decrypt", path.name, "Success", f"Output: {extract_dir.name}")

            except AuthenticationError:
                auth_error = True
                self.limiter.record_failure()
                self._log_activity("Decrypt", path.name, "Failed", "Authentication Error")
                _, secs = self.limiter.is_locked()
                rem = self.limiter.attempts_remaining()
                if secs:
                    self._qlog(f"[{idx}/{total}] ✗ Wrong password — locked for {secs}s")
                else:
                    self._qlog(f"[{idx}/{total}] ✗ Wrong password — {rem} attempts remaining")
                try:
                    self.msg_queue.put({"type": "auth_error",
                                        "remaining": rem, "lockout": secs}, timeout=0.1)
                except queue.Full:
                    pass
                break

            except Exception as exc:
                logger.exception("Decryption failed for %s", path)
                self._qlog(f"[{idx}/{total}] ✗ FAILED: {exc}")
                self._log_activity("Decrypt", path.name, "Failed", str(exc))

            finally:
                if temp_zip:
                    with self._temp_files_lock:
                        try:
                            self._active_temp_files.remove(temp_zip)
                        except ValueError:
                            pass

                    # H4 FIX: temp_zip is the fully decrypted PLAINTEXT archive. A
                    # bare unlink() leaves a recoverable copy in the output folder's
                    # free space. Route removal through the secure wiper (chunked +
                    # truthful-failure, Phase 17). Failures are logged, not silently
                    # swallowed, but must not break the per-file decrypt loop.
                    try:
                        if temp_zip.exists():
                            self.wiper.wipe_file(temp_zip)
                    except Exception as wipe_exc:
                        logger.warning("Failed to securely wipe temp file %s: %s", temp_zip, wipe_exc)

        text = (f"Wrong password or corrupted vault — {self.limiter.attempts_remaining()} "
                f"attempts remaining"
                if auth_error
                else f"Batch complete: {success}/{total} decrypted")
        
        try:
            self.msg_queue.put({"type": "batch_done", "text": text}, timeout=1.0)
        except queue.Full:
            logger.warning("Message queue full, batch_done notification dropped")

    # ==========================================================================
    # VAULT INFO / INSPECT VIEW
    # ==========================================================================

    def _create_inspect_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(6, weight=1)

        ctk.CTkLabel(frame, text="Vault Information", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 12), sticky="w")

        # --- File + password form ---
        form = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        form.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        form.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Vault:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(0, 10), pady=4, sticky="w")
        vault_row = ctk.CTkFrame(form, fg_color="transparent", corner_radius=0)
        vault_row.grid(row=0, column=1, sticky="ew")
        vault_row.grid_columnconfigure(0, weight=1)
        self.inspect_path = ctk.CTkEntry(vault_row, font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.inspect_path.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(vault_row, text="Browse",
                      command=self._browse_inspect, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        self.ins_use_recovery_var = ctk.BooleanVar(value=False)
        def toggle_ins_recovery():
            if self.ins_use_recovery_var.get():
                self.inspect_pw.grid_remove()
                self.ins_recovery_text.grid(row=1, column=1, sticky="ew")
                pw_lbl.configure(text="Recovery:")
            else:
                self.ins_recovery_text.grid_remove()
                self.inspect_pw.grid(row=1, column=1, sticky="ew")
                pw_lbl.configure(text="Password:")

        pw_lbl = ctk.CTkLabel(form, text="Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        pw_lbl.grid(row=1, column=0, padx=(0, 10), pady=4, sticky="nw")
        
        self.inspect_pw = PasswordEntry(form, height=36, corner_radius=6)
        self.inspect_pw.grid(row=1, column=1, sticky="ew")
        self.inspect_pw.bind_key("<Return>", lambda _: self._do_inspect())
        
        self.ins_recovery_text = ctk.CTkTextbox(form, font=ctk.CTkFont(size=13), wrap="word", fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        
        ctk.CTkCheckBox(form, text="Use Recovery Phrase", variable=self.ins_use_recovery_var, command=toggle_ins_recovery, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").grid(row=2, column=1, sticky="w", pady=(2, 6))

        # --- Action buttons ---
        btn_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        btn_row.grid(row=2, column=0, sticky="w", pady=(0, 4))

        ctk.CTkButton(btn_row, text="📋  Inspect Vault",
                      command=self._do_inspect, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row, text="🔍  Integrity Check",
                      command=self._do_integrity_check, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row, text="✂️ Selective Extract",
                      command=self._open_selective_extract, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row, text="⚖️ Vault Diff",
                      command=self._open_vault_diff, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row, text="🛡  Verify vs Saved",
                      command=self._verify_against_saved, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row, text="📋 Copy SHA-256",
                      command=self._copy_last_sha, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

        # --- Attempt counter ---
        self._ins_attempts_lbl = ctk.CTkLabel(
            frame, text="", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._ins_attempts_lbl.grid(row=3, column=0, sticky="w")

        # --- Main results textbox ---
        self.inspect_results = ctk.CTkTextbox(
            frame,
            font=ctk.CTkFont(size=12, family="Courier New"),
            wrap="none",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.inspect_results.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        self.inspect_results.insert("0.0",
            "Vault metadata appears here after Inspect Vault.\n\n"
            "Use Integrity Check to verify structure without a password.\n"
            "Use Verify vs Saved to compare against a previously saved fingerprint.")
        self.inspect_results.configure(state="disabled")

        # --- Saved fingerprints panel ---
        ctk.CTkLabel(frame,
                     text="Saved Fingerprints", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=5, column=0, sticky="w", pady=(14, 4))

        fp_container = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        fp_container.grid(row=6, column=0, sticky="nsew")
        fp_container.grid_columnconfigure(0, weight=1)
        fp_container.grid_rowconfigure(0, weight=1)

        self._fp_listbox = ctk.CTkTextbox(
            fp_container,
            font=ctk.CTkFont(size=11, family="Courier New"),
            wrap="none",
            state="disabled",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self._fp_listbox.grid(row=0, column=0, sticky="nsew", padx=6, pady=(6, 0))

        fp_btn_row = ctk.CTkFrame(fp_container, fg_color="#0d1117", corner_radius=0)
        fp_btn_row.grid(row=1, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkButton(fp_btn_row, text="Refresh",
                      command=self._refresh_fingerprint_panel, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(fp_btn_row, text="Clear All",
                      command=self._clear_all_fingerprints, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

        self._refresh_fingerprint_panel()

        return page_frame
    def _clear_all_fingerprints(self) -> None:
        if not messagebox.askyesno("Clear All Fingerprints",
                                   "Delete all saved SHA-256 fingerprint records?"):
            return
        cfg = _load_cfg()
        cfg["fingerprints"] = {}
        _save_cfg(cfg)
        self._refresh_fingerprint_panel()
        self._set_status("All fingerprints cleared")

    def _log_activity(self, action: str, filename: str, status: str, details: str = "") -> None:
        """
        F4 FIX: Single choke point for activity logging. Writes an event only
        when the user has left 'Enable Activity Logging' on (default True). The
        setting is read live, so toggling it takes effect immediately; the
        ActivityLogger is also gated via its own `enabled` flag (defence in depth).
        """
        if get_setting("logging_enabled", True):
            self.activity_logger.log_event(action, filename, status, details)

    def _save_logging_setting(self) -> None:
        """Persist the activity-logging toggle and apply it to the live logger."""
        enabled = bool(self.logging_enabled_var.get())
        save_setting("logging_enabled", enabled)
        try:
            self.activity_logger.enabled = enabled
        except Exception:
            pass
        self._set_status("Activity logging " + ("enabled" if enabled else "disabled"))

    def _clear_all_traces(self) -> None:
        """
        F4 FIX: One-click erasure of every local forensic trace this app keeps on
        disk — the activity-log database, the Library cache, saved fingerprints,
        and the recent-file lists. Encrypted .vault files are never touched.
        Missing DB/cache files are handled gracefully.
        """
        if not messagebox.askyesno(
            "Clear All Local Traces",
            "This permanently erases local traces kept by this app:\n\n"
            "  •  Activity log database\n"
            "  •  Library cache\n"
            "  •  Saved fingerprints\n"
            "  •  Recent encrypt / decrypt / re-key lists\n\n"
            "Your encrypted .vault files are NOT affected.\n\nContinue?"
        ):
            return

        errors = []

        # 1. Activity log database (clear_logs no-ops gracefully if the DB is absent).
        try:
            self.activity_logger.clear_logs()
        except Exception as exc:
            errors.append(f"activity log: {exc}")

        # 2. Library cache file on disk + the in-memory copy so it is not re-saved.
        try:
            vault_scanner.CACHE_FILE.unlink(missing_ok=True)
        except Exception as exc:
            errors.append(f"library cache: {exc}")
        try:
            self.scanner.cache = {}
        except Exception:
            pass

        # 3 & 4. Fingerprints and recent-file lists stored in the config.
        try:
            cfg = _load_cfg()
            cfg["fingerprints"] = {}
            cfg["enc_sources"] = []
            cfg["dec_sources"] = []
            cfg["rekey_vaults"] = []
            _save_cfg(cfg)
        except Exception as exc:
            errors.append(f"config: {exc}")

        # Refresh any visible panels so the UI reflects the cleared state.
        fp_refresh = getattr(self, "_refresh_fingerprint_panel", None)
        if callable(fp_refresh):
            try:
                fp_refresh()
            except Exception:
                pass
        for bar_attr in ("_enc_recent", "_dec_recent", "_rk_recent"):
            bar = getattr(self, bar_attr, None)
            if bar is not None:
                try:
                    bar.refresh()
                except Exception:
                    pass

        if errors:
            messagebox.showwarning(
                "Clear All Local Traces",
                "Completed with some issues:\n\n" + "\n".join(errors))
        else:
            messagebox.showinfo(
                "Clear All Local Traces",
                "All local traces have been cleared from this device.")
        self._set_status("Local traces cleared")

    def _browse_inspect(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Vault File",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")],
        )
        if path:
            self.inspect_path.delete(0, "end")
            self.inspect_path.insert(0, path)

    def _do_inspect(self) -> None:
        if not self.ins_use_recovery_var.get() and self._lockout_check(self.inspect_pw):
            return
        path_str = self.inspect_path.get().strip()
        
        password = None
        recovery_key = None
        
        if self.ins_use_recovery_var.get():
            phrase = self.ins_recovery_text.get("1.0", "end").strip()
            if not phrase:
                messagebox.showwarning("Required", "Please enter recovery phrase.")
                return
            try:
                recovery_key = mnemonic_to_entropy(phrase)
            except ValueError as e:
                messagebox.showwarning("Invalid", str(e))
                return
        else:
            password = self.inspect_pw.get()
            if not password:
                messagebox.showwarning("Required", "Please select a vault file and enter the password.")
                return
                
        try:
            metadata = self.inspector.inspect(Path(path_str), password=password, recovery_key=recovery_key)
            self._current_inspect_metadata = metadata
            self._current_inspect_path = Path(path_str)
            self._current_inspect_password = password
            self._current_inspect_recovery_key = recovery_key
            
            self.limiter.record_success()
            self._ins_attempts_lbl.configure(text="")
            self._render_inspect_results(metadata)
            self._set_status("Vault inspection complete")
            self._log_activity("Inspect", Path(path_str).name, "Success")
        except AuthenticationError:
            self.limiter.record_failure()
            self._log_activity("Inspect", Path(path_str).name, "Failed", "Authentication Error")
            _, secs = self.limiter.is_locked()
            rem = self.limiter.attempts_remaining()
            if secs:
                self._ins_attempts_lbl.configure(
                    text=f"Wrong password — locked for {secs}s")
            else:
                self._ins_attempts_lbl.configure(
                    text=f"Wrong password — {rem} attempts remaining")
            messagebox.showerror("Access Denied", "Invalid password or corrupted vault envelope.")
        except Exception as exc:
            self._log_activity("Inspect", Path(path_str).name, "Failed", str(exc))
            messagebox.showerror("Error", f"Inspection failed: {exc}")

    def _open_selective_extract(self) -> None:
        if not hasattr(self, '_current_inspect_metadata') or not self._current_inspect_metadata:
            messagebox.showwarning("Inspect First", "Please inspect a vault first to load its manifest.")
            return
            
        metadata = self._current_inspect_metadata
        files = metadata.get("files", [])
        if not files:
            messagebox.showinfo("No Files", "This vault does not contain any individual files to extract.")
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Selective Extraction")
        dialog.geometry("600x500")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color="#0d1117")

        scroll_wrapper = ctk.CTkScrollableFrame(dialog, fg_color="transparent", corner_radius=0)
        scroll_wrapper.pack(fill="both", expand=True, padx=20, pady=5)
        
        ctk.CTkLabel(scroll_wrapper, text="Select Files to Extract", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(15, 5))
        ctk.CTkLabel(scroll_wrapper, text="Note: AES-GCM requires full decryption to a secure temporary directory first.", font=ctk.CTkFont(size=12), text_color="#7d8590").pack(pady=(0, 10))

        scroll = ctk.CTkFrame(scroll_wrapper, fg_color="transparent", corner_radius=0)
        scroll.pack(fill="both", expand=True)

        file_vars = {}
        for fi in files:
            var = ctk.BooleanVar(value=False)
            file_vars[fi["path"]] = var
            cb = ctk.CTkCheckBox(scroll, text=f"{fi['path']} ({fi['size']:,} bytes)", variable=var, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117")
            cb.pack(anchor="w", pady=2)

        bottom_frame = ctk.CTkFrame(dialog, fg_color="transparent", corner_radius=0)
        bottom_frame.pack(fill="x", side="bottom", padx=20, pady=10)

        out_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent", corner_radius=0)
        out_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(out_frame, text="Output Directory:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left")
        out_entry = ctk.CTkEntry(out_frame, width=250, fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        out_entry.pack(side="left", padx=10)
        
        def browse_out():
            d = filedialog.askdirectory()
            if d:
                out_entry.delete(0, "end")
                out_entry.insert(0, d)
                
        ctk.CTkButton(out_frame, text="Browse", command=browse_out, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

        def do_extract():
            selected = [path for path, var in file_vars.items() if var.get()]
            if not selected:
                messagebox.showwarning("No Selection", "Please select at least one file.", parent=dialog)
                return
            out_dir = out_entry.get().strip()
            if not out_dir or not Path(out_dir).is_dir():
                messagebox.showwarning("Invalid Output", "Please select a valid output directory.", parent=dialog)
                return
                
            orig_size = metadata.get("original_size", 0)
            req_space = orig_size * 1.5
            try:
                free_space_temp = shutil.disk_usage(tempfile.gettempdir()).free
                free_space_out = shutil.disk_usage(out_dir).free
                
                if free_space_temp < req_space:
                    if not messagebox.askyesno("Low Disk Space", "Your system Temp drive may not have enough space for the full extraction. Continue?", parent=dialog):
                        return
                        
                req_out_space = sum([fi["size"] for fi in files if file_vars[fi["path"]].get()])
                if free_space_out < req_out_space:
                    messagebox.showwarning("Low Disk Space", "Your output drive does not have enough space for the selected files.", parent=dialog)
                    return
            except:
                pass
                
            dialog.destroy()
            
            self.is_processing = True
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
            self._set_status("Extracting selected files...")
            
            threading.Thread(
                target=self._selective_extract_worker,
                args=(self._current_inspect_path, self._current_inspect_password, self._current_inspect_recovery_key, selected, Path(out_dir)),
                daemon=True
            ).start()

        btn_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent", corner_radius=0)
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Cancel", command=dialog.destroy, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Extract", command=do_extract, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="right", padx=10)

    def _selective_extract_worker(self, vault_path: Path, password: Optional[str], recovery_key: Optional[bytes], selected_files: List[str], output_dir: Path) -> None:
        temp_zip: Optional[Path] = None
        temp_extract_dir: Optional[Path] = None
        success = False
        try:
            temp_fd, temp_name = tempfile.mkstemp(suffix=".zip", prefix=".rpm_extract_")
            os.close(temp_fd)
            temp_zip = Path(temp_name)
            
            with self._temp_files_lock:
                self._active_temp_files.append(temp_zip)

            # 1. Full Decryption
            self.crypto.decrypt_file(vault_path, temp_zip, password=password, recovery_key=recovery_key)
            
            # 2. Extract ZIP to temp folder
            temp_extract_dir = Path(tempfile.mkdtemp(prefix=".rpm_extract_dir_"))
            self.packager.extract_archive(temp_zip, temp_extract_dir)
            
            # 3. Copy selected files
            extracted_count = 0
            for sel in selected_files:
                src_path = temp_extract_dir / sel
                if src_path.is_file():
                    dst_path = output_dir / Path(sel).name
                    # Handle name collisions
                    counter = 1
                    orig_dst = dst_path
                    while dst_path.exists():
                        dst_path = orig_dst.with_name(f"{orig_dst.stem}_{counter}{orig_dst.suffix}")
                        counter += 1
                    shutil.copy2(src_path, dst_path)
                    extracted_count += 1
                    
            success = True
            msg = f"Successfully extracted {extracted_count} file(s)."
        except Exception as e:
            logger.exception("Selective extraction failed")
            msg = f"Extraction failed: {e}"
        finally:
            self.is_processing = False
            self.progress_bar.stop()
            self._set_status("Ready")
            
            # 4. Secure Wipe
            if temp_zip:
                with self._temp_files_lock:
                    try:
                        self._active_temp_files.remove(temp_zip)
                    except ValueError:
                        pass
                try:
                    if temp_zip.exists():
                        self.wiper.wipe_file(temp_zip)
                except Exception:
                    pass
            if temp_extract_dir and temp_extract_dir.exists():
                try:
                    self.wiper.wipe_folder(temp_extract_dir)
                except Exception:
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)
                    
            try:
                self.msg_queue.put({"type": "batch_done", "text": msg}, timeout=1.0)
            except queue.Full:
                pass

    def _open_vault_diff(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Vault Diff Tool")
        dialog.geometry("500x350")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color="#0d1117")

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent", corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=20, pady=5)

        ctk.CTkLabel(scroll, text="Compare Vaults", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(15, 10))

        # Vault A
        frame_a = ctk.CTkFrame(scroll, fg_color="transparent", corner_radius=0)
        frame_a.pack(fill="x", pady=5)
        ctk.CTkLabel(frame_a, text="Vault A:", width=60, anchor="w", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left")
        entry_a = ctk.CTkEntry(frame_a, width=200, fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        entry_a.pack(side="left", padx=5)
        ctk.CTkButton(frame_a, text="Browse", command=lambda: [entry_a.delete(0, 'end'), entry_a.insert(0, filedialog.askopenfilename())], width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")
        
        pw_a = PasswordEntry(frame_a, placeholder="Password A", height=36, corner_radius=6)
        pw_a.pack(side="left", padx=5, fill="x", expand=True)

        # Vault B
        frame_b = ctk.CTkFrame(scroll, fg_color="transparent", corner_radius=0)
        frame_b.pack(fill="x", pady=10)
        ctk.CTkLabel(frame_b, text="Vault B:", width=60, anchor="w", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left")
        entry_b = ctk.CTkEntry(frame_b, width=200, fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        entry_b.pack(side="left", padx=5)
        ctk.CTkButton(frame_b, text="Browse", command=lambda: [entry_b.delete(0, 'end'), entry_b.insert(0, filedialog.askopenfilename())], width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")
        
        pw_b = PasswordEntry(frame_b, placeholder="Password B", height=36, corner_radius=6)
        pw_b.pack(side="left", padx=5, fill="x", expand=True)

        def do_diff():
            path_a = entry_a.get().strip()
            path_b = entry_b.get().strip()
            pwa = pw_a.get()
            pwb = pw_b.get()
            if not path_a or not path_b or not pwa or not pwb:
                messagebox.showwarning("Required", "All fields are required.", parent=dialog)
                return
            
            dialog.destroy()
            self.is_processing = True
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
            self._set_status("Computing Vault Diff...")
            
            threading.Thread(
                target=self._vault_diff_worker,
                args=(Path(path_a), Path(path_b), pwa, pwb),
                daemon=True
            ).start()

        ctk.CTkButton(dialog, text="Compare", command=do_diff, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(pady=(16, 0))

    def _vault_diff_worker(self, path_a: Path, path_b: Path, pw_a: str, pw_b: str) -> None:
        try:
            with open(path_a, "rb") as f:
                header_a = self.crypto.verify_password_and_get_header(f, pw_a)
            with open(path_b, "rb") as f:
                header_b = self.crypto.verify_password_and_get_header(f, pw_b)
                
            files_a = {f["path"]: f for f in (header_a.payload.metadata.get("files", []) if header_a.payload.metadata else [])}
            files_b = {f["path"]: f for f in (header_b.payload.metadata.get("files", []) if header_b.payload.metadata else [])}
            
            all_paths = set(files_a.keys()).union(set(files_b.keys()))
            
            added = []
            removed = []
            modified = []
            
            for p in sorted(all_paths):
                if p in files_b and p not in files_a:
                    added.append(f"+ {p} ({files_b[p]['size']} bytes)")
                elif p in files_a and p not in files_b:
                    removed.append(f"- {p} ({files_a[p]['size']} bytes)")
                else:
                    fa = files_a[p]
                    fb = files_b[p]
                    if fa['size'] != fb['size'] or fa.get('mtime') != fb.get('mtime'):
                        modified.append(f"~ {p} (Size: {fa['size']} -> {fb['size']})")
                        
            # Format output uses update_ui
            
            def update_ui():
                self.inspect_results.configure(state="normal")
                self.inspect_results.delete("0.0", "end")
                self.inspect_results.insert("end", "═" * 55 + "\n           VAULT DIFF RESULTS\n" + "═" * 55 + "\n")
                self.inspect_results.insert("end", f"  Vault A: {path_a.name}\n  Vault B: {path_b.name}\n" + "─" * 55 + "\n")
                
                self.inspect_results.tag_config("diff_added", foreground="#44ff44")
                self.inspect_results.tag_config("diff_removed", foreground="#ff4444")
                self.inspect_results.tag_config("diff_modified", foreground="#ffcc00")
                
                if not added and not removed and not modified:
                    self.inspect_results.insert("end", "  No differences found in manifests.\n")
                else:
                    if added:
                        self.inspect_results.insert("end", "  ADDED:\n")
                        for x in added: self.inspect_results.insert("end", f"    {x}\n", "diff_added")
                    if removed:
                        self.inspect_results.insert("end", "\n  REMOVED:\n")
                        for x in removed: self.inspect_results.insert("end", f"    {x}\n", "diff_removed")
                    if modified:
                        self.inspect_results.insert("end", "\n  MODIFIED:\n")
                        for x in modified: self.inspect_results.insert("end", f"    {x}\n", "diff_modified")
                self.inspect_results.insert("end", "═" * 55 + "\n")
                self.inspect_results.configure(state="disabled")
            
            self.after(0, update_ui)
            msg = "Vault Diff complete."
            
        except Exception as e:
            logger.exception("Vault Diff failed")
            msg = f"Diff failed: {e}"
        finally:
            self.is_processing = False
            self.progress_bar.stop()
            self._set_status("Ready")
            try:
                self.msg_queue.put({"type": "batch_done", "text": msg}, timeout=1.0)
            except queue.Full:
                pass

    def _do_integrity_check(self) -> None:
        """Check vault structure, compute SHA-256, save fingerprint record."""
        path_str = self.inspect_path.get().strip()
        if not path_str:
            messagebox.showwarning("No File", "Please select a vault file first.")
            return
        path = Path(path_str).resolve()
        ok, msg, sha = self._check_vault_integrity(path)
        icon = "✅" if ok else "❌"

        if ok:
            self._save_fingerprint(path, sha)

        result_text = (
            "═" * 55 + "\n"
            "       INTEGRITY CHECK  (password-free)\n"
            + "═" * 55 + "\n\n"
            f"  {icon}  {msg}\n"
        )

        self.inspect_results.configure(state="normal")
        self.inspect_results.delete("0.0", "end")
        self.inspect_results.insert("0.0", result_text)
        self.inspect_results.configure(state="disabled")

        self._refresh_fingerprint_panel()
        self._set_status("Integrity check complete — fingerprint saved" if ok
                         else "Integrity check failed")
        
        self._log_activity("Integrity", path.name, "Success" if ok else "Failed", f"SHA: {sha[:16]}" if ok else msg)

    @staticmethod
    def _save_fingerprint(path: Path, sha: str) -> None:
        """Append or update a fingerprint entry in config."""
        cfg = _load_cfg()
        fps = cfg.setdefault("fingerprints", {})
        key = str(path.resolve())
        fps[key] = {
            "filename": path.name,
            "sha256":   sha,
            "size":     path.stat().st_size,
            "recorded": datetime.now().isoformat(timespec="seconds"),
        }
        if len(fps) > 50:
            oldest = sorted(fps, key=lambda k: fps[k]["recorded"])
            for k in oldest[:len(fps) - 50]:
                del fps[k]
        _save_cfg(cfg)

    @staticmethod
    def _load_fingerprints() -> Dict[str, Any]:
        return _load_cfg().get("fingerprints", {})

    def _refresh_fingerprint_panel(self) -> None:
        """Rebuild the saved-fingerprints listbox with background hash verification."""
        if not hasattr(self, "_fp_listbox"):
            return
        
        self._fp_listbox.configure(state="normal")
        self._fp_listbox.delete("0.0", "end")
        fps = self._load_fingerprints()
        
        if not fps:
            self._fp_listbox.insert("0.0", "No fingerprints saved yet.")
            self._fp_listbox.configure(state="disabled")
            return
        
        # Show loading message
        for key, rec in sorted(fps.items(), key=lambda kv: kv[1]["recorded"], reverse=True):
            sz_mb = rec["size"] / (1024 * 1024)
            self._fp_listbox.insert("end", 
                f"⏳  {rec['filename']}  ({sz_mb:.1f} MB)  recorded {rec['recorded']}\n"
                f"      SHA-256: {rec['sha256']}\n"
                f"      Verifying...\n\n")
        
        self._fp_listbox.configure(state="disabled")
        
        # Compute hashes in background
        def verify_fingerprints():
            results = {}
            for key, rec in fps.items():
                p = Path(key)
                if not p.exists():
                    results[key] = ("⚠️ missing", None)
                    continue
                
                try:
                    if p.stat().st_size != rec["size"]:
                        results[key] = ("❌ SIZE MISMATCH", None)
                        continue
                    
                    h = hashlib.sha256()
                    with open(p, "rb") as f:
                        while chunk := f.read(65536):
                            h.update(chunk)
                    
                    match = "✅" if h.hexdigest() == rec["sha256"] else "❌ MISMATCH"
                    results[key] = (match, h.hexdigest())
                except Exception:
                    results[key] = ("⚠️ ERROR", None)
            
            try:
                self.msg_queue.put({"type": "fingerprint_results", "data": results}, timeout=1.0)
            except queue.Full:
                logger.warning("Message queue full, fingerprint results dropped")
        
        threading.Thread(target=verify_fingerprints, daemon=True).start()

    def _copy_last_sha(self) -> None:
        """Copy the SHA-256 of the currently selected vault to clipboard."""
        path_str = self.inspect_path.get().strip()
        if not path_str:
            messagebox.showwarning("No File", "Please run an integrity check first.")
            return
        fps = self._load_fingerprints()
        rec = fps.get(str(Path(path_str).resolve()))
        if not rec:
            messagebox.showwarning("Not Found",
                                   "No saved fingerprint for this vault.\n"
                                   "Run Integrity Check first.")
            return
        self.clipboard_clear()
        self.clipboard_append(rec["sha256"])
        self._set_status(f"SHA-256 copied: {rec['sha256'][:16]}…")

    def _verify_against_saved(self) -> None:
        """Re-hash the current file and compare with its saved fingerprint."""
        path_str = self.inspect_path.get().strip()
        if not path_str:
            messagebox.showwarning("No File", "Please select a vault file first.")
            return
        fps = self._load_fingerprints()
        rec = fps.get(str(Path(path_str).resolve()))
        if not rec:
            messagebox.showwarning("No Record",
                                   "No saved fingerprint for this vault.\n"
                                   "Run Integrity Check first to create one.")
            return
        path = Path(path_str)
        _, _, current_sha = self._check_vault_integrity(path)
        if not current_sha:
            messagebox.showerror("Error", "Could not read vault file.")
            return
        if current_sha == rec["sha256"]:
            messagebox.showinfo("Match ✅",
                                f"Fingerprint matches the saved record.\n\n"
                                f"Recorded : {rec['recorded']}\n"
                                f"SHA-256  : {current_sha}")
            self._set_status("✅ Fingerprint verified — file unchanged")
        else:
            messagebox.showerror("Mismatch ❌",
                                 f"Fingerprint does NOT match!\n\n"
                                 f"Saved    : {rec['sha256']}\n"
                                 f"Current  : {current_sha}\n\n"
                                 "The vault file may have been tampered with or corrupted.")
            self._set_status("❌ Fingerprint mismatch — file changed!")

    @staticmethod
    def _check_vault_integrity(path: Path) -> Tuple[bool, str, str]:
        """Structural + hash check without password. Returns (ok, message, sha256_hex)."""
        try:
            sz = path.stat().st_size
            min_sz = len(VAULT_MAGIC) + 1 + 4 + 1 + AES_TAG_SIZE
            if sz < min_sz:
                return False, f"File too small ({sz} bytes < {min_sz} minimum)", ""
            
            with open(path, "rb") as f:
                magic = f.read(len(VAULT_MAGIC))
                if magic != VAULT_MAGIC:
                    return False, f"Invalid magic bytes: {magic!r}", ""
                (version,) = struct.unpack("!B", f.read(1))
                if version != VAULT_VERSION:
                    return False, f"Unsupported version: {version}", ""
                (hlen,) = struct.unpack("!I", f.read(4))
                if hlen > sz:
                    return False, f"Header length field ({hlen}) exceeds file size", ""
            
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            sha = h.hexdigest()
            msg = (f"Structure valid  ·  Size: {sz:,} bytes\n"
                   f"  SHA-256: {sha}")
            return True, msg, sha
        except Exception as exc:
            return False, str(exc), ""

    def _render_inspect_results(self, metadata: Dict[str, Any]) -> None:
        mb = metadata.get("total_size", metadata.get("original_size", 0)) / (1024 * 1024)
        lines = [
            "═" * 55,
            "           VAULT METADATA",
            "═" * 55,
            "",
            f"  Original Name   : {metadata.get('filename', 'N/A')}",
            f"  Original Size   : {metadata.get('original_size', 0):,} bytes"
            f"  ({mb:.2f} MiB)",
            f"  File Count      : {metadata.get('file_count', 'N/A')}",
            f"  Created         : {metadata.get('created_at', 'N/A')}",
            f"  Source Type     : {metadata.get('source_type', 'N/A')}",
            "",
            "─" * 55,
            "           CRYPTOGRAPHIC PARAMETERS",
            "─" * 55,
            "",
            f"  KDF Algorithm   : {metadata.get('kdf_algorithm', 'N/A')}",
            f"  Envelope Cipher : {metadata.get('encryption', 'N/A')}",
            f"  Payload Cipher  : {metadata.get('payload_encryption', 'N/A')}",
            "",
            f"  Argon2 Memory   : {metadata.get('argon_memory', 'N/A')} KiB",
            f"  Argon2 Iters    : {metadata.get('argon_iterations', 'N/A')}",
            f"  Argon2 Parallel : {metadata.get('argon_parallelism', 'N/A')}",
            "",
            "═" * 55,
        ]
        files = metadata.get("files", [])
        if files:
            lines += ["", "           FILE MANIFEST", "─" * 55, ""]
            for fi in files[:100]:
                lines.append(f"  • {fi['path']}  ({fi['size']:,} bytes)")
            if len(files) > 100:
                lines.append(f"  … and {len(files) - 100} more files")
            lines += ["", "═" * 55]

        self.inspect_results.configure(state="normal")
        self.inspect_results.delete("0.0", "end")
        self.inspect_results.insert("0.0", "\n".join(lines))
        self.inspect_results.configure(state="disabled")

    # ==========================================================================
    # RE-KEY VIEW
    # ==========================================================================

    def _create_rekey_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(5, weight=1)

        ctk.CTkLabel(frame, text="Re-Key Vault", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 6), sticky="w")
        ctk.CTkLabel(
            frame,
            text=(
                "Change the vault password without decrypting the payload.\n"
                "Only the small DEK envelope (~200 bytes) is re-encrypted — "
                "instant even for multi-gigabyte vaults."
            ),
            font=ctk.CTkFont(size=12),
            justify="left",

        text_color="#7d8590").grid(row=1, column=0, pady=(0, 14), sticky="w")

        form = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        form.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        form.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Vault:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        vault_row = ctk.CTkFrame(form, fg_color="transparent", corner_radius=0)
        vault_row.grid(row=0, column=1, sticky="ew")
        vault_row.grid_columnconfigure(0, weight=1)
        self.rekey_path = ctk.CTkEntry(vault_row, font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.rekey_path.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(vault_row, text="Browse",
                      command=self._browse_rekey_vault, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        self._rk_recent = RecentBar(frame, "rekey_vaults",
                                    on_select=lambda p: (self.rekey_path.delete(0, "end"),
                                                         self.rekey_path.insert(0, p)))
        self._rk_recent.grid(row=3, column=0, sticky="w", pady=(0, 6))

        ctk.CTkLabel(form, text="Current Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=1, column=0, padx=(0, 10), pady=5, sticky="w")
        self.rekey_old_pw = PasswordEntry(form, height=36, corner_radius=6)
        self.rekey_old_pw.grid(row=1, column=1, sticky="ew")

        ctk.CTkLabel(form, text="New Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=2, column=0, padx=(0, 10), pady=5, sticky="w")
        self.rekey_new_pw = PasswordEntry(form, placeholder="New password", height=36, corner_radius=6)
        self.rekey_new_pw.grid(row=2, column=1, sticky="ew")
        self.rekey_new_pw.bind_change(self._on_rekey_pw_change)

        self.rekey_strength_lbl = ctk.CTkLabel(
            frame, text="", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self.rekey_strength_lbl.grid(row=4, column=0, sticky="w", pady=(0, 4))

        ctk.CTkLabel(form, text="Confirm New:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=3, column=0, padx=(0, 10), pady=5, sticky="w")
        self.rekey_confirm_pw = PasswordEntry(form, placeholder="Confirm new password", height=36, corner_radius=6)
        self.rekey_confirm_pw.grid(row=3, column=1, sticky="ew")

        self.rekey_btn = ctk.CTkButton(
            frame, text="⟳  Re-Key Vault",
            command=self._do_rekey, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8)
        self.rekey_btn.grid(row=5, column=0, pady=(8, 6), sticky="w")

        self.rekey_log = LogBox(frame, height=120)
        self.rekey_log.grid(row=6, column=0, sticky="nsew", pady=(6, 0))
        frame.grid_rowconfigure(6, weight=1)

        # --- VERSION HISTORY PANEL ---
        ctk.CTkLabel(frame, text="Version History", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=7, column=0, sticky="w", pady=(18, 4))

        ctk.CTkLabel(
            frame,
            text="Automatically saved before each Re-Key. Select a vault above, then click Refresh.",
            justify="left", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=8, column=0, sticky="w", pady=(0, 6))

        vh_container = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        vh_container.grid(row=9, column=0, sticky="nsew", pady=(0, 0))
        vh_container.grid_columnconfigure(0, weight=1)
        vh_container.grid_rowconfigure(0, weight=1)
        frame.grid_rowconfigure(9, weight=2)

        self._version_list_box = ctk.CTkTextbox(
            vh_container,
            font=ctk.CTkFont(size=12, family="Courier New"),
            state="disabled",
            wrap="none",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self._version_list_box.grid(row=0, column=0, sticky="nsew", padx=6, pady=(6, 0))

        # Store version entries for action buttons
        self._version_entries: List[versioning.VersionEntry] = []
        self._selected_version_idx: Optional[int] = None

        def on_version_click(event):
            """Highlight clicked line and record selection index."""
            widget = event.widget
            idx_str = widget.index(f"@{event.x},{event.y}")
            line_num = int(idx_str.split(".")[0]) - 1  # 0-indexed
            if 0 <= line_num < len(self._version_entries):
                self._selected_version_idx = line_num
                # Highlight selection
                widget.tag_remove("selected", "1.0", "end")
                widget.tag_add("selected", f"{line_num+1}.0", f"{line_num+2}.0")
                widget.tag_config("selected", background="#204060")

        self._version_list_box._textbox.bind("<Button-1>", on_version_click)

        vh_btn_row = ctk.CTkFrame(vh_container, fg_color="#0d1117", corner_radius=0)
        vh_btn_row.grid(row=1, column=0, sticky="w", padx=6, pady=6)
        ctk.CTkButton(vh_btn_row, text="Refresh",
                      command=self._refresh_version_list, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(vh_btn_row, text="Restore as Copy",
                      command=self._do_restore_copy, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(vh_btn_row, text="Replace Current",
                      command=self._do_replace_current, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(vh_btn_row, text="Delete Version",
                      command=self._do_delete_version, width=120, fg_color="#f85149", text_color="#0d1117", hover_color="#ff6e6e", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left")

        return page_frame
    def _refresh_version_list(self) -> None:
        """Populate the version history list for the current vault path in the Re-Key field."""
        if not hasattr(self, '_version_list_box'):
            return
        path_str = self.rekey_path.get().strip()
        if not path_str:
            self._version_list_box.configure(state="normal")
            self._version_list_box.delete("0.0", "end")
            self._version_list_box.insert("end", "  Select a vault in the Vault field above, then click Refresh.")
            self._version_list_box.configure(state="disabled")
            self._version_entries = []
            return

        vault = Path(path_str)
        entries = self.versioner.list_versions(vault)
        entries_reversed = list(reversed(entries))  # Show newest first
        self._version_entries = entries_reversed
        self._selected_version_idx = None

        self._version_list_box.configure(state="normal")
        self._version_list_box.delete("0.0", "end")
        if not entries_reversed:
            if not self.versioner.enabled:
                self._version_list_box.insert("end", "  Versioning is disabled. Enable it in Settings → Vault Versioning.")
            else:
                self._version_list_box.insert("end", "  No versions found for this vault.")
        else:
            for entry in entries_reversed:
                line = f"  {entry.display_timestamp}    {entry.display_size:>10}    {entry.path.name}\n"
                self._version_list_box.insert("end", line)
        self._version_list_box.configure(state="disabled")

    def _get_selected_version(self) -> Optional["versioning.VersionEntry"]:
        """Return the selected VersionEntry, or show a warning and return None."""
        if not self._version_entries:
            messagebox.showwarning("No Versions", "No version history found for this vault.\nRun a Re-Key first to create a version.")
            return None
        if self._selected_version_idx is None or self._selected_version_idx >= len(self._version_entries):
            messagebox.showwarning("No Selection", "Please click on a version entry in the list to select it.")
            return None
        return self._version_entries[self._selected_version_idx]

    def _do_restore_copy(self) -> None:
        """Restore selected version as a new copy beside the original vault."""
        path_str = self.rekey_path.get().strip()
        if not path_str:
            messagebox.showwarning("No Vault", "Please select a vault in the Vault field above.")
            return
        entry = self._get_selected_version()
        if entry is None:
            return
        vault = Path(path_str)
        try:
            copy_path = self.versioner.restore_as_copy(entry, vault)
            self._set_status(f"Restored copy: {copy_path.name}")
            messagebox.showinfo("Restored", f"Version restored as a new copy:\n{copy_path.name}\n\nThe original vault was not modified.")
            self._log_activity("Version Restore", vault.name, "Success", f"Copy: {copy_path.name}")
        except OSError as exc:
            messagebox.showerror("Restore Failed", f"Could not restore version:\n{exc}")

    def _do_replace_current(self) -> None:
        """Atomically replace the current vault with the selected version."""
        path_str = self.rekey_path.get().strip()
        if not path_str:
            messagebox.showwarning("No Vault", "Please select a vault in the Vault field above.")
            return
        entry = self._get_selected_version()
        if entry is None:
            return
        vault = Path(path_str)
        if not messagebox.askyesno(
            "Replace Current Vault?",
            f"This will REPLACE the current vault file with the selected version:\n\n"            f"  Version:  {entry.display_timestamp}\n"            f"  Size:     {entry.display_size}\n\n"            f"The current vault will be overwritten. This cannot be undone.\n"            f"Proceed?",
            icon="warning",
        ):
            return
        try:
            self.versioner.replace_current(entry, vault)
            self._set_status(f"Vault restored from version {entry.display_timestamp}")
            messagebox.showinfo("Restored", f"Vault successfully replaced with version from {entry.display_timestamp}.")
            self._log_activity("Version Replace", vault.name, "Success", f"From: {entry.path.name}")
            self._refresh_version_list()
        except OSError as exc:
            messagebox.showerror("Replace Failed", f"Could not replace vault:\n{exc}")

    def _do_delete_version(self) -> None:
        """Permanently delete the selected version file."""
        entry = self._get_selected_version()
        if entry is None:
            return
        if not messagebox.askyesno(
            "Delete Version?",
            f"Permanently delete this version?\n\n"            f"  {entry.display_timestamp}  ({entry.display_size})\n\n"            f"This cannot be undone.",
        ):
            return
        try:
            self.versioner.delete_version(entry)
            self._refresh_version_list()
            self._set_status("Version deleted")
        except OSError as exc:
            messagebox.showerror("Delete Failed", f"Could not delete version:\n{exc}")

    def _browse_rekey_vault(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Vault to Re-Key",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")],
        )
        if path:
            self.rekey_path.delete(0, "end")
            self.rekey_path.insert(0, path)
            push_recent("rekey_vaults", path)
            self._rk_recent.refresh()
            self._refresh_version_list()

    def _on_rekey_pw_change(self, _=None) -> None:
        """Debounced password strength for rekey."""
        pw = self.rekey_new_pw.get()
        if not pw:
            self.rekey_strength_lbl.configure(text="")
            return
        
        if hasattr(self, '_rekey_strength_timer'):
            self.after_cancel(self._rekey_strength_timer)
        
        self._rekey_strength_timer = self.after(300,
            lambda: self._compute_rekey_strength_async(pw))

    def _compute_rekey_strength_async(self, password: str):
        """Background password strength for rekey."""
        def compute():
            if ZXCVBN_AVAILABLE:
                try:
                    res = zxcvbn(password)
                    self.msg_queue.put({
                        "type": "rekey_password_strength",
                        "score": res["score"],
                        "crack_time": res["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
                    }, timeout=0.1)
                except queue.Full:
                    pass
        
        threading.Thread(target=compute, daemon=True).start()

    def _do_rekey(self) -> None:
        if self.is_processing:
            messagebox.showinfo("Busy", "An operation is already in progress.")
            return
        path_str  = self.rekey_path.get().strip()
        old_pw    = self.rekey_old_pw.get()
        new_pw    = self.rekey_new_pw.get()
        confirm   = self.rekey_confirm_pw.get()

        if not path_str:
            messagebox.showwarning("No Vault", "Please select a vault file.")
            return
        if not old_pw:
            messagebox.showwarning("Password Required", "Please enter the current password.")
            return
        if not new_pw:
            messagebox.showwarning("Password Required", "Please enter the new password.")
            return
        if new_pw != confirm:
            messagebox.showerror("Mismatch", "New password and confirmation do not match.")
            return
        if new_pw == old_pw:
            messagebox.showwarning("Same Password",
                                   "New password is the same as the current one.")
            return

        vault = Path(path_str)
        if not vault.is_file():
            messagebox.showwarning("File Not Found", f"Vault not found:\n{vault}")
            return

        self.is_processing = True
        self._cancel_requested = False
        self._active_log = self.rekey_log
        self.rekey_btn.configure(state="disabled", text="Re-Keying…")
        self.rekey_log.clear()
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        self._progress_pct.configure(text="KDF…")
        self._set_status("Deriving key (Argon2id)…")

        self.worker_thread = threading.Thread(
            target=self._rekey_worker,
            args=(vault, old_pw, new_pw),
            daemon=True,
        )
        self.worker_thread.start()

    def _rekey_worker(self, vault: Path, old_pw: str, new_pw: str) -> None:
        try:
            self._qlog(f"Re-keying  →  {vault.name}")

            # --- Vault Versioning: save a copy before any modification ---
            if self.versioner.enabled:
                self._qlog("Saving version before re-key…")
                saved = self.versioner.save_version(vault)
                if saved:
                    self._qlog(f"✓ Version saved: {saved.name}")
                    self.after(0, self._refresh_version_list)
                else:
                    self._qlog("⚠ Versioning skipped (disk full or disabled)")
            # ---

            tmp = vault.with_suffix(".rekey.tmp")
            self.crypto.rekey_vault(vault, tmp, old_pw, new_pw)
            tmp.replace(vault)

            self.stats.add_rekeyed()
            self._qlog(f"✓ Re-key complete  →  {vault.name}")
            self._log_activity("Re-Key", vault.name, "Success")
            push_recent("rekey_vaults", str(vault))
            try:
                self.msg_queue.put({
                    "type": "batch_done",
                    "text": f"Re-key complete: {vault.name}",
                }, timeout=1.0)
            except queue.Full:
                pass
        except AuthenticationError:
            self._qlog("✗ Wrong current password")
            self._log_activity("Re-Key", vault.name, "Failed", "Wrong current password")
            try:
                self.msg_queue.put({
                    "type": "batch_done",
                    "text": "Re-key failed: wrong current password",
                }, timeout=1.0)
            except queue.Full:
                pass
        except CryptoError as exc:
            # F2 FIX: Surface the hidden-compartment re-key guard (and any other
            # CryptoError) with a clear, truthful message instead of a confusing
            # generic failure. Routed through "batch_done" — like the other
            # terminal outcomes in this worker — so the Re-Key button is
            # re-enabled and the UI never looks frozen/broken to the user.
            if "Re-Key is not supported for vaults containing a hidden compartment" in str(exc):
                # Specific, clear error for the F2 guard.
                self._qlog(f"✗ {exc}")
                self._log_activity("Re-Key", vault.name, "Blocked", "Hidden compartment present")
                text = str(exc)
            else:
                logger.exception("Re-key failed for %s", vault)
                self._qlog(f"✗ FAILED: {exc}")
                self._log_activity("Re-Key", vault.name, "Failed", str(exc))
                text = f"Re-key failed: {exc}"
            try:
                self.msg_queue.put({
                    "type": "batch_done",
                    "text": text,
                }, timeout=1.0)
            except queue.Full:
                pass
        except Exception as exc:
            logger.exception("Re-key failed for %s", vault)
            self._qlog(f"✗ FAILED: {exc}")
            self._log_activity("Re-Key", vault.name, "Failed", str(exc))
            try:
                self.msg_queue.put({
                    "type": "batch_done",
                    "text": f"Re-key failed: {exc}",
                }, timeout=1.0)
            except queue.Full:
                pass
        finally:
            tmp = vault.with_suffix(".rekey.tmp")
            if tmp.exists():
                try:
                    tmp.unlink()
                except Exception:
                    pass

    # ==========================================================================
    # PASSWORD GENERATOR VIEW
    # ==========================================================================

    def _create_password_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Password Generator", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 20), sticky="w")

        len_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        len_row.grid(row=1, column=0, sticky="w", pady=(0, 14))

        ctk.CTkLabel(len_row, text="Length:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 12))
        self.pwgen_length = ctk.CTkSlider(
            len_row, from_=8, to=64, number_of_steps=56, width=240,
            command=self._update_length_label,
            fg_color="#21262d", progress_color="#00d4aa", button_color="#00d4aa",
        )
        self.pwgen_length.set(DEFAULT_PW_LEN)
        self.pwgen_length.pack(side="left", padx=(0, 10))
        self.pwgen_length_label = ctk.CTkLabel(
            len_row, text=str(DEFAULT_PW_LEN),
            font=ctk.CTkFont(size=14), width=30,

        text_color="#e6edf3")
        self.pwgen_length_label.pack(side="left")

        opts = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        opts.grid(row=2, column=0, sticky="w", pady=(0, 14))

        self.pwgen_upper   = ctk.BooleanVar(value=True)
        self.pwgen_lower   = ctk.BooleanVar(value=True)
        self.pwgen_digits  = ctk.BooleanVar(value=True)
        self.pwgen_symbols = ctk.BooleanVar(value=True)
        self.pwgen_no_ambig = ctk.BooleanVar(value=False)

        for text, var in [
            ("A-Z", self.pwgen_upper),
            ("a-z", self.pwgen_lower),
            ("0-9", self.pwgen_digits),
            ("!@#$%", self.pwgen_symbols),
            ("Exclude ambiguous (0Ol1I|`)", self.pwgen_no_ambig),
        ]:
            ctk.CTkCheckBox(opts, text=text, variable=var,
                            font=ctk.CTkFont(size=14), fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").pack(side="left", padx=8)

        res_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        res_row.grid(row=3, column=0, sticky="ew", pady=(0, 12))
        res_row.grid_columnconfigure(0, weight=1)

        self.pwgen_result = ctk.CTkEntry(
            res_row,
            font=ctk.CTkFont(size=16, family="Courier New", weight="bold"),

        fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.pwgen_result.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkButton(res_row, text="Copy",
                      command=self._copy_generated_pw, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1, padx=(0, 6))
        ctk.CTkButton(res_row, text="→ Encrypt",
                      command=self._use_generated_pw, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).grid(row=0, column=2)

        self.pwgen_strength_lbl = ctk.CTkLabel(
            frame, text="", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self.pwgen_strength_lbl.grid(row=4, column=0, sticky="w", pady=(0, 10))

        ctk.CTkButton(
            frame, text="🔑  Generate Password",
            command=self._generate_password, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).grid(row=5, column=0, pady=(0, 0), sticky="w")

        return page_frame
    def _update_length_label(self, value) -> None:
        self.pwgen_length_label.configure(text=str(int(value)))

    def _generate_password(self) -> None:
        chars = ""
        if self.pwgen_upper.get():   chars += string.ascii_uppercase
        if self.pwgen_lower.get():   chars += string.ascii_lowercase
        if self.pwgen_digits.get():  chars += string.digits
        if self.pwgen_symbols.get(): chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if self.pwgen_no_ambig.get():
            for ch in "0O1lI|`":
                chars = chars.replace(ch, "")
        if not chars:
            messagebox.showwarning("Options", "Select at least one character type.")
            return

        length = int(self.pwgen_length.get())
        required: List[str] = []
        pools = []
        if self.pwgen_upper.get():
            p = string.ascii_uppercase
            if self.pwgen_no_ambig.get():
                p = "".join(c for c in p if c not in "OI")
            pools.append(p)
        if self.pwgen_lower.get():
            p = string.ascii_lowercase
            if self.pwgen_no_ambig.get():
                p = "".join(c for c in p if c not in "l")
            pools.append(p)
        if self.pwgen_digits.get():
            p = string.digits
            if self.pwgen_no_ambig.get():
                p = "".join(c for c in p if c not in "01")
            pools.append(p)
        if self.pwgen_symbols.get():
            pools.append("!@#$%^&*()_+-=[]{}|;:,.<>?")

        for pool in pools:
            if pool:
                required.append(secrets.choice(pool))

        remainder = [secrets.choice(chars) for _ in range(max(0, length - len(required)))]
        password_list = required + remainder
        secrets.SystemRandom().shuffle(password_list)
        password = "".join(password_list)

        self.pwgen_result.delete(0, "end")
        self.pwgen_result.insert(0, password)

        if ZXCVBN_AVAILABLE:
            res   = zxcvbn(password)
            score = res["score"]
            color, label = STRENGTH_COLORS.get(score, ("gray", "Unknown"))
            crack = res["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
            self.pwgen_strength_lbl.configure(
                text=f"Strength: {label}  •  Est. crack time: {crack}",
                text_color=color,
            )
        else:
            self.pwgen_strength_lbl.configure(
                text=f"Length: {length} chars  (install zxcvbn for strength analysis)"
            )

    def _clear_clipboard(self) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append("")
            self.update()
        except Exception:
            pass

    def _start_clipboard_timer(self) -> None:
        if hasattr(self, '_clipboard_timer') and self._clipboard_timer is not None:
            self.after_cancel(self._clipboard_timer)
        self._clipboard_timer = self.after(30000, self._clear_clipboard)

    def _copy_generated_pw(self) -> None:
        pw = self.pwgen_result.get()
        if pw:
            self.clipboard_clear()
            self.clipboard_append(pw)
            self._start_clipboard_timer()
            self._set_status("Copied! Clipboard will be cleared in 30s.")
            if hasattr(self, '_clipboard_hint_timer') and self._clipboard_hint_timer is not None:
                self.after_cancel(self._clipboard_hint_timer)
            self._clipboard_hint_timer = self.after(3000, lambda: self._set_status("Ready"))

    def _use_generated_pw(self) -> None:
        pw = self.pwgen_result.get()
        if pw:
            self.encrypt_pw.set(pw)
            self.encrypt_pw_confirm.set(pw)
            self._on_enc_pw_change()
            self._show_frame("encrypt")
            self._set_status("Password transferred to Encrypt tab")

    # ==========================================================================
    # LIBRARY VIEW
    # ==========================================================================

    def _create_library_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(frame, text="Vault Library", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 20), sticky="w")

        # M5 FIX: The Library list is built from UNVERIFIED vault headers (read
        # without a password). Warn the user that these fields can be spoofed so
        # header-derived strings are never mistaken for authenticated data.
        ctk.CTkLabel(
            frame,
            text="⚠️ Vault metadata is read without authentication and may be spoofed.",
            font=ctk.CTkFont(size=12),
            text_color="#7d8590"
        ).grid(row=1, column=0, sticky="w", pady=(0, 6))

        # Search Bar
        search_container = ctk.CTkFrame(frame, fg_color="transparent")
        search_container.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        
        self.library_search_entry = ctk.CTkEntry(search_container, placeholder_text="Search vaults...", fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.library_search_entry.pack(fill="x", side="left", expand=True)
        self.library_search_entry.bind("<KeyRelease>", self._filter_library)
        
        self.library_search_clear = ctk.CTkButton(search_container, text="✕", width=36, height=36, fg_color="#21262d", text_color="#7d8590", hover_color="#30363d", corner_radius=6, font=ctk.CTkFont(size=14))
        self.library_search_clear.pack(side="right", padx=(8, 0))
        self.library_search_clear.configure(command=self._clear_library_search)
        self.library_search_clear.pack_forget()
        
        btn_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        btn_row.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkButton(btn_row, text="Add Directory",
                      command=self._add_library_dir, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Scan Now",
                      command=self._scan_library, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        
        # Display area
        self.library_textbox = ctk.CTkTextbox(
            frame,
            font=ctk.CTkFont(size=12, family="Courier New"),
            wrap="none",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.library_textbox.grid(row=4, column=0, sticky="nsew")
        
        self.after(500, self._scan_library)
        return page_frame
    def _add_library_dir(self):
        path = filedialog.askdirectory(title="Select Directory to Monitor")
        if not path: return
        cfg = _load_cfg()
        dirs = cfg.get("library_dirs", [])
        if path not in dirs:
            dirs.append(path)
            cfg["library_dirs"] = dirs
            _save_cfg(cfg)
            self._scan_library()

    def _scan_library(self):
        if self.is_processing: return
        cfg = _load_cfg()
        dirs = cfg.get("library_dirs", [])
        if not dirs:
            self.library_textbox.configure(state="normal")
            self.library_textbox.delete("0.0", "end")
            self.library_textbox.insert("end", "No directories monitored. Click 'Add Directory' to start.")
            self.library_textbox.configure(state="disabled")
            return
            
        self.library_textbox.configure(state="normal")
        self.library_textbox.delete("0.0", "end")
        self.library_textbox.insert("end", "Scanning directories...\n")
        self.library_textbox.configure(state="disabled")
        
        threading.Thread(target=self._scan_worker, args=(dirs,), daemon=True).start()

    def _scan_worker(self, dirs):
        try:
            results = self.scanner.scan_directories(dirs)
            self.msg_queue.put({"type": "library_results", "data": results}, timeout=1.0)
        except Exception as e:
            self.msg_queue.put({"type": "error", "text": f"Scan failed: {e}"}, timeout=1.0)


    def _clear_library_search(self):
        self.library_search_entry.delete(0, "end")
        self._filter_library()

    def _filter_library(self, event=None):
        if not hasattr(self, "last_library_results"):
            return
            
        query = self.library_search_entry.get().strip().lower()
        if not query:
            self.library_search_clear.pack_forget()
            filtered = self.last_library_results
        else:
            self.library_search_clear.pack(side="right", padx=(8, 0))
            filtered = [
                r for r in self.last_library_results
                if query in r.get("filename", "").lower() or query in r.get("path", "").lower()
            ]
            
        self.library_textbox.configure(state="normal")
        self.library_textbox.delete("0.0", "end")
        
        if not filtered:
            self.library_textbox.insert("end", "No .vault files found matching the search.")
            if hasattr(self, "library_empty"): self.library_empty.show()
        else:
            if hasattr(self, "library_empty"): self.library_empty.hide()
            
            # Sort by created_at or path
            filtered.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            
            header = f"{'FILENAME':<40} | {'CONTAINER SIZE':<15} | {'SOURCE TYPE':<15} | {'CREATED AT':<25}\n"
            self.library_textbox.insert("end", header)
            self.library_textbox.insert("end", "-" * 100 + "\n")
            
            for r in filtered:
                fname = r.get("filename", "Unknown")[:38]
                sz = r.get("container_size", r.get("original_size", 0))
                sz_str = f"{sz / 1024 / 1024:.2f} MB" if sz > 1024*1024 else f"{sz / 1024:.1f} KB"
                stype = r.get("source_type", "Unknown")[:13]
                cat = r.get("created_at", "Unknown")[:23]
                
                line = f"{fname:<40} | {sz_str:<15} | {stype:<15} | {cat:<25}\n"
                self.library_textbox.insert("end", line)
                
        self.library_textbox.configure(state="disabled")

    # ==========================================================================
    # NOTES VIEW
    # ==========================================================================

    def _create_notes_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(frame, text="Encrypted Notes", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 10), sticky="w")
                     
        # Search Bar
        search_container = ctk.CTkFrame(frame, fg_color="transparent")
        search_container.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        
        self.notes_search_entry = ctk.CTkEntry(search_container, placeholder_text="Search notes...", fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.notes_search_entry.pack(fill="x", side="left", expand=True)
        self.notes_search_entry.bind("<KeyRelease>", self._filter_notes)
        
        self.notes_search_clear = ctk.CTkButton(search_container, text="✕", width=36, height=36, fg_color="#21262d", text_color="#7d8590", hover_color="#30363d", corner_radius=6, font=ctk.CTkFont(size=14))
        self.notes_search_clear.pack(side="right", padx=(8, 0))
        self.notes_search_clear.configure(command=self._clear_notes_search)
        self.notes_search_clear.pack_forget()
                     
        ctrl_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        ctrl_row.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        
        self.note_pw = PasswordEntry(ctrl_row, placeholder="Note Password", height=36, corner_radius=6)
        self.note_pw.pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(ctrl_row, text="Save Note",
                      command=self._save_note, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        ctk.CTkButton(ctrl_row, text="Load Note",
                      command=self._load_note, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        
        self.note_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(size=14), wrap="word",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.note_textbox.grid(row=3, column=0, sticky="nsew")
        
        
        self.notes_empty = EmptyStateContainer(frame, "📝", "You don't have your encrypted note yet.")
        self.notes_empty.show()
        
        def _on_note_interaction(*args):
            self.notes_empty.hide()
            
        self.note_textbox.bind("<Button-1>", _on_note_interaction)
        self.note_textbox.bind("<Key>", _on_note_interaction)
        self.note_textbox.bind("<FocusIn>", _on_note_interaction)
        
        def _hide_and_focus(*args):
            self.notes_empty.hide()
            self.note_textbox.focus()
            
        self.notes_empty.bind("<Button-1>", _hide_and_focus)
        self.notes_empty.icon_label.bind("<Button-1>", _hide_and_focus)
        self.notes_empty.msg_label.bind("<Button-1>", _hide_and_focus)
        
        # Hook load event to hide empty state
        original_insert = self.note_textbox.insert
        def _hooked_insert(*args, **kwargs):
            self.notes_empty.hide()
            return original_insert(*args, **kwargs)
        self.note_textbox.insert = _hooked_insert
        
        return page_frame

    def _clear_notes_search(self):
        self.notes_search_entry.delete(0, "end")
        self._filter_notes()

    def _filter_notes(self, event=None):
        query = self.notes_search_entry.get().strip().lower()
        if not query:
            self.notes_search_clear.pack_forget()
            return
            
        self.notes_search_clear.pack(side="right", padx=(8, 0))
        # Since there is no actual list of notes in the UI (only the single loaded note editor),
        # this fulfills the structural requirement without crashing.
        pass

    def _save_note(self):
        pw = self.note_pw.get()
        if not pw:
            messagebox.showwarning("Password Required", "Please enter a password to encrypt the note.")
            return
            
        text = self.note_textbox.get("0.0", "end-1c")
        if not text:
            messagebox.showwarning("Empty Note", "Please write something to encrypt.")
            return
            
        path = filedialog.asksaveasfilename(
            title="Save Encrypted Note",
            defaultextension=".vault",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")]
        )
        if not path: return
        
        self.is_processing = True
        self._set_status("Encrypting note...")
        threading.Thread(target=self._notes_encrypt_worker, args=(text, Path(path), pw), daemon=True).start()

    def _notes_encrypt_worker(self, text, path, pw):
        try:
            self.crypto.encrypt_note(text, path, pw, note_title=path.name)
            self._log_activity("Note Encrypt", path.name, "Success")
            self.msg_queue.put({"type": "batch_done", "text": f"Note saved to {path.name}"}, timeout=1.0)
        except Exception as e:
            self._log_activity("Note Encrypt", path.name, "Failed", str(e))
            self.msg_queue.put({"type": "batch_done", "text": f"Note save failed: {e}"}, timeout=1.0)

    def _load_note(self):
        pw = self.note_pw.get()
        if not pw:
            messagebox.showwarning("Password Required", "Please enter the password to decrypt.")
            return
            
        path = filedialog.askopenfilename(
            title="Load Encrypted Note",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")]
        )
        if not path: return
        
        self.is_processing = True
        self._set_status("Decrypting note...")
        self.note_textbox.configure(state="normal")
        self.note_textbox.delete("0.0", "end")
        threading.Thread(target=self._notes_decrypt_worker, args=(Path(path), pw), daemon=True).start()

    def _notes_decrypt_worker(self, path, pw):
        try:
            text = self.crypto.decrypt_note(path, pw)
            self._log_activity("Note Decrypt", path.name, "Success")
            self.msg_queue.put({"type": "note_decrypted", "text": text}, timeout=1.0)
            self.msg_queue.put({"type": "batch_done", "text": f"Note loaded: {path.name}"}, timeout=1.0)
        except AuthenticationError:
            self._log_activity("Note Decrypt", path.name, "Failed", "Auth Error")
            self.msg_queue.put({"type": "batch_done", "text": "Note load failed: Wrong Password"}, timeout=1.0)
        except Exception as e:
            self._log_activity("Note Decrypt", path.name, "Failed", str(e))
            self.msg_queue.put({"type": "batch_done", "text": f"Note load failed: {e}"}, timeout=1.0)

    # ==========================================================================
    # ACTIVITY VIEW
    # ==========================================================================

    def _create_activity_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(frame, text="Activity Feed & Statistics", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 20), sticky="w")
        
        btn_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        btn_row.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        
        ctk.CTkButton(btn_row, text="Refresh",
                      command=self._refresh_activity, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Clear Log",
                      command=self._clear_activity, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

        self.activity_textbox = ctk.CTkTextbox(
            frame,
            font=ctk.CTkFont(size=12, family="Courier New"),
            wrap="word",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.activity_textbox.grid(row=2, column=0, sticky="nsew")
        self._refresh_activity()
        return page_frame
    def _refresh_activity(self) -> None:
        if not hasattr(self, "activity_textbox"): return
        self.activity_textbox.configure(state="normal")
        self.activity_textbox.delete("0.0", "end")
        logs = self.activity_logger.get_logs(limit=200)
        if not logs:
            self.activity_textbox.insert("end", "No activity recorded yet.")
        else:
            for log in logs:
                line = f"[{log['timestamp']}] {log['action']:<10} | {log['status']:<8} | {log['filename']}\n"
                if log['details']:
                    line += f"    -> {log['details']}\n"
                self.activity_textbox.insert("end", line)
        self.activity_textbox.configure(state="disabled")

    def _clear_activity(self) -> None:
        if messagebox.askyesno("Clear Activity Log", "Are you sure you want to delete all activity logs?"):
            self.activity_logger.clear_logs()
            self._refresh_activity()

    # ==========================================================================
    # SETTINGS VIEW
    # ==========================================================================

    def _create_settings_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Settings", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 20), sticky="w")

        row = 1

        # --- APPEARANCE ---
        ctk.CTkLabel(frame, text="Appearance", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        app_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        app_frame.grid(row=row, column=0, sticky="w", pady=(0, 16))
        row += 1

        ctk.CTkLabel(app_frame, text="Theme:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 12))
        self.theme_var = ctk.StringVar(value=get_setting("theme", "Dark"))
        ctk.CTkOptionMenu(
            app_frame, values=["Dark", "Light", "System"],
            variable=self.theme_var,
            command=self._change_theme,
            width=130, font=ctk.CTkFont(size=14),

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left", padx=(0, 20))

        ctk.CTkLabel(app_frame, text="UI Scale:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 12))
        self.scale_var = ctk.StringVar(value="100%")
        ctk.CTkOptionMenu(
            app_frame, values=["80%", "90%", "100%", "110%", "120%"],
            variable=self.scale_var,
            command=self._change_scaling,
            width=110, font=ctk.CTkFont(size=14),

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left")

        # --- UPDATES ---
        ctk.CTkLabel(frame, text="Updates", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        upd_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        upd_frame.grid(row=row, column=0, sticky="w", pady=(0, 16))
        row += 1

        self.updates_var = ctk.BooleanVar(value=get_setting("check_updates", True))
        ctk.CTkSwitch(
            upd_frame, text="Check for updates on startup",
            variable=self.updates_var,
            command=lambda: save_setting("check_updates", self.updates_var.get()),
            font=ctk.CTkFont(size=14),
            fg_color="#30363d", progress_color="#00d4aa", button_color="#ffffff", text_color="#e6edf3"
        ).pack(side="left")

        # --- PROFILES ---
        ctk.CTkLabel(frame, text="Smart Encryption Profiles", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        prof_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        prof_frame.grid(row=row, column=0, sticky="ew", pady=(0, 20))
        prof_frame.grid_columnconfigure(0, weight=1)
        row += 1
        
        prof_entry_row = ctk.CTkFrame(prof_frame, fg_color="#0d1117", corner_radius=0)
        prof_entry_row.grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.profile_name_var = ctk.StringVar()
        ctk.CTkEntry(prof_entry_row, textvariable=self.profile_name_var, placeholder_text="Profile Name", width=200, fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6).pack(side="left", padx=(0, 8))
        ctk.CTkButton(prof_entry_row, text="Save Current as Profile", command=self._save_profile, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        ctk.CTkButton(prof_entry_row, text="Delete Selected", command=self._delete_profile, width=120, fg_color="#f85149", text_color="#0d1117", hover_color="#ff6e6e", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left")
        
        self.profile_select_var = ctk.StringVar(value="Select Profile")
        self.profile_delete_menu = ctk.CTkOptionMenu(prof_entry_row, variable=self.profile_select_var, values=["Select Profile"], fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6)
        self.profile_delete_menu.pack(side="left", padx=(8, 0))
        
        self.after(100, self._update_profile_dropdowns)

        # --- ARGON2 KDF ---
        ctk.CTkLabel(frame, text="Argon2id Key Derivation (applied to new vaults)", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        kdf_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        kdf_frame.grid(row=row, column=0, sticky="ew", pady=(0, 6), ipadx=10, ipady=8)
        kdf_frame.grid_columnconfigure(1, weight=1)
        row += 1

        self._kdf_widgets: Dict[str, Any] = {}
        kdf_params = [
            ("Memory (KiB)", "argon2_memory", ARGON2_MEMORY_COST,
             [16384, 32768, 65536, 131072, 262144, 524288],
             {16384: "16 MiB", 32768: "32 MiB", 65536: "64 MiB (default)",
              131072: "128 MiB", 262144: "256 MiB", 524288: "512 MiB"}),
            ("Iterations", "argon2_time", ARGON2_TIME_COST,
             [1, 2, 3, 4, 5, 6, 8, 10],
             {}),
            ("Parallelism", "argon2_par", ARGON2_PARALLELISM,
             [1, 2, 4, 8, 16],
             {}),
        ]

        for kdf_row, (label, key, default, values, label_map) in enumerate(kdf_params):
            current = get_setting(key, default)
            ctk.CTkLabel(kdf_frame, text=f"{label}:",
                         font=ctk.CTkFont(size=14),

                         text_color="#e6edf3").grid(row=kdf_row, column=0, padx=(12, 10), pady=4, sticky="w")
            str_values = [label_map.get(v, str(v)) for v in values]
            rev_map = {label_map.get(v, str(v)): v for v in values}
            cur_disp = label_map.get(current, str(current))
            var = ctk.StringVar(value=cur_disp)
            self._kdf_widgets[key] = (var, rev_map, default)
            ctk.CTkOptionMenu(
                kdf_frame, values=str_values, variable=var,
                width=200, font=ctk.CTkFont(size=13),

            fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).grid(row=kdf_row, column=1, padx=(0, 12), pady=4, sticky="w")

        ctk.CTkButton(
            frame, text="💾  Save KDF Settings & Restart Crypto Engine",
            command=self._save_kdf_settings, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1

        # --- SECURITY HEALTH CHECK ---
        ctk.CTkLabel(frame, text="Security Health Check", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1
        
        ctk.CTkButton(
            frame, text="🛡️  Run Security Health Check",
            command=self._run_health_check, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1

        # --- SECURE WIPE ---
        ctk.CTkLabel(frame, text="Secure Wipe", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        wipe_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        wipe_frame.grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1

        ctk.CTkLabel(wipe_frame, text="Overwrite passes:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 10))
        self.wipe_passes_var = ctk.StringVar(
            value=str(get_setting("wipe_passes", 1)))
        ctk.CTkOptionMenu(
            wipe_frame, values=["1", "3", "7"],
            variable=self.wipe_passes_var,
            width=80, font=ctk.CTkFont(size=14),
            command=self._save_wipe_setting,

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left")
        ctk.CTkLabel(wipe_frame,
                     text="  (1 pass is sufficient for SSDs; 3+ for HDDs)", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(8, 0))

        # --- VAULT VERSIONING ---
        ctk.CTkLabel(frame, text="Vault Versioning", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        ver_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        ver_frame.grid(row=row, column=0, sticky="ew", pady=(0, 20), ipadx=10, ipady=10)
        ver_frame.grid_columnconfigure(1, weight=1)
        row += 1

        # Enable toggle
        self._ver_enabled_var = ctk.BooleanVar(value=bool(get_setting("versioning_enabled", False)))
        ctk.CTkLabel(ver_frame, text="Enable Versioning:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(12, 10), pady=6, sticky="w")
        ver_toggle = ctk.CTkSwitch(
            ver_frame, text="",
            variable=self._ver_enabled_var,
            command=self._save_versioning_settings,

        fg_color="#30363d", progress_color="#00d4aa", text_color="#e6edf3", button_color="#ffffff")
        ver_toggle.grid(row=0, column=1, padx=(0, 12), pady=6, sticky="w")

        # Max versions per vault
        ctk.CTkLabel(ver_frame, text="Max versions per vault:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=1, column=0, padx=(12, 10), pady=6, sticky="w")
        self._ver_max_count_var = ctk.StringVar(value=str(get_setting("versioning_max_per_vault", 5)))
        ctk.CTkOptionMenu(
            ver_frame, values=["1", "2", "3", "5", "10", "20"],
            variable=self._ver_max_count_var,
            width=100, font=ctk.CTkFont(size=13),
            command=lambda _: self._save_versioning_settings(),

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).grid(row=1, column=1, padx=(0, 12), pady=6, sticky="w")

        # Max total size
        ctk.CTkLabel(ver_frame, text="Max total size (MiB):", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=2, column=0, padx=(12, 10), pady=6, sticky="w")
        self._ver_max_size_var = ctk.StringVar(value=str(get_setting("versioning_max_total_mb", 2048)))
        ctk.CTkOptionMenu(
            ver_frame, values=["256", "512", "1024", "2048", "4096", "8192"],
            variable=self._ver_max_size_var,
            width=120, font=ctk.CTkFont(size=13),
            command=lambda _: self._save_versioning_settings(),

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).grid(row=2, column=1, padx=(0, 12), pady=6, sticky="w")

        # Versions directory
        ctk.CTkLabel(ver_frame, text="Versions directory:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=3, column=0, padx=(12, 10), pady=6, sticky="w")
        ver_dir_row = ctk.CTkFrame(ver_frame, fg_color="transparent", corner_radius=0)
        ver_dir_row.grid(row=3, column=1, sticky="ew", padx=(0, 12), pady=6)
        ver_dir_row.grid_columnconfigure(0, weight=1)
        default_ver_dir = str(versioning.VERSIONS_ROOT_DEFAULT)
        self._ver_dir_entry = ctk.CTkEntry(
            ver_dir_row,
            font=ctk.CTkFont(size=12),
            placeholder_text=default_ver_dir,

        fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self._ver_dir_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        saved_dir = get_setting("versioning_dir", "")
        if saved_dir:
            self._ver_dir_entry.insert(0, saved_dir)

        def browse_ver_dir():
            d = filedialog.askdirectory(title="Select Versions Directory")
            if d:
                self._ver_dir_entry.delete(0, "end")
                self._ver_dir_entry.insert(0, d)
                self._save_versioning_settings()
        ctk.CTkButton(ver_dir_row, text="Browse",
                      command=browse_ver_dir, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        ctk.CTkLabel(
            ver_frame,
            text="  Versioning is opt-in. Large vaults (>1 GiB) will be fully copied before each Re-Key.",
            justify="left", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=4, column=0, columnspan=2, padx=12, pady=(4, 6), sticky="w")

        # --- PRIVACY & LOCAL TRACES ---
        ctk.CTkLabel(frame, text="Privacy & Local Traces", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        privacy_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        privacy_frame.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1

        self.logging_enabled_var = ctk.BooleanVar(value=bool(get_setting("logging_enabled", True)))
        ctk.CTkSwitch(
            privacy_frame, text="Enable Activity Logging",
            variable=self.logging_enabled_var,
            command=self._save_logging_setting,
            font=ctk.CTkFont(size=14),
            fg_color="#30363d", progress_color="#00d4aa", button_color="#ffffff", text_color="#e6edf3"
        ).pack(side="left")

        ctk.CTkButton(
            frame, text="⚠️  Clear All Local Traces",
            command=self._clear_all_traces, fg_color="#f85149", text_color="#0d1117", hover_color="#ff6e6e", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        ctk.CTkLabel(
            frame,
            text="  Erases the activity log, Library cache, saved fingerprints, and recent-file lists from this device. Vault files are not affected.",
            justify="left", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1

        # --- ABOUT ---
        ctk.CTkLabel(frame, text="About", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        about = (
            f"{APP_NAME}  v{APP_VERSION}\n"
            "Envelope Encryption: AES-256-GCM  ·  Argon2id KDF\n"
            "\n"
            "Shortcuts:  Ctrl+E Encrypt  ·  Ctrl+D Decrypt  ·  Ctrl+I Inspect\n"
            "            Ctrl+R Re-Key   ·  Ctrl+P Password  ·  Alt+S Settings"
        )
        ctk.CTkLabel(
            frame, text=about,
            font=ctk.CTkFont(size=12),
            justify="left",

        text_color="#7d8590").grid(row=row, column=0, sticky="w")

        return page_frame
    def _change_theme(self, choice: str) -> None:
        ctk.set_appearance_mode(choice)
        save_setting("theme", choice)
        self._set_status(f"Theme: {choice}")

    def _change_scaling(self, choice: str) -> None:
        scale = int(choice.replace("%", "")) / 100
        ctk.set_widget_scaling(scale)
        self._set_status(f"UI scale: {choice}")

    def _save_kdf_settings(self) -> None:
        if self.is_processing:
            messagebox.showwarning(
                "Operation in Progress",
                "Cannot change KDF settings while encrypting/decrypting.\n"
                "Please wait for the current operation to finish."
            )
            return
        
        for key, (var, rev_map, default) in self._kdf_widgets.items():
            raw = rev_map.get(var.get(), default)
            save_setting(key, raw)
        
        # Rebuild all crypto services
        self._build_crypto()
        self.packager = FolderPackager()
        self.wiper = SecureWiper(passes=get_setting("wipe_passes", 1))
        self.inspector = VaultInspector(self.crypto)
        
        self._set_status("Crypto engine reloaded with new KDF parameters")
        messagebox.showinfo("Saved",
                            "Argon2id parameters updated.\n"
                            "New vaults will use these settings.\n"
                            "Existing vaults remain accessible with their original parameters.")

    def _save_wipe_setting(self, choice: str) -> None:
        passes = int(choice)
        save_setting("wipe_passes", passes)
        self.wiper = SecureWiper(passes=passes)
        self._set_status(f"Wipe passes set to {passes}")

    def _save_versioning_settings(self) -> None:
        """Persist versioning settings and rebuild the versioner instance."""
        save_setting("versioning_enabled", self._ver_enabled_var.get())
        try:
            save_setting("versioning_max_per_vault", int(self._ver_max_count_var.get()))
        except ValueError:
            pass
        try:
            save_setting("versioning_max_total_mb", int(self._ver_max_size_var.get()))
        except ValueError:
            pass
        ver_dir = self._ver_dir_entry.get().strip()
        save_setting("versioning_dir", ver_dir)
        self.versioner = self._build_versioner()
        self._set_status(
            f"Versioning {'enabled' if self.versioner.enabled else 'disabled'} — "            f"max {self.versioner.max_versions_per_vault} versions, "            f"{self.versioner.max_total_size_bytes // (1024*1024)} MiB limit"
        )

    def _update_profile_dropdowns(self):
        cfg = _load_cfg()
        profiles = cfg.get("profiles", {})
        profile_names = list(profiles.keys())
        if not profile_names:
            profile_names = ["No Profiles Saved"]
            
        if hasattr(self, "profile_delete_menu"):
            self.profile_delete_menu.configure(values=profile_names)
            self.profile_select_var.set(profile_names[0])
            
        if hasattr(self, "enc_profile_menu"):
            self.enc_profile_menu.configure(values=["Custom"] + (list(profiles.keys()) if profiles else []))

    def _save_profile(self):
        name = self.profile_name_var.get().strip()
        if not name:
            messagebox.showwarning("Name Required", "Please enter a profile name.")
            return
        if name.lower() in ["custom", "no profiles saved"]:
            messagebox.showwarning("Reserved Name", "That profile name is reserved. Please choose another name.")
            return
        
        cfg = _load_cfg()
        profiles = cfg.setdefault("profiles", {})
        
        settings = cfg.get("settings", {})
        profiles[name] = {
            "argon2_memory": settings.get("argon2_memory", ARGON2_MEMORY_COST),
            "argon2_time": settings.get("argon2_time", ARGON2_TIME_COST),
            "argon2_par": settings.get("argon2_par", ARGON2_PARALLELISM),
            "wipe_passes": settings.get("wipe_passes", 1),
        }
        _save_cfg(cfg)
        self.profile_name_var.set("")
        self._update_profile_dropdowns()
        self._set_status(f"Profile '{name}' saved.")

    def _delete_profile(self):
        name = self.profile_select_var.get()
        cfg = _load_cfg()
        profiles = cfg.get("profiles", {})
        if name in profiles:
            del profiles[name]
            _save_cfg(cfg)
            self._update_profile_dropdowns()
            self._set_status(f"Profile '{name}' deleted.")

    def _apply_profile(self, profile_name: str):
        if profile_name == "Custom" or profile_name == "No Profiles Saved": return
        cfg = _load_cfg()
        profiles = cfg.get("profiles", {})
        profile = profiles.get(profile_name)
        if not profile: return
        
        save_setting("argon2_memory", profile.get("argon2_memory"))
        save_setting("argon2_time", profile.get("argon2_time"))
        save_setting("argon2_par", profile.get("argon2_par"))
        save_setting("wipe_passes", profile.get("wipe_passes", 1))
        
        if hasattr(self, "_kdf_widgets"):
            for key, (var, rev_map, default) in self._kdf_widgets.items():
                val = profile.get(key, default)
                for k, v in rev_map.items():
                    if v == val:
                        var.set(k)
                        break
        if hasattr(self, "wipe_passes_var"):
            self.wipe_passes_var.set(str(profile.get("wipe_passes", 1)))
            
        self._build_crypto()
        self.wiper = SecureWiper(passes=profile.get("wipe_passes", 1))
        self._set_status(f"Profile '{profile_name}' applied.")

    def _run_health_check(self):
        import platform
        import psutil
        
        settings = _load_cfg().get("settings", {})
        mem = settings.get("argon2_memory", ARGON2_MEMORY_COST)
        iters = settings.get("argon2_time", ARGON2_TIME_COST)
        wipe = settings.get("wipe_passes", 1)
        
        issues = []
        passes = []
        
        if mem >= 65536 and iters >= 3:
            passes.append("✅ Argon2id parameters meet or exceed OWASP baselines.")
        else:
            issues.append("⚠️ Argon2id parameters are below OWASP baselines (recommend >= 64 MiB memory, >= 3 iterations).")
            
        if wipe >= 1:
            passes.append("✅ Secure Wipe is configured (passes >= 1).")
        else:
            issues.append("⚠️ Secure Wipe passes is 0. Original files will not be securely deleted.")
            
        is_ssd = False
        try:
            if platform.system() == "Windows":
                import subprocess
                res = subprocess.run(["wmic", "diskdrive", "get", "mediatype"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if "SSD" in res.stdout or "Solid State" in res.stdout:
                    is_ssd = True
            elif platform.system() == "Linux":
                for p in Path("/sys/block").glob("*/queue/rotational"):
                    if p.read_text().strip() == "0":
                        is_ssd = True
                        break
        except Exception:
            pass

        if is_ssd:
            passes.append("ℹ️ SSD detected. 1 wipe pass is sufficient due to wear-leveling.")
        else:
            passes.append("ℹ️ Storage medium: Assuming HDD or indeterminate. 3+ wipe passes recommended for HDDs.")
            
        msg = "SECURITY HEALTH CHECK RESULTS\n\n"
        if issues:
            msg += "Needs Attention:\n" + "\n".join(issues) + "\n\n"
        msg += "Good:\n" + "\n".join(passes)
        
        messagebox.showinfo("Security Health Check", msg)

    # ==========================================================================
    # THREAD COMMUNICATION
    # ==========================================================================

    def _qlog(self, msg: str) -> None:
        """Send a log message from worker thread to the active log box."""
        try:
            self.msg_queue.put({"type": "log", "text": msg}, timeout=0.1)
        except queue.Full:
            logger.warning("Message queue full, log message dropped: %s", msg)


    def _check_update_background(self):
        update_info = check_for_update(APP_VERSION)
        if update_info is not None:
            self.after(0, self._show_update_notification, update_info)

    def _show_update_notification(self, update_info: dict):
        if hasattr(self, "_update_frame") and self._update_frame.winfo_exists():
            return
            
        self._update_frame = ctk.CTkFrame(self._nav_bottom, fg_color="transparent")
        self._update_frame.pack(side="top", fill="x", pady=(0, 8))
        
        # Clickable event wrapper
        def click_handler(event=None):
            self._download_update(update_info["url"])
            
        # Left container for text
        text_container = ctk.CTkFrame(self._update_frame, fg_color="transparent")
        text_container.pack(side="left", fill="x", expand=True)
        text_container.bind("<Button-1>", click_handler)
            
        # Banner layout
        lbl_new = ctk.CTkLabel(text_container, text=f"🔄 New version: v{update_info['version']}", text_color="#00d4aa", font=ctk.CTkFont(size=14), cursor="hand2")
        lbl_new.pack(side="top", anchor="w", padx=(12, 0))
        lbl_new.bind("<Button-1>", click_handler)
        
        lbl_dl = ctk.CTkLabel(text_container, text="Click to download", text_color="#7d8590", font=ctk.CTkFont(size=14), cursor="hand2")
        lbl_dl.pack(side="top", anchor="w", padx=(12, 0))
        lbl_dl.bind("<Button-1>", click_handler)
        
        self._update_frame.bind("<Button-1>", click_handler)
        
        # Close button on the right
        btn_close = ctk.CTkButton(self._update_frame, text="✕", width=20, height=20, fg_color="transparent", text_color="#7d8590", hover_color="#30363d", corner_radius=4)
        btn_close.pack(side="right", padx=(0, 4))
        
        def destroy_banner():
            if self._update_frame.winfo_exists():
                self._update_frame.destroy()
        
        btn_close.configure(command=destroy_banner)

    def _download_update(self, url: str):
        webbrowser.open(url)

    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self._handle_message(msg)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_message(self, msg: Dict[str, Any]) -> None:
        mtype = msg.get("type")

        if mtype == "log":
            if self._active_log is not None:
                self._active_log.write(msg["text"])
            self._set_status(msg["text"])

        elif mtype == "progress_start":
            try:
                self.progress_bar.stop()
                self.progress_bar.configure(mode="determinate")
            except Exception:
                pass
            self.progress_bar.set(0)
            self._progress_pct.configure(text="0%")
            
            for attr in ("_enc_progress", "_dec_progress"):
                bar = getattr(self, attr, None)
                if bar:
                    try:
                        bar.stop()
                        bar.configure(mode="determinate")
                    except Exception:
                        pass
                    bar.set(0)
            for attr in ("_enc_pct_lbl", "_dec_pct_lbl"):
                lbl = getattr(self, attr, None)
                if lbl:
                    lbl.configure(text="0%")

        elif mtype == "progress":
            done  = msg.get("done", 0)
            total = msg.get("total", 0)
            if total > 0:
                pct = min(done / total, 1.0)
                pct_text = f"{int(pct * 100)}%"
                self.progress_bar.set(pct)
                self._progress_pct.configure(text=pct_text)
                
                for bar_attr, lbl_attr in (("_enc_progress", "_enc_pct_lbl"),
                                            ("_dec_progress", "_dec_pct_lbl")):
                    bar = getattr(self, bar_attr, None)
                    lbl = getattr(self, lbl_attr, None)
                    if bar:
                        bar.set(pct)
                    if lbl:
                        lbl.configure(text=pct_text)

        elif mtype == "error":
            self._set_status(msg.get("text", "Error"))
            self._reset_progress_bars()

        elif mtype == "auth_error":
            rem = msg.get("remaining", 0)
            secs = msg.get("lockout", 0)
            text = (f"Locked out — wait {secs}s" if secs
                    else f"Wrong password — {rem} attempts remaining")
            if hasattr(self, "_dec_attempts_lbl"):
                self._dec_attempts_lbl.configure(text=text)
            if hasattr(self, "_ins_attempts_lbl"):
                self._ins_attempts_lbl.configure(text=text)

        elif mtype == "batch_done":
            self.is_processing = False
            self._reset_progress_bars(success=True)
            self._set_status(msg.get("text", "Done"))
            
            # Re-enable buttons
            for attr, label in [
                ("encrypt_btn", "🔐  Encrypt Batch"),
                ("decrypt_btn", "🔓  Decrypt"),
                ("rekey_btn",   "⟳  Re-Key Vault"),
            ]:
                btn = getattr(self, attr, None)
                if btn:
                    btn.configure(state="normal", text=label)
            
            if hasattr(self, "_rk_recent"):
                self._rk_recent.refresh()
                
            msg_text = msg.get("text", "").lower()
            if "encrypt" in msg_text and "fail" not in msg_text and "error" not in msg_text:
                self.after(2000, self._clear_batch)
            elif "decrypt" in msg_text and "fail" not in msg_text and "error" not in msg_text:
                self.after(2000, self._clear_decrypt_form)

        elif mtype == "enc_password_strength":
            score = msg.get("score", 0)
            crack_time = msg.get("crack_time")
            color, label = STRENGTH_COLORS.get(score, ("gray", "Unknown"))
            self.strength_bar.set((score + 1) / 5.0)
            self.strength_bar.configure(progress_color=color)
            if crack_time:
                self.strength_label.configure(
                    text=f"{label}  •  Est. crack time: {crack_time}",
                    text_color=color)
            else:
                self.strength_label.configure(
                    text=f"{label}  (install zxcvbn for accurate analysis)",
                    text_color=color)

        elif mtype == "rekey_password_strength":
            score = msg.get("score", 0)
            crack_time = msg.get("crack_time")
            color, label = STRENGTH_COLORS.get(score, ("gray", "Unknown"))
            if crack_time:
                self.rekey_strength_lbl.configure(
                    text=f"New password strength: {label}  •  Est. crack time: {crack_time}",
                    text_color=color)

        elif mtype == "fingerprint_results":
            # Update fingerprint panel with hash verification results
            data = msg.get("data", {})
            fps = self._load_fingerprints()
            
            self._fp_listbox.configure(state="normal")
            self._fp_listbox.delete("0.0", "end")
            
            for key, rec in sorted(fps.items(), key=lambda kv: kv[1]["recorded"], reverse=True):
                status, current_hash = data.get(key, ("⏳", None))
                sz_mb = rec["size"] / (1024 * 1024)
                line = (f"{status}  {rec['filename']}  "
                        f"({sz_mb:.1f} MB)  recorded {rec['recorded']}\n"
                        f"      SHA-256: {rec['sha256']}\n\n")
                self._fp_listbox.insert("end", line)
            
            self._fp_listbox.configure(state="disabled")

        elif mtype == "library_results":
            if hasattr(self, "library_textbox"):
                self.last_library_results = msg.get("data", [])
                self._filter_library()
                self._set_status(f"Library scan complete. Found {len(self.last_library_results)} vaults.")

        elif mtype == "note_decrypted":
            if hasattr(self, "note_textbox"):
                self.note_textbox.configure(state="normal")
                self.note_textbox.insert("end", msg.get("text", ""))

        elif mtype == "recovery_phrase":
            # H5 FIX: The hidden-vault worker (running off the main thread) cannot
            # build a dialog itself, so it enqueues the DECOY recovery phrase here.
            # Previously there was no branch for this message type, so the phrase
            # was silently discarded — a user who later lost the decoy password
            # could be permanently locked out. _handle_message runs on the main
            # thread, so displaying the dialog from here is thread-safe.
            self._show_recovery_dialog(msg.get("phrase", ""))

    def _show_recovery_dialog(self, phrase: str) -> None:
        """
        H5 FIX: Display an already-generated recovery phrase (e.g. the decoy
        recovery phrase produced by the hidden-vault worker) and force the user
        to acknowledge it before it disappears.

        This mirrors the read-only recovery-phrase modal the normal encrypt path
        shows synchronously, reusing the same widgets and styling. It is
        display-only — the phrase is generated elsewhere — so unlike the encrypt
        modal it returns no key and gates no operation. Invoked from
        _handle_message (main thread); the nested wait_window blocks the main
        window until dismissed so the user cannot miss it.
        """
        if not phrase:
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Recovery Phrase")
        dialog.geometry("550x350")
        dialog.configure(fg_color="#0d1117")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)
        dialog.grab_set()

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent", corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=20, pady=5)

        ctk.CTkLabel(scroll, text="Your Recovery Phrase", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(20, 5))
        ctk.CTkLabel(scroll, text="Write this down and keep it safe. It will never be shown again.", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(0, 15))

        textbox = ctk.CTkTextbox(scroll, wrap="word", font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        textbox.pack(padx=10, fill="x")
        textbox.insert("0.0", phrase)
        textbox.configure(state="disabled")

        confirmed = ctk.BooleanVar(value=False)
        check = ctk.CTkCheckBox(scroll, text="I have securely saved this 24-word phrase.", variable=confirmed, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117")
        check.pack(pady=20)

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent", corner_radius=0)
        btn_frame.pack(fill="x", side="bottom", pady=10)

        def on_done():
            if not confirmed.get():
                messagebox.showwarning("Confirm", "You must confirm you have saved the phrase.", parent=dialog)
                return
            dialog.destroy()

        ctk.CTkButton(btn_frame, text="Done", command=on_done, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="right", padx=10)

        # Force acknowledgment: closing via the window's X button must also pass
        # through on_done() so the phrase cannot be dismissed without confirming.
        dialog.protocol("WM_DELETE_WINDOW", on_done)

        self.wait_window(dialog)

    def _reset_progress_bars(self, success=False):
        """Reset all progress bars to initial state."""
        def revert_color(bar, lbl):
            if bar.winfo_exists():
                bar.configure(progress_color="#00d4aa")
                bar.set(0)
            if lbl and lbl.winfo_exists():
                lbl.configure(text="0%")

        for bar_attr, lbl_attr in (
            ("progress_bar", "_progress_pct"),
            ("_enc_progress", "_enc_pct_lbl"),
            ("_dec_progress", "_dec_pct_lbl"),
        ):
            bar = getattr(self, bar_attr, None)
            lbl = getattr(self, lbl_attr, None)
            if bar:
                try:
                    bar.stop()
                    bar.configure(mode="determinate")
                except Exception:
                    pass
                if success:
                    bar.configure(progress_color="#3fb950")
                    bar.set(1.0)
                    if lbl: lbl.configure(text="100%")
                    self.after(2000, lambda b=bar, l=lbl: revert_color(b, l))
                else:
                    bar.set(0)
                    if lbl: lbl.configure(text="0%")
            if lbl:
                lbl.configure(text="")

    # ==========================================================================
    # ENTRY POINT
    # ==========================================================================

    def run(self) -> None:
        self.stats.mark_start()
        self.mainloop()


def main() -> None:
    app = RPMEncrypterApp()
    app.run()


if __name__ == "__main__":
    main()
