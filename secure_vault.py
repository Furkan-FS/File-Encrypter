"""
Secure Folder RPM Encrypter  V1.0
================================
AES-256-GCM + Argon2id şifreleyici — tam özellikli masaüstü uygulaması.

Bağımlılıklar:
    pip install cryptography argon2-cffi zxcvbn customtkinter tkinterdnd2
"""

import os, json, secrets, shutil, threading, zipfile, time, struct, colorsys
import subprocess, platform, math, re, hashlib
from pathlib import Path
from datetime import datetime
from queue import Queue, Empty

# ── Bağımlılık kontrolü ───────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    import argon2
    import zxcvbn as _zxcvbn_mod
    import customtkinter as _ctk_unused   # sadece varlık kontrolü
    from tkinter import filedialog, messagebox, colorchooser
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD
        HAS_DND = True
    except ImportError:
        HAS_DND = False
except ImportError as e:
    print("Eksik bağımlılık:\n"
          "pip install cryptography argon2-cffi zxcvbn customtkinter tkinterdnd2")
    raise

import tkinter as tk
from tkinter import font as tkfont

# ── Sabitler ──────────────────────────────────────────────────────────────────
APP_VERSION      = "1.0"
VAULT_EXTENSION  = ".vault"
CHUNK_SIZE       = 64 * 1024
SALT_SIZE        = 32
NONCE_SIZE       = 12
VAULT_MAGIC      = b"SVPV2\x00"
MIN_PWD_LEN      = 8
MAX_ATTEMPTS     = 5
LOCKOUT_SECS     = 30
RECENT_FILE      = Path.home() / ".vault_pro_config.json"
MAX_RECENT       = 8

# Argon2id varsayılan parametreler (ayarlar tab'ında değiştirilebilir)
DEFAULT_ARGON2 = {"time_cost": 3, "memory_cost": 131072, "parallelism": 4}

# ── Tema paleti ───────────────────────────────────────────────────────────────
THEMES = {
    "Amber": {
        "bg": "#09090a", "surface": "#0e0e10", "surface2": "#16181d",
        "border": "#282835", "border_hi": "#c8963e",
        "accent": "#c8963e", "accent_dim": "#7a5a24", "accent_glow": "#e8b060",
        "accent_bg": "#1e150a",
        "green": "#3ecf7a", "red": "#e05252", "orange": "#e07a30",
        "yellow": "#e0c040", "cyan": "#38c8c8",
        "text": "#e8e8f0", "text_dim": "#8a8ab2", "text_muted": "#5a5a7a",
    },
    "Yeşil": {
        "bg": "#070c07", "surface": "#0b100b", "surface2": "#121a12",
        "border": "#1a2e1a", "border_hi": "#3ecf7a",
        "accent": "#3ecf7a", "accent_dim": "#1a6030", "accent_glow": "#60ef9a",
        "accent_bg": "#0a180a",
        "green": "#3ecf7a", "red": "#e05252", "orange": "#e07a30",
        "yellow": "#e0c040", "cyan": "#38c8c8",
        "text": "#dff0df", "text_dim": "#72a272", "text_muted": "#48584a",
    },
    "Mavi": {
        "bg": "#07090e", "surface": "#0b0d14", "surface2": "#12151e",
        "border": "#1a2038", "border_hi": "#4a8cf0",
        "accent": "#4a8cf0", "accent_dim": "#283880", "accent_glow": "#6aaeff",
        "accent_bg": "#0a1020",
        "green": "#3ecf7a", "red": "#e05252", "orange": "#e07a30",
        "yellow": "#e0c040", "cyan": "#38c8c8",
        "text": "#dde8f8", "text_dim": "#6a78a8", "text_muted": "#454860",
    },
    "Mor": {
        "bg": "#09070e", "surface": "#0e0b14", "surface2": "#18121e",
        "border": "#2a1a3a", "border_hi": "#9060e0",
        "accent": "#9060e0", "accent_dim": "#4a2880", "accent_glow": "#b080ff",
        "accent_bg": "#160a20",
        "green": "#3ecf7a", "red": "#e05252", "orange": "#e07a30",
        "yellow": "#e0c040", "cyan": "#38c8c8",
        "text": "#ede0f8", "text_dim": "#8a68a8", "text_muted": "#504060",
    },
}
C = dict(THEMES["Amber"])

# ── Config yönetimi ───────────────────────────────────────────────────────────
def _load_config() -> dict:
    try:
        if RECENT_FILE.exists():
            return json.loads(RECENT_FILE.read_text("utf-8"))
    except Exception:
        pass
    return {}

def _save_config(data: dict):
    try:
        RECENT_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    except Exception:
        pass

def get_recent(is_vault: bool) -> list[str]:
    cfg = _load_config()
    key = "vaults" if is_vault else "folders"
    return [p for p in cfg.get(key, []) if Path(p).exists()]

def save_recent(path: str, is_vault: bool):
    cfg = _load_config()
    key = "vaults" if is_vault else "folders"
    lst = cfg.get(key, [])
    if path in lst: lst.remove(path)
    lst.insert(0, path)
    cfg[key] = lst[:MAX_RECENT]
    _save_config(cfg)

def get_setting(key: str, default=None):
    return _load_config().get("settings", {}).get(key, default)

def save_setting(key: str, value):
    cfg = _load_config()
    cfg.setdefault("settings", {})[key] = value
    _save_config(cfg)

# Dinamik Font Yönetimi
def update_fonts():
    global FONT_UI, FONT_HEAD, FONT_MONO, FONT_SUBHEAD
    fam = get_setting("custom_font_family", "Segoe UI")
    size = get_setting("custom_font_size", 10)
    head_size = get_setting("custom_header_size", 22)
    
    FONT_UI   = (fam, size)
    FONT_HEAD = (fam, head_size, "bold")
    FONT_MONO = ("Courier New", size - 1)
    # Alt başlıklar ana başlığın yarısı kadar, ama en az genel yazı boyutu kadar olsun
    FONT_SUBHEAD = (fam, max(size, int(head_size * 0.5)), "bold")

update_fonts()

def _adjust_color(hex_color, amount):
    try:
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16)/255.0 for i in (0, 2, 4))
        h, l, s = colorsys.rgb_to_hls(r, g, b)
        l = max(0, min(1, l + amount))
        r, g, b = colorsys.hls_to_rgb(h, l, s)
        return '#%02x%02x%02x' % (int(r*255), int(g*255), int(b*255))
    except: return hex_color

# ── Güvenlik yardımcıları ─────────────────────────────────────────────────────
def _zero(ba: bytearray):
    for i in range(len(ba)): ba[i] = 0

def open_folder(path: Path):
    try:
        s = platform.system()
        if s == "Windows":   os.startfile(path)
        elif s == "Darwin":  subprocess.Popen(["open", str(path)])
        else:                subprocess.Popen(["xdg-open", str(path)])
    except Exception: pass

# ── Güvenli Silici ────────────────────────────────────────────────────────────
class SecureWiper:
    @staticmethod
    def wipe_file(p: Path, passes: int = 1) -> bool:
        if not p.exists(): return True
        try:
            sz = p.stat().st_size
            if sz > 0:
                with open(p, "r+b", buffering=0) as f:
                    for _ in range(passes):
                        f.seek(0); f.write(secrets.token_bytes(sz)); f.flush(); os.fsync(f.fileno())
            p.unlink(); return True
        except Exception as exc:
            print(f"[WIPE] {p}: {exc}"); return False

    @classmethod
    def wipe_folder(cls, folder: Path) -> list[str]:
        if not folder.exists(): return []
        failed = []
        for item in folder.rglob("*"):
            if item.is_symlink():
                try: item.unlink()
                except Exception as e: failed.append(f"{item}: {e}")
            elif item.is_file():
                if not cls.wipe_file(item): failed.append(str(item))
        try: shutil.rmtree(folder, ignore_errors=True)
        except Exception as e: failed.append(f"[RMTREE] {e}")
        return failed

# ── Kripto Motoru ─────────────────────────────────────────────────────────────
class CryptoEngine:
    """AES-256-GCM + Argon2id şifreleyici."""

    def __init__(self, password: str):
        self._pwd = bytearray(password.encode("utf-8"))

    def _derive(self, salt: bytes, params: dict | None = None) -> bytes:
        p = params or {
            "time_cost":   get_setting("argon2_time",   DEFAULT_ARGON2["time_cost"]),
            "memory_cost": get_setting("argon2_mem",    DEFAULT_ARGON2["memory_cost"]),
            "parallelism": get_setting("argon2_par",    DEFAULT_ARGON2["parallelism"]),
        }
        return argon2.low_level.hash_secret_raw(
            secret=bytes(self._pwd), salt=salt,
            time_cost=p["time_cost"], memory_cost=p["memory_cost"],
            parallelism=p["parallelism"], hash_len=32,
            type=argon2.low_level.Type.ID)

    def _cleanup(self): _zero(self._pwd)

    # ── Şifreleme ──────────────────────────────────────────────────────
    def encrypt_folder(self, folder: Path, out_vault: Path, cb=None) -> dict:
        salt = secrets.token_bytes(SALT_SIZE)
        key  = self._derive(salt)
        try:
            files = [f for f in folder.rglob("*") if f.is_file() and not f.is_symlink()]
            n     = len(files)
            total = sum(f.stat().st_size for f in files)
            names = [str(f.relative_to(folder)) for f in files]

            meta = {"version": APP_VERSION, "created_at": datetime.now().isoformat(),
                    "file_count": n, "original_size": total,
                    "folder_name": folder.name, "file_names": names,
                    "argon2": {"time_cost": get_setting("argon2_time", DEFAULT_ARGON2["time_cost"]),
                               "memory_cost": get_setting("argon2_mem", DEFAULT_ARGON2["memory_cost"]),
                               "parallelism": get_setting("argon2_par", DEFAULT_ARGON2["parallelism"])}}
            gcm = AESGCM(key)
            mn  = secrets.token_bytes(NONCE_SIZE)
            mct = gcm.encrypt(mn, json.dumps(meta, ensure_ascii=False).encode(), None)

            if cb: cb(0.05, "Sıkıştırılıyor…")
            tmp = out_vault.with_suffix(".tmp.zip")
            try:
                with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
                    for i, fp in enumerate(files):
                        zf.write(fp, fp.relative_to(folder))
                        if cb and n: cb(0.05 + 0.30*(i+1)/n, f"Sıkıştırılıyor: {fp.name}")

                zsz, dn = tmp.stat().st_size, secrets.token_bytes(NONCE_SIZE)
                if cb: cb(0.35, "Şifreleniyor…")
                chunks, done = [], 0
                with open(tmp, "rb") as fi:
                    while chunk := fi.read(CHUNK_SIZE):
                        chunks.append(chunk); done += len(chunk)
                        if cb and zsz: cb(0.35 + 0.50*done/zsz, "Şifreleniyor…")
                pt  = b"".join(chunks); dct = gcm.encrypt(dn, pt, None)
                del pt, chunks
                if cb: cb(0.90, "Yazılıyor…")
                with open(out_vault, "wb") as fo:
                    fo.write(VAULT_MAGIC + salt + mn)
                    fo.write(struct.pack(">I", len(mct)) + mct + dn + dct)
            finally:
                if tmp.exists(): tmp.unlink()
            del key
        finally:
            self._cleanup()
        if cb: cb(1.0, "Tamamlandı.")
        return {"file_count": n, "original_size": total,
                "vault_size": out_vault.stat().st_size}

    # ── Şifre çözme ────────────────────────────────────────────────────
    def decrypt_vault(self, vault: Path, out_dir: Path, cb=None) -> dict:
        try:
            with open(vault, "rb") as f:
                if f.read(6) != VAULT_MAGIC: raise ValueError("Geçersiz vault formatı.")
                salt = f.read(SALT_SIZE); mn = f.read(NONCE_SIZE)
                ml   = struct.unpack(">I", f.read(4))[0]; mct = f.read(ml)
                dn   = f.read(NONCE_SIZE); dct = f.read()
            if cb: cb(0.10, "Anahtar türetiliyor…")
            key = self._derive(salt)
            gcm = AESGCM(key)
            try: mp = gcm.decrypt(mn, mct, None)
            except InvalidTag: raise ValueError("Hatalı şifre (metadata doğrulaması başarısız).")
            md = json.loads(mp.decode())
            if cb: cb(0.30, "Doğrulanıyor…")
            try: pt = gcm.decrypt(dn, dct, None)
            except InvalidTag: raise ValueError("Hatalı şifre (veri doğrulaması başarısız).")
            del key
            if cb: cb(0.70, "Açılıyor…")
            if out_dir.exists():
                ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
                out_dir = out_dir.parent / f"{out_dir.name}_{ts}"
            out_dir.mkdir(parents=True, exist_ok=True)
            tmp = vault.with_suffix(".dec.tmp.zip")
            try:
                tmp.write_bytes(pt); del pt
                with zipfile.ZipFile(tmp) as zf: zf.extractall(out_dir)
            finally:
                if tmp.exists(): tmp.unlink()
        finally:
            self._cleanup()
        if cb: cb(1.0, "Tamamlandı.")
        md["extracted_to"] = str(out_dir); return md

    # ── Metadata okuma ─────────────────────────────────────────────────
    def read_metadata(self, vault: Path) -> dict:
        key = None
        try:
            with open(vault, "rb") as f:
                if f.read(6) != VAULT_MAGIC: raise ValueError("Geçersiz vault formatı.")
                salt = f.read(SALT_SIZE); mn = f.read(NONCE_SIZE)
                ml   = struct.unpack(">I", f.read(4))[0]; mct = f.read(ml)
            key = self._derive(salt)
            try: mp = AESGCM(key).decrypt(mn, mct, None)
            except InvalidTag: raise ValueError("Hatalı şifre.")
            return json.loads(mp.decode())
        finally:
            if key is not None: del key
            self._cleanup()

    # ── Yeniden şifreleme (re-key) ─────────────────────────────────────
    def rekey_vault(self, vault: Path, new_password: str, cb=None) -> None:
        """Vault'u yeni şifre ile yeniden şifreler (şifre değiştirme)."""
        # 1. Eski şifre ile metadata + data oku
        if cb: cb(0.05, "Eski vault okunuyor…")
        with open(vault, "rb") as f:
            if f.read(6) != VAULT_MAGIC: raise ValueError("Geçersiz vault formatı.")
            salt = f.read(SALT_SIZE); mn = f.read(NONCE_SIZE)
            ml   = struct.unpack(">I", f.read(4))[0]; mct = f.read(ml)
            dn   = f.read(NONCE_SIZE); dct = f.read()
        key = self._derive(salt)
        gcm = AESGCM(key)
        try: mp = gcm.decrypt(mn, mct, None)
        except InvalidTag: raise ValueError("Eski şifre hatalı.")
        try: pt = gcm.decrypt(dn, dct, None)
        except InvalidTag: raise ValueError("Eski şifre hatalı (veri).")
        del key; self._cleanup()

        if cb: cb(0.40, "Yeni anahtar türetiliyor…")
        # 2. Yeni şifre ile yeniden şifrele
        new_engine = CryptoEngine(new_password)
        new_salt = secrets.token_bytes(SALT_SIZE)
        new_key  = new_engine._derive(new_salt)
        new_gcm  = AESGCM(new_key)

        # metadata güncelle
        md = json.loads(mp.decode())
        md["rekeyed_at"] = datetime.now().isoformat()
        new_mn  = secrets.token_bytes(NONCE_SIZE)
        new_mct = new_gcm.encrypt(new_mn, json.dumps(md, ensure_ascii=False).encode(), None)
        new_dn  = secrets.token_bytes(NONCE_SIZE)
        new_dct = new_gcm.encrypt(new_dn, pt, None)
        del pt, new_key

        if cb: cb(0.80, "Vault yeniden yazılıyor…")
        tmp = vault.with_suffix(".rekey.tmp")
        try:
            with open(tmp, "wb") as fo:
                fo.write(VAULT_MAGIC + new_salt + new_mn)
                fo.write(struct.pack(">I", len(new_mct)) + new_mct + new_dn + new_dct)
            # Atomik yeniden adlandır
            tmp.replace(vault)
        finally:
            if tmp.exists(): tmp.unlink()
            new_engine._cleanup()
        if cb: cb(1.0, "Tamamlandı.")

    # ── Bütünlük kontrolü (şifresiz) ───────────────────────────────────
    @staticmethod
    def verify_integrity(vault: Path) -> tuple[bool, str]:
        """
        Şifre gerekmeden temel bütünlük kontrolü.
        Döner: (geçerli_mi, açıklama)
        """
        try:
            sz = vault.stat().st_size
            min_sz = 6 + SALT_SIZE + NONCE_SIZE + 4 + 16 + NONCE_SIZE + 16
            if sz < min_sz:
                return False, f"Dosya çok küçük ({sz} byte < {min_sz} min)"
            with open(vault, "rb") as f:
                magic = f.read(6)
                if magic != VAULT_MAGIC:
                    return False, f"Geçersiz magic: {magic!r}"
                f.read(SALT_SIZE)
                f.read(NONCE_SIZE)
                ml = struct.unpack(">I", f.read(4))[0]
                if ml > sz: return False, f"Metadata boyutu geçersiz ({ml})"
            sha = hashlib.sha256(vault.read_bytes()).hexdigest()[:16]
            return True, f"Yapı geçerli · SHA256[16]: {sha} · {sz:,} byte"
        except Exception as e:
            return False, str(e)

# ── Deneme sınırlayıcı ────────────────────────────────────────────────────────
class AttemptLimiter:
    def __init__(self):
        self._lock = threading.Lock(); self._n = 0; self._until = 0.0

    def is_locked(self) -> tuple[bool, int]:
        with self._lock:
            r = self._until - time.time()
            return (True, int(r)+1) if r > 0 else (False, 0)

    def fail(self):
        with self._lock:
            self._n += 1
            if self._n >= MAX_ATTEMPTS:
                self._until = time.time() + LOCKOUT_SECS; self._n = 0

    def ok(self):
        with self._lock: self._n = 0; self._until = 0.0

    def remaining(self) -> int:
        with self._lock: return max(0, MAX_ATTEMPTS - self._n)

# ── İstatistik sayacı ─────────────────────────────────────────────────────────
class Stats:
    """Oturum istatistiklerini tutar."""
    def __init__(self):
        self.encrypted = 0; self.decrypted = 0; self.rekeyed = 0
        self.files_enc  = 0; self.bytes_enc  = 0; self.start  = time.time()

    def record_enc(self, file_count: int, orig_bytes: int):
        self.encrypted += 1; self.files_enc += file_count; self.bytes_enc += orig_bytes

    def record_dec(self): self.decrypted += 1
    def record_rekey(self): self.rekeyed += 1

    def uptime(self) -> str:
        s = int(time.time() - self.start)
        return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

SESSION = Stats()

# =============================================================================
#  GUI Bileşenleri
# =============================================================================

# ── Toast bildirimi ───────────────────────────────────────────────────────────
class _Toast:
    """Sağ altta beliren, otomatik kaybolan bildirim."""
    _active: list = []

    @classmethod
    def show(cls, root: tk.Tk, msg: str, kind: str = "info", duration: int = 3500):
        color = {"info": C["accent"], "success": C["green"],
                 "error": C["red"], "warn": C["orange"]}.get(kind, C["accent"])
        icon  = {"info": "◈", "success": "✓", "error": "✗", "warn": "⚠"}.get(kind, "◈")

        win = tk.Toplevel(root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=C["surface"])

        frame = tk.Frame(win, bg=C["surface"], highlightthickness=1,
                         highlightbackground=color)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text=f" {icon} ", bg=C["surface"], fg=color,
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=(15, 0), pady=12)
        tk.Label(frame, text=msg, bg=C["surface"], fg=C["text"],
                 font=("Segoe UI", 10), wraplength=260, justify="left").pack(
                     side="left", padx=(4, 16), pady=12)

        win.update_idletasks()
        W, H = win.winfo_width(), win.winfo_height()
        sw   = root.winfo_screenwidth(); sh = root.winfo_screenheight()

        # Stack: birden fazla toast üst üste gelmesin
        offset = sum(w.winfo_height() + 8 for w in cls._active if w.winfo_exists())
        x = sw - W - 20; y = sh - H - 60 - offset
        win.geometry(f"+{x}+{y}")
        cls._active.append(win)

        # Fade-out + destroy
        def _fade(alpha=1.0):
            if not win.winfo_exists(): return
            if alpha <= 0:
                try:
                    cls._active.remove(win)
                except ValueError: pass
                win.destroy(); return
            try: win.attributes("-alpha", alpha)
            except Exception: pass
            win.after(30, lambda: _fade(alpha - 0.07))

        win.after(duration, _fade)


# ── Temel girdi kutusu ────────────────────────────────────────────────────────
class _Entry(tk.Frame):
    """
    Tek kenarlıklı, focus-animasyonlu, placeholder destekli Entry.

    textvariable KULLANILMAZ — tüm okuma/yazma doğrudan tk.Entry
    metodları (get/delete/insert) ile yapılır.  Bu sayede placeholder
    ve gerçek değer hiçbir zaman karışmaz.

    Harici StringVar (var=) verilirse sadece dış kod değişkeni izlemek
    için kullanabilir; widget içi mantık ona bağlı değildir.
    """
    def __init__(self, master, var=None, placeholder="", show="", font_size=12, **kw):
        super().__init__(master, bg=C["surface"], highlightthickness=1,
                         highlightbackground=C["border"], highlightcolor=C["border_hi"])
        self._ph      = placeholder
        self._show    = show
        self._showing = False
        self._is_ph   = False

        self._e = tk.Entry(self,
                           bg=C["surface"], fg=C["text"],
                           insertbackground=C["accent"],
                           relief="flat", bd=0,
                           font=("Segoe UI", font_size),
                           show=show)
        self._e.pack(fill="both", expand=True, padx=12, pady=9)

        if placeholder:
            self._put_ph()

        self._e.bind("<FocusIn>",  self._fi)
        self._e.bind("<FocusOut>", self._fo)
        self._e.bind("<KeyPress>", self._fi)

    # ── placeholder yönetimi ─────────────────────────────────────────
    def _put_ph(self):
        self._is_ph = True
        self._e.config(show="", fg=C["text_dim"])
        self._e.delete(0, "end")          # önce tamamen temizle
        self._e.insert(0, self._ph)       # sonra placeholder yaz

    def _clr_ph(self):
        if self._is_ph:
            self._is_ph = False
            self._e.delete(0, "end")
            self._e.config(fg=C["text"],
                           show="" if self._showing else self._show)

    def _fi(self, _=None):
        try:
            if self.winfo_exists():
                self.config(highlightbackground=C["border_hi"])
        except Exception:
            pass
        self._clr_ph()

    def _fo(self, _=None):
        self.config(highlightbackground=C["border"])
        if not self._is_ph and not self._e.get():
            self._put_ph()

    # ── public API ──────────────────────────────────────────────────
    def get(self) -> str:
        return "" if self._is_ph else self._e.get()

    def set(self, v: str):
        try:
            # Önce mevcut placeholder durumunu temizle
            self._clr_ph()
            self._e.delete(0, "end")

            if v:
                self._e.insert(0, v)
                self._e.config(fg=C["text"],
                               show="" if self._showing else self._show)
            else:
                # Odak bizde değilse placeholder koy
                if self.focus_get() != self._e:
                    self._put_ph()
        except Exception:
            pass

    def toggle_show(self):
        if not self._show:
            return
        self._showing = not self._showing
        if not self._is_ph:
            self._e.config(show="" if self._showing else self._show)

    def bind_key(self, ev, cb):
        self._e.bind(ev, cb)

    def configure(self, **kw):
        if "state" in kw:
            self._e.configure(state=kw.pop("state"))
        if kw:
            super().configure(**kw)


class _PwdField(tk.Frame):
    """Şifre girişi + göster/gizle + opsiyonel güç çubuğu."""
    def __init__(self, master, var=None, placeholder="Şifre", show_strength=False, linked_bar=None, **kw):
        super().__init__(master, bg=C["surface"])
        row = tk.Frame(self, bg=C["surface"]); row.pack(fill="x")
        self._entry = _Entry(row, placeholder=placeholder, show="*")
        self._entry.pack(side="left", fill="x", expand=True)
        eye = tk.Label(row, text="👁", bg=C["surface"], fg=C["text_dim"],
                       font=("TkDefaultFont", 12), cursor="hand2", padx=9, pady=9)
        eye.pack(side="right")
        eye.bind("<Button-1>", lambda _: (self._entry.toggle_show(),
                                          eye.config(fg=C["accent"] if self._entry._showing else C["text_dim"])))
        eye.bind("<Enter>", lambda _: eye.config(fg=C["accent"]))
        eye.bind("<Leave>", lambda _: eye.config(fg=C["text_dim"] if not self._entry._showing else C["accent"]))

        self._bar = linked_bar
        if show_strength and not self._bar:
            self._bar = _StrBar(self); self._bar.pack(fill="x", pady=(4, 0))

        if self._bar:
            # Hem KeyRelease hem KeyPress (gecikmeli) ile daha hassas güncelleme
            self._entry._e.bind("<KeyRelease>", self._upd)
            self._entry._e.bind("<KeyPress>", lambda _: self.after(1, self._upd))
            self._entry._e.bind("<FocusIn>", self._upd, add=True)

    def _upd(self, *_):
        if not self.winfo_exists(): return
        try:
            v = self._entry.get()
            if not v:
                if self._bar: self._bar.set(None)
            else:
                if self._bar: self._bar.set(_zxcvbn_mod.zxcvbn(v)["score"])
        except Exception:
            pass

    def get(self): return self._entry.get()
    def set(self, v):
        try: self._entry.set(v)
        except Exception: pass
    def bind_return(self, cb): self._entry.bind_key("<Return>", cb)

    def winfo_exists(self):
        try: return super().winfo_exists()
        except: return False


class _StrBar(tk.Frame):
    COLS  = [None, None, None, None, None]   # filled at paint time
    LBLS  = ["Çok Zayıf", "Zayıf", "Orta", "Güçlü", "Çok Güçlü"]

    def __init__(self, master, **kw):
        super().__init__(master, bg=C["surface"])
        row = tk.Frame(self, bg=C["surface"]); row.pack(fill="x", pady=(3,1))
        self._segs = []
        for i in range(5):
            s = tk.Frame(row, height=3, bg=C["border"])
            s.pack(side="left", fill="x", expand=True, padx=(0, 2 if i<4 else 0))
            self._segs.append(s)
        self._lbl = tk.Label(self, text="", bg=C["surface"], fg=C["text_dim"],
                             font=("Segoe UI", 8), anchor="e")
        self._lbl.pack(fill="x")

    def _colors(self, score):
        return [C["red"], C["orange"], C["yellow"], C["green"], C["green"]][score]

    def set(self, score):
        if score is None:
            for s in self._segs: s.config(bg=C["border"])
            self._lbl.config(text=""); return
        c = self._colors(score)
        for i, s in enumerate(self._segs):
            s.config(bg=c if i <= score else C["border"])
        self._lbl.config(text=self.LBLS[score], fg=c)


class _ProgRow(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=C["surface"])
        self._tr = tk.Frame(self, bg=C["border"], height=2); self._tr.pack(fill="x")
        self._fi = tk.Frame(self._tr, bg=C["accent"], height=2)
        self._fi.place(x=0, y=0, relheight=1, relwidth=0)
        self._lb = tk.Label(self, text="", bg=C["surface"], fg=C["text_dim"],
                            font=("Segoe UI", 8), anchor="w")
        self._lb.pack(fill="x", pady=(2,0))

    def set(self, pct, msg=""):
        if not self.winfo_exists(): return
        pct = max(0., min(1., pct))
        try:
            self._fi.place(relwidth=pct)
            self._fi.config(bg=C["green"] if pct >= 1. else C["accent"])
            self._lb.config(text=msg, fg=C["green"] if pct >= 1. else C["text_dim"])
        except Exception: pass

    def reset(self): self.set(0, "")


class _Log(tk.Frame):
    def __init__(self, master, h=6, **kw):
        super().__init__(master, bg=C["surface"], highlightthickness=0)
        # Tek katman için koyu bir ton veya bg rengi
        log_bg = _adjust_color(C["bg"], -0.05)
        self._t = tk.Text(self, bg=log_bg, fg="#6a9a6a", font=FONT_MONO,
                          relief="flat", bd=0, height=h,
                          insertbackground=C["accent"], wrap="word",
                          selectbackground=C["accent_dim"])
        sb = tk.Scrollbar(self, orient="vertical", command=self._t.yview, width=7)
        self._t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", pady=1)
        self._t.pack(side="left", fill="both", expand=True, padx=8, pady=6)

    def write(self, msg):
        if not self.winfo_exists(): return
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            self._t.configure(state="normal")
            self._t.insert("end", f"[{ts}] {msg}\n")
            self._t.see("end"); self._t.configure(state="disabled")
        except Exception: pass

    def clear(self):
        if not self.winfo_exists(): return
        try: self._t.configure(state="normal"); self._t.delete("1.0","end"); self._t.configure(state="disabled")
        except Exception: pass

    def put(self, txt):
        if not self.winfo_exists(): return
        try:
            self._t.configure(state="normal"); self._t.delete("1.0","end")
            self._t.insert("end", txt); self._t.configure(state="disabled")
        except Exception: pass


class _PathPicker(tk.Frame):
    def __init__(self, master, ph="Yol seçin…", vault=False, dnd=False, **kw):
        super().__init__(master, bg=C["surface"])
        self._var = tk.StringVar(); self._vault = vault
        row = tk.Frame(self, bg=C["surface"]); row.pack(fill="x")
        self._e = _Entry(row, var=self._var, placeholder=ph)
        self._e.pack(side="left", fill="x", expand=True)
        btn = tk.Label(row, text="GÖZAT", bg=C["surface"], fg=C["accent"],
                       font=("Segoe UI", 9, "bold"), padx=14, pady=9, cursor="hand2")
        btn.pack(side="right", padx=(6,0))
        btn.bind("<Button-1>", lambda _: self._browse())
        btn.bind("<Enter>",    lambda _: btn.config(bg=C["accent_dim"]))
        btn.bind("<Leave>",    lambda _: btn.config(bg=C["surface"]))

        if dnd:
            dz = tk.Frame(self, bg=C["surface"], highlightthickness=1,
                          highlightbackground=C["border"], height=32)
            dz.pack(fill="x", pady=(4,0)); dz.pack_propagate(False)
            tk.Label(dz, text="↓  Sürükle & Bırak", bg=C["surface"],
                     fg=C["accent_dim"], font=("Segoe UI", 8)).place(relx=.5, rely=.5, anchor="center")
            try:
                dz.drop_target_register(DND_FILES)
                dz.dnd_bind("<<Drop>>", lambda e: self._set(e.data.strip("{}")))
            except Exception: pass

        self._recent_row = tk.Frame(self, bg=C["surface"]); self._recent_row.pack(fill="x", pady=(3,0))
        self._refresh_recent()

    def _set(self, p):
        self._e.set(p)       # _Entry.set() hem _real_val hem _is_ph'yi doğru günceller
        self._refresh_recent()

    def _browse(self):
        p = (filedialog.askopenfilename(filetypes=[("Vault", f"*{VAULT_EXTENSION}"), ("Tümü","*.*")])
             if self._vault else filedialog.askdirectory())
        if p: self._set(p)

    def _refresh_recent(self):
        for w in self._recent_row.winfo_children(): w.destroy()
        recent = get_recent(self._vault)[:4]
        if not recent: return
        tk.Label(self._recent_row, text="SON:", bg=C["surface"], fg=C["text_muted"],
                 font=("Segoe UI", 7, "bold")).pack(side="left")
        for p in recent:
            n = Path(p).name
            lb = tk.Label(self._recent_row, text=f"  {n}", bg=C["surface"],
                          fg=C["accent_dim"], font=("Segoe UI", 8), cursor="hand2")
            lb.pack(side="left")
            lb.bind("<Button-1>", lambda _, _p=p: self._set(_p))
            lb.bind("<Enter>",    lambda _, l=lb: l.config(fg=C["accent"]))
            lb.bind("<Leave>",    lambda _, l=lb: l.config(fg=C["accent_dim"]))

    def get(self): return self._e.get()


class _NavTab(tk.Frame):
    def __init__(self, master, text, icon, cmd, **kw):
        super().__init__(master, bg=C["bg"], cursor="hand2", highlightthickness=0)
        self._active = False; self._cmd = cmd
        self._ic = tk.Label(self, text=icon, bg=C["bg"], fg=C["text_dim"], font=("TkDefaultFont", 17))
        self._ic.pack(pady=(12,1))
        self._tx = tk.Label(self, text=text, bg=C["bg"], fg=C["text_dim"], font=("Segoe UI", 9, "bold"))
        self._tx.pack(pady=(0,3))
        self._bar = tk.Frame(self, height=2, bg=C["bg"]); self._bar.pack(fill="x")
        for w in (self, self._ic, self._tx, self._bar):
            w.bind("<Button-1>", lambda _: self._cmd())
            w.bind("<Enter>",    self._hin)
            w.bind("<Leave>",    self._hout)

    def _hin(self, _=None):
        if not self._active: self._tx.config(fg=C["text"]); self._ic.config(fg=C["text"])
    def _hout(self, _=None):
        if not self._active: self._tx.config(fg=C["text_dim"]); self._ic.config(fg=C["text_dim"])

    def activate(self, v):
        self._active = v
        c = C["accent_glow"] if v else C["text_dim"]
        self._bar.config(bg=C["accent"] if v else C["bg"])
        self._tx.config(fg=c); self._ic.config(fg=c)


class _Card(tk.Frame):
    def __init__(self, master, **kw):
        # Tek katmanlı yapı için çerçeveleri kaldırdık
        super().__init__(master, bg=C["surface"], highlightthickness=0, **kw)


class _Btn(tk.Frame):
    """Aksiyon butonu — accent veya danger."""
    def __init__(self, master, text, cmd, danger=False, small=False, **kw):
        fg   = C["red"] if danger else C["accent"]
        hov  = "#200808" if danger else C["accent_bg"]
        fnt  = ("Segoe UI", 10 if small else 11, "bold")
        pad  = (8, 6) if small else (13, 13)
        super().__init__(master, bg=C["surface"], highlightthickness=1,
                         highlightbackground=fg, cursor="hand2")
        self._cmd = cmd; self._fg = fg; self._hov = hov; self._bg = C["surface"]
        self._lbl = tk.Label(self, text=text, bg=C["surface"], fg=fg, font=fnt,
                             pady=pad[1], padx=pad[0])
        self._lbl.pack(fill="both", expand=True)
        for w in (self, self._lbl):
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>",    self._hin)
            w.bind("<Leave>",    self._hout)

    def _click(self, _=None):
        if str(self._lbl["state"]) != "disabled": self._cmd()

    def _hin(self, _=None):
        if str(self._lbl["state"]) != "disabled":
            self._lbl.config(bg=self._hov); self.config(bg=self._hov)

    def _hout(self, _=None):
        self._lbl.config(bg=self._bg); self.config(bg=self._bg)

    def configure(self, **kw):
        if not self.winfo_exists(): return
        st = kw.pop("state", None)
        if st:
            try:
                dis = st == "disabled"
                self._lbl.config(state=st, fg=C["text_muted"] if dis else self._fg)
                self.config(highlightbackground=C["text_muted"] if dis else self._fg,
                            cursor="" if dis else "hand2")
            except Exception: pass
        if kw:
            try: super().configure(**kw)
            except Exception: pass


# ── Şifre üretici yardımcı ────────────────────────────────────────────────────
def generate_password(length: int, upper: bool, digits: bool,
                      symbols: bool, exclude_ambiguous: bool) -> str:
    import string
    pool = string.ascii_lowercase
    if upper:   pool += string.ascii_uppercase
    if digits:  pool += string.digits
    if symbols: pool += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if exclude_ambiguous:
        for ch in "0O1lI|`": pool = pool.replace(ch, "")
    if not pool: pool = string.ascii_lowercase
    while True:
        pwd = "".join(secrets.choice(pool) for _ in range(length))
        ok = True
        if upper   and not any(c in string.ascii_uppercase for c in pwd): ok = False
        if digits  and not any(c in string.digits          for c in pwd): ok = False
        if symbols and not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd): ok = False
        if ok: return pwd

def password_entropy(pwd: str) -> float:
    if not pwd: return 0.0
    import string
    pool = 0
    if any(c in string.ascii_lowercase for c in pwd): pool += 26
    if any(c in string.ascii_uppercase for c in pwd): pool += 26
    if any(c in string.digits          for c in pwd): pool += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd): pool += 32
    if pool == 0: pool = 26
    return len(pwd) * math.log2(pool)


# =============================================================================
#  Ana GUI
# =============================================================================
class VaultGUI(tk.Tk):

    def __init__(self):
        super().__init__()
        # DnD
        self.dnd = False
        if HAS_DND:
            try: TkinterDnD._tags_install(self); self.tk.call("info","commands","tkdnd::drop_target"); self.dnd = True
            except Exception: pass

        self._q     = Queue()
        self._lim   = AttemptLimiter()
        self._tab   = 0
        self._logbox  = None
        self._progress = None

        self.title("RPM Encrypter  ///  AES-256-GCM")
        self.geometry("1060x740"); self.minsize(880, 620)
        self.configure(bg=C["bg"]); self.resizable(True, True)

        # Klavye kısayolları
        self.bind("<Control-e>", lambda _: self._switch(0))
        self.bind("<Control-d>", lambda _: self._switch(1))
        self.bind("<Control-i>", lambda _: self._switch(2))
        self.bind("<Control-k>", lambda _: self._switch(3))
        self.bind("<Control-g>", lambda _: self._switch(4))
        self.bind("<Control-b>", lambda _: self._switch(5))
        self.bind("<Control-s>", lambda _: self._switch(6))
        self.bind("<Control-q>", lambda _: self.destroy())

        self._build_chrome()
        self._switch(get_setting("start_tab", 0))
        self._poll()

    # ── Sayaç ────────────────────────────────────────────────────────────────
    def _poll(self):
        try:
            while True: self._q.get_nowait()()
        except Empty: pass
        self.after(40, self._poll)

    def _post(self, fn): self._q.put(fn)

    # ── Chrome (header + tabs + statusbar) ──────────────────────────────────
    def _build_chrome(self):
        # ── Header ────────────────────────────────────────────────────────
        self._hdr_frame = tk.Frame(self, bg=C["bg"]); self._hdr_frame.pack(fill="x")
        la  = tk.Frame(self._hdr_frame, bg=C["bg"]); la.pack(side="left", padx=(24,0), pady=(18,0))
        tk.Label(la, text="◈", bg=C["bg"], fg=C["accent"],
                 font=("Segoe UI", 20, "bold")).pack(side="left")
        self._hdr_title = tk.Label(la, text="  RPM Encrypter", bg=C["bg"], fg=C["text"],
                 font=("Segoe UI", 16, "bold")); self._hdr_title.pack(side="left")
        self._hdr_sub = tk.Label(la, text=f"  AES-256-GCM · ARGON2ID · V{APP_VERSION}",
                 bg=C["bg"], fg=C["text_muted"], font=("Segoe UI", 8)); self._hdr_sub.pack(side="left", pady=(5,0))

        ra = tk.Frame(self._hdr_frame, bg=C["bg"]); ra.pack(side="right", padx=24, pady=(18,0))
        self._clk = tk.Label(ra, bg=C["bg"], fg=C["text_muted"], font=("Segoe UI", 8))
        self._clk.pack(side="right", padx=(12,0))
        self._hdr_theme_lbl = tk.Label(ra, text="TEMA:", bg=C["bg"], fg=C["text_muted"],
                 font=("Courier", 7, "bold")); self._hdr_theme_lbl.pack(side="left")
        for name, th in THEMES.items():
            dot = tk.Frame(ra, width=10, height=10, bg=th["accent"], cursor="hand2")
            dot.pack(side="left", padx=3)
            dot.bind("<Button-1>", lambda _, n=name: self._theme(n))
            tk.Label(ra, text=name, bg=C["bg"], fg=th["accent"],
                     font=("Segoe UI", 8), cursor="hand2").pack(side="left")
            ra.children[list(ra.children)[-1]].bind("<Button-1>", lambda _, n=name: self._theme(n))

        self._tick()
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x", pady=(10,0))

        # ── Tabs ──────────────────────────────────────────────────────────
        self._tab_bar = tk.Frame(self, bg=C["bg"]); self._tab_bar.pack(fill="x")
        tab_defs = [
            ("Şifrele",  "⬡", 0, "Ctrl+E"),
            ("Çöz",      "⬢", 1, "Ctrl+D"),
            ("Bilgi",    "◎", 2, "Ctrl+I"),
            ("Re-Key",   "⟳", 3, "Ctrl+K"),
            ("Üretici",  "✦", 4, "Ctrl+G"),
            ("Toplu",    "⊞", 5, "Ctrl+B"),
            ("Görünüm",  "🎨", 6, "Özelleştir"),
            ("Ayarlar",  "⚙", 7, "Ctrl+S"),
        ]
        self._tabs: list[_NavTab] = []
        for name, icon, idx, tip in tab_defs:
            t = _NavTab(self._tab_bar, name, icon, lambda i=idx: self._switch(i))
            t.pack(side="left", padx=(24 if idx==0 else 0, 0), ipadx=16)
            self._tabs.append(t)
            # Tooltip
            self._bind_tooltip(t, tip)

        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        # ── İçerik alanı ─────────────────────────────────────────────────
        # Kaydırma için Canvas ve Scrollbar yapısı
        self._canvas_container = tk.Frame(self, bg=C["bg"])
        self._canvas_container.pack(fill="both", expand=True)

        self._canvas = tk.Canvas(self._canvas_container, bg=C["bg"], highlightthickness=0)
        self._vsb = tk.Scrollbar(self._canvas_container, orient="vertical", command=self._canvas.yview, width=10)
        self._vsb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
        self._canvas.configure(yscrollcommand=self._vsb.set)

        self._content = tk.Frame(self._canvas, bg=C["bg"])
        self._canvas_win = self._canvas.create_window((0, 0), window=self._content, anchor="nw")

        # İçerik değiştikçe kaydırma alanını güncelle
        self._content.bind("<Configure>", lambda _: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>", lambda e: self._canvas.itemconfig(self._canvas_win, width=e.width))
        self.bind_all("<MouseWheel>", self._on_mousewheel)

        # ── Status bar ────────────────────────────────────────────────────
        self._sb_frame = tk.Frame(self, bg=C["bg"], height=22)
        self._sb_frame.pack(fill="x", side="bottom"); self._sb_frame.pack_propagate(False)
        self._sb_left  = tk.Label(self._sb_frame, text="Hazır", bg=C["bg"],
                                  fg=C["text_muted"], font=("Segoe UI", 8), anchor="w")
        self._sb_left.pack(side="left", padx=12)
        self._sb_right = tk.Label(self._sb_frame, text="", bg=C["bg"],
                                  fg=C["text_muted"], font=("Segoe UI", 8), anchor="e")
        self._sb_right.pack(side="right", padx=12)
        self._tick_stats()

    def _on_mousewheel(self, event):
        # Fare tekerleği ile kaydırma (Windows için event.delta kullanılır)
        if self._canvas.winfo_exists():
            delta = int(-1 * (event.delta / 120))
            self._canvas.yview(tk.SCROLL, delta, "units")

    def _bind_tooltip(self, widget, text):
        tip = None
        def show(_):
            nonlocal tip
            x = widget.winfo_rootx(); y = widget.winfo_rooty() + widget.winfo_height()
            tip = tk.Toplevel(self); tip.overrideredirect(True)
            tip.geometry(f"+{x}+{y}")
            tk.Label(tip, text=text, bg=C["surface2"], fg=C["text_dim"],
                     font=("Segoe UI", 8), padx=6, pady=3).pack()
        def hide(_):
            nonlocal tip
            if tip:
                try: tip.destroy()
                except: pass
                tip = None
        widget.bind("<Enter>", show, add=True)
        widget.bind("<Leave>", hide, add=True)

    def _tick(self):
        self._clk.config(text=datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick)

    def _tick_stats(self):
        self._sb_right.config(
            text=f"⬡ {SESSION.encrypted} şifrelendi  ⬢ {SESSION.decrypted} çözüldü  "
                 f"⟳ {SESSION.rekeyed} re-key  ·  Çalışma: {SESSION.uptime()}")
        self.after(1000, self._tick_stats)

    def _theme(self, name):
        global C
        C.update(THEMES[name])
        
        # Özelleştirmeleri Uygula
        c_bg = get_setting("custom_bg")
        c_tx = get_setting("custom_text_color")
        c_ac = get_setting("custom_accent_color")
        
        if c_bg:
            C["bg"] = C["surface"] = C["surface2"] = c_bg
            C["border"] = _adjust_color(c_bg, 0.1)
        if c_tx:
            C["text"] = c_tx
            C["text_dim"] = _adjust_color(c_tx, -0.2)
            C["text_muted"] = _adjust_color(c_tx, -0.4) # Sönük yazıları da uyarla  
        if c_ac:
            C["accent"] = C["border_hi"] = c_ac
            C["accent_dim"] = _adjust_color(c_ac, -0.3)

        update_fonts()
        save_setting("theme", name)
        
        # Global renk güncellemeleri
        if hasattr(self, "_hdr_frame"): self._hdr_frame.configure(bg=C["bg"])
        if hasattr(self, "_tab_bar"): self._tab_bar.configure(bg=C["bg"])
        if hasattr(self, "_sb_frame"): self._sb_frame.configure(bg=C["bg"])
        
        self.configure(bg=C["bg"])

        # Sabit etiketleri güncelle (Header ve Status Bar)
        for attr in ["_hdr_title", "_hdr_sub", "_hdr_theme_lbl", "_clk", "_sb_left", "_sb_right"]:
            if hasattr(self, attr):
                lbl = getattr(self, attr)
                lbl.config(bg=C["bg"], fg=C["text"] if "title" in attr else C["text_muted"])

        if hasattr(self, "_canvas"): self._canvas.configure(bg=C["bg"])
        if hasattr(self, "_content"): self._content.configure(bg=C["bg"])
        self._switch(self._tab)

    def _switch(self, idx):
        self._tab = idx
        for i, t in enumerate(self._tabs): t.activate(i == idx)
        for w in self._content.winfo_children(): w.destroy()
        self._logbox = None; self._progress = None
        [self._pg_encrypt, self._pg_decrypt, self._pg_info,
         self._pg_rekey,   self._pg_generator, self._pg_batch,
         self._pg_customize, self._pg_settings][idx]()
        self._sb_left.config(text=["Şifrele","Çöz","Bilgi","Re-Key",
                                   "Şifre Üretici","Toplu İşlem","Özelleştir","Ayarlar"][idx])

    # ── Ortak yardımcılar ────────────────────────────────────────────────────
    def _post_log(self, msg): self._post(lambda m=msg: self._logbox and self._logbox.winfo_exists() and self._logbox.write(m))
    def _post_prog(self, p, m):
        self._post(lambda pp=p, mm=m: self._progress and self._progress.winfo_exists() and self._progress.set(pp, mm))
        self._post_log(f"[{int(p*100):3d}%]  {m}")

    def _card(self, lbl=None, parent=None):
        p = parent or self._content
        if lbl: tk.Label(p, text=lbl.upper(), bg=C["bg"], fg=C["accent"],
                         font=FONT_SUBHEAD).pack(anchor="w", padx=(25, 0), pady=(15,5))
        c = _Card(p); c.pack(fill="x", pady=(0,4)); return c

    def _pad(self, card, px=18, py=14):
        f = tk.Frame(card, bg=C["surface"]); f.pack(fill="both", expand=True, padx=px, pady=py); return f

    def _hdr(self, title, sub=""):
        # Başlıkları çok daha belirgin, merkezlenmiş ve büyük yaptık
        f = tk.Frame(self._content, bg=C["bg"])
        f.pack(fill="x", pady=(20, 30))
        tk.Label(f, text=title, bg=C["bg"], fg=C["accent"],
                 font=FONT_HEAD, justify="center").pack(anchor="center")
        if sub:
            tk.Label(f, text=sub.upper(), bg=C["bg"], fg=C["text_dim"],
                     font=(FONT_UI[0], FONT_UI[1], "bold")).pack(anchor="center", pady=(5,0))
        # Alt çizgi (merkezlenmiş)
        sep = tk.Frame(self._content, bg=C["border"], height=1)
        sep.pack(fill="x", padx=150, pady=(0, 25))
        # Ayırıcı çizgi
        tk.Frame(self._content, bg=C["border"], height=1).pack(fill="x", padx=100, pady=(0, 20))

    def _disable(self):
        for a in ("_enc_btn","_dec_btn","_rk_btn","_info_btn"):
            w = getattr(self, a, None)
            if w:
                try: w.configure(state="disabled")
                except: pass

    def _enable(self):
        for a in ("_enc_btn","_dec_btn","_rk_btn","_info_btn"):
            w = getattr(self, a, None)
            if w:
                try: w.configure(state="normal")
                except: pass

    def _toast(self, msg, kind="info"): _Toast.show(self, msg, kind)

    # =========================================================================
    #  Şifrele ekranı
    # =========================================================================
    def _pg_encrypt(self):
        self._hdr("KLASÖRÜ KİLİTLE", "AES-256-GCM + ARGON2ID")

        # Klasör
        c1 = self._card("Hedef Klasör"); p1 = self._pad(c1)
        self._enc_path = _PathPicker(p1, ph="Şifrelenecek klasör…", vault=False, dnd=self.dnd)
        self._enc_path.pack(fill="x")

        # Şifre satırı
        c2 = self._card("Şifre"); p2 = self._pad(c2)
        cols = tk.Frame(p2, bg=C["surface"]); cols.pack(fill="x")
        cols.columnconfigure(0, weight=1); cols.columnconfigure(1, weight=1)

        lc = tk.Frame(cols, bg=C["surface"]); lc.grid(row=0, column=0, sticky="ew", padx=(0,8))
        tk.Label(lc, text="Şifre", bg=C["surface"], fg=C["text_dim"], font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0,3))

        self._ep_bar = _StrBar(p2) # Kart geneline yayılacak bar
        self._ep = _PwdField(lc, placeholder="Şifrenizi girin", linked_bar=self._ep_bar)
        self._ep.pack(fill="x")

        rc = tk.Frame(cols, bg=C["surface"]); rc.grid(row=0, column=1, sticky="ew", padx=(8,0))
        tk.Label(rc, text="Onay", bg=C["surface"], fg=C["text_dim"], font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0,3))
        self._ec = _PwdField(rc, placeholder="Tekrar girin")
        self._ec.pack(fill="x")
        self._ec.bind_return(lambda _: self._do_enc())

        self._ep_bar.pack(fill="x", pady=(10, 0)) # Sütunların altına, tam genişlikte yerleştir

        # Eşleşme göstergesi — KeyRelease ile güncelle
        self._ematch = tk.Label(p2, text="", bg=C["surface"], fg=C["text_muted"], font=("Courier", 8))
        self._ematch.pack(anchor="w", pady=(4,0))
        self._ep._entry._e.bind("<KeyRelease>", self._enc_check)
        self._ec._entry._e.bind("<KeyRelease>", self._enc_check)

        # Seçenekler
        c3 = self._card("Seçenekler"); p3 = self._pad(c3, py=10)
        opt_row = tk.Frame(p3, bg=C["surface"]); opt_row.pack(fill="x")

        self._wipe_v = tk.BooleanVar(value=False)
        self._wipe_cb = self._checkbox(opt_row, "Güvenli Sil (orijinal dosyaları kalıcı sil)",
                                       self._wipe_v, danger=True)
        self._wipe_cb.pack(side="left")

        self._open_v = tk.BooleanVar(value=True)
        self._checkbox(opt_row, "  Tamamlanınca klasörü göster",
                       self._open_v).pack(side="left", padx=(24,0))

        self._warn_lbl = tk.Label(p3, text="", bg=C["surface"], fg=C["red"], font=("Segoe UI", 8))
        self._warn_lbl.pack(anchor="w")
        self._wipe_v.trace_add("write", lambda *_: self._warn_lbl.config(
            text="⚠  BU İŞLEM GERİ ALINAMAZ — orijinal dosyalar kalıcı silinir!" if self._wipe_v.get() else ""))

        # Aksiyon
        c4 = self._card(); p4 = self._pad(c4)
        self._enc_btn = _Btn(p4, "▶  ŞIFRELE  &  KİLİTLE", self._do_enc)
        self._enc_btn.pack(fill="x")
        self._progress = _ProgRow(p4); self._progress.pack(fill="x", pady=(10,0))
        self._logbox   = _Log(p4, h=5);  self._logbox.pack(fill="x",  pady=(8,0))

    def _checkbox(self, parent, text, var, danger=False):
        f = tk.Frame(parent, bg=C["surface"], cursor="hand2")
        cv = tk.Canvas(f, width=16, height=16, bg=C["surface"], highlightthickness=0)
        cv.pack(side="left")
        tk.Label(f, text=text, bg=C["surface"],
                 fg=C["red"] if danger else C["text_dim"],
                 font=("Segoe UI", 9)).pack(side="left")
        def _draw():
            cv.delete("all")
            cv.create_rectangle(1,1,15,15, outline=C["accent_dim"], fill=C["surface"])
            if var.get():
                cv.create_line(3,8,7,13,fill=C["accent"],width=2)
                cv.create_line(7,13,13,4,fill=C["accent"],width=2)
        def _tog(_=None): var.set(not var.get()); _draw()
        cv.bind("<Button-1>", _tog); f.bind("<Button-1>", _tog)
        var.trace_add("write", lambda *_: _draw()); _draw()
        return f

    def _enc_check(self, *_):
        p = self._ep.get(); c = self._ec.get()
        if not hasattr(self, "_ematch") or not self._ematch.winfo_exists(): return
        if p and c:
            match = p == c
            self._ematch.config(text="✓ Şifreler eşleşiyor" if match else "✗ Şifreler eşleşmiyor",
                                fg=C["green"] if match else C["red"])
        else:
            self._ematch.config(text="")

    def _do_enc(self):
        folder_s = self._enc_path.get().strip()
        pwd      = self._ep.get(); conf = self._ec.get()
        if not folder_s: return self._toast("Lütfen bir klasör seçin.", "error")
        if not pwd.strip(): return self._toast("Şifre boş olamaz.", "error")
        if len(pwd) < MIN_PWD_LEN: return self._toast(f"Şifre en az {MIN_PWD_LEN} karakter olmalı.", "error")
        if pwd != conf: return self._toast("Şifreler eşleşmiyor!", "error")
        folder = Path(folder_s)
        if not folder.is_dir(): return self._toast("Geçerli bir klasör seçin.", "error")
        out = folder.with_suffix(VAULT_EXTENSION)
        if out.exists():
            if not messagebox.askyesno("Üzerine Yaz?", f"{out.name} zaten var.\nÜzerine yazılsın mı?"): return

        self._disable(); self._progress.reset(); self._logbox.clear()
        do_wipe = self._wipe_v.get(); do_open = self._open_v.get()
        save_recent(str(folder), False)

        def _work():
            try:
                st = CryptoEngine(pwd).encrypt_folder(folder, out, cb=self._post_prog)
                SESSION.record_enc(st["file_count"], st["original_size"])
                if do_wipe:
                    self._post_log("Güvenli silme başlatıldı…")
                    fails = SecureWiper.wipe_folder(folder)
                    if fails: self._post_log(f"⚠ {len(fails)} dosya silinemedi")
                save_recent(str(out), True)
                def _fin():
                    if not self.winfo_exists(): return
                    self._toast(f"✓ {out.name} oluşturuldu  ({st['vault_size']//1024:,} KB)", "success")
                    if do_open and out.parent.exists(): open_folder(out.parent)
                self._post(_fin)
            except Exception as exc:
                self._post(lambda e=exc: self._toast(str(e), "error"))
            finally:
                self._post(lambda: self._ep.set(""))
                self._post(lambda: self._ec.set(""))
                self._post(self._enable)
        threading.Thread(target=_work, daemon=True).start()

    # =========================================================================
    #  Çöz ekranı
    # =========================================================================
    def _pg_decrypt(self):
        self._hdr("VAULT'U AÇ", "Kimlik Doğrulamalı Şifre Çözme")

        c1 = self._card("Vault Dosyası"); p1 = self._pad(c1)
        self._dec_path = _PathPicker(p1, ph=".vault dosyasını seçin…", vault=True, dnd=self.dnd)
        self._dec_path.pack(fill="x")

        c2 = self._card("Şifre"); p2 = self._pad(c2)
        self._dp = _PwdField(p2, placeholder="Vault şifresini girin")
        self._dp.pack(fill="x")
        self._dp.bind_return(lambda _: self._do_dec())

        # Deneme göstergesi
        att_row = tk.Frame(p2, bg=C["surface"]); att_row.pack(fill="x", pady=(6,0))
        tk.Label(att_row, text="KALAN DENEME", bg=C["surface"], fg=C["text_muted"],
                 font=("Segoe UI", 7, "bold")).pack(side="left")
        self._dot_f = tk.Frame(att_row, bg=C["surface"]); self._dot_f.pack(side="left", padx=(8,0))
        self._dots = []
        for _ in range(MAX_ATTEMPTS):
            d = tk.Canvas(self._dot_f, width=9, height=9, bg=C["surface"], highlightthickness=0)
            d.pack(side="left", padx=2)
            d.create_oval(1,1,8,8,fill=C["accent"],outline=""); self._dots.append(d)
        self._lock_lbl = tk.Label(att_row, text="", bg=C["surface"], fg=C["red"], font=("Segoe UI", 8))
        self._lock_lbl.pack(side="right")
        self._upd_dots(MAX_ATTEMPTS)

        # Seçenek: çıkış klasörü
        c_opt = self._card("Çıkış Klasörü"); p_opt = self._pad(c_opt, py=10)
        opt2 = tk.Frame(p_opt, bg=C["surface"]); opt2.pack(fill="x")
        self._custom_out_v = tk.BooleanVar(value=False)
        self._checkbox(opt2, "Özel çıkış klasörü belirle", self._custom_out_v).pack(side="left")
        self._out_path_row = tk.Frame(p_opt, bg=C["surface"]); self._out_path_row.pack(fill="x", pady=(6,0))
        self._dec_out = _PathPicker(self._out_path_row, ph="Çıkış klasörü", vault=False)
        self._custom_out_v.trace_add("write", lambda *_: (
            self._dec_out.pack(fill="x") if self._custom_out_v.get() else self._dec_out.pack_forget()))
        self._dec_out.pack_forget()

        c3 = self._card(); p3 = self._pad(c3)
        self._dec_btn = _Btn(p3, "▶  ÇÖZ  &  AÇ", self._do_dec)
        self._dec_btn.pack(fill="x")
        self._progress = _ProgRow(p3); self._progress.pack(fill="x", pady=(10,0))
        self._logbox   = _Log(p3, h=5);  self._logbox.pack(fill="x",  pady=(8,0))

    def _upd_dots(self, rem):
        if not hasattr(self, "_dots"): return
        for i, d in enumerate(self._dots):
            if not d.winfo_exists(): continue
            d.delete("all")
            c = (C["accent"] if rem > 2 else (C["orange"] if rem > 1 else C["red"])) if i < rem else C["text_muted"]
            d.create_oval(1,1,8,8,fill=c,outline="")

    def _do_dec(self):
        vault_s = self._dec_path.get().strip(); pwd = self._dp.get()
        if not vault_s: return self._toast("Vault dosyası seçin.", "error")
        if not pwd.strip(): return self._toast("Şifre boş.", "error")
        lk, rs = self._lim.is_locked()
        if lk: return self._toast(f"Hesap kilitli. {rs}s bekleyin.", "warn")
        vault = Path(vault_s)
        if not vault.exists(): return self._toast("Vault dosyası bulunamadı.", "error")

        out_dir = vault.parent / f"{vault.stem}_unlocked"
        if self._custom_out_v.get() and self._dec_out.get().strip():
            out_dir = Path(self._dec_out.get().strip())

        self._disable(); self._progress.reset(); self._logbox.clear()
        save_recent(vault_s, True)

        def _work():
            try:
                md = CryptoEngine(pwd).decrypt_vault(vault, out_dir, cb=self._post_prog)
                self._lim.ok(); SESSION.record_dec()
                dest = Path(md.get("extracted_to", str(out_dir)))
                def _fin():
                    if not self.winfo_exists(): return
                    self._upd_dots(MAX_ATTEMPTS)
                    self._lock_lbl.config(text="")
                    self._toast(f"✓ {dest.name} açıldı  ({md.get('file_count','?')} dosya)", "success")
                    if messagebox.askyesno("Tamamlandı",
                        f"Vault çözüldü!\n\n  Klasör: {md.get('folder_name','—')}\n"
                        f"  Dosya sayısı: {md.get('file_count','?')}\n\n"
                        "Klasörü açmak ister misiniz?", parent=self):
                        open_folder(dest)
                self._post(_fin)
            except ValueError as exc:
                self._lim.fail(); ra = self._lim.remaining(); lk2, rs2 = self._lim.is_locked()
                def _ef(e=exc, lk=lk2, rs=rs2, ra=ra):
                    self._upd_dots(0 if lk else ra)
                    self._toast(str(e), "error")
                    if lk:
                        self._lock_lbl.config(text=f"🔒 {rs}s")
                        self._post(self._start_countdown)
                    else:
                        self._lock_lbl.config(text=f"{ra} deneme kaldı")
                self._post(_ef)
            except Exception as exc:
                self._post(lambda e=exc: self._toast(str(e), "error"))
            finally:
                self._post(lambda: self._dp.set(""))
                self._post(self._enable)
        threading.Thread(target=_work, daemon=True).start()

    def _start_countdown(self):
        def _tick():
            lk, r = self._lim.is_locked()
            if lk:
                try:
                    if hasattr(self,"_lock_lbl") and self._lock_lbl.winfo_exists():
                        self._lock_lbl.config(text=f"🔒 {r}s")
                except: pass
                self.after(1000, _tick)
            else:
                try:
                    if hasattr(self,"_lock_lbl") and self._lock_lbl.winfo_exists():
                        self._lock_lbl.config(text="")
                    self._upd_dots(MAX_ATTEMPTS)
                except: pass
        self.after(1000, _tick)

    # =========================================================================
    #  Bilgi ekranı
    # =========================================================================
    def _pg_info(self):
        self._hdr("VAULT BİLGİ", "Şifreli Metadata + Bütünlük Kontrolü")

        c1 = self._card("Vault Dosyası"); p1 = self._pad(c1)
        self._info_path = _PathPicker(p1, ph=".vault dosyasını seçin…", vault=True, dnd=self.dnd)
        self._info_path.pack(fill="x")

        # Bütünlük kontrolü (şifresiz)
        c_int = self._card("Hızlı Kontrol (Şifresiz)"); p_int = self._pad(c_int, py=10)
        int_row = tk.Frame(p_int, bg=C["surface"]); int_row.pack(fill="x")
        _Btn(int_row, "◉  BÜTÜNLÜK KONTROL", self._do_integrity, small=True).pack(side="left")
        self._int_lbl = tk.Label(int_row, text="", bg=C["surface"], fg=C["text_dim"],
                                 font=("Segoe UI", 9), anchor="w")
        self._int_lbl.pack(side="left", padx=12)

        # Güvenli silme butonu
        _Btn(int_row, "🗑  VAULT'U GÜVENLİ SİL",
             self._do_wipe_vault, danger=True, small=True).pack(side="right")

        c2 = self._card("Şifre"); p2 = self._pad(c2)
        self._ip = _PwdField(p2, placeholder="Metadata için şifre girin")
        self._ip.pack(fill="x")
        self._ip.bind_return(lambda _: self._do_info())

        c3 = self._card(); p3 = self._pad(c3, py=10)
        self._info_btn = _Btn(p3, "◎  METADATA'YI OKU", self._do_info)
        self._info_btn.pack(fill="x")

        # Sonuç paneli
        tk.Label(self._content, text="VAULT İÇERİĞİ", bg=C["bg"], 
                 fg=C["accent"], font=FONT_SUBHEAD).pack(anchor="w", padx=(25, 0), pady=(15,5))
        res = _Card(self._content); res.pack(fill="both", expand=True)
        rp  = tk.Frame(res, bg=C["surface"]); rp.pack(fill="both", expand=True, padx=18, pady=14)
        rp.columnconfigure(0, weight=1); rp.columnconfigure(1, weight=2); rp.rowconfigure(0, weight=1)

        # Sol: scrollable stat tiles
        lo = tk.Frame(rp, bg=C["surface"]); lo.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        lo.rowconfigure(0, weight=1); lo.columnconfigure(0, weight=1)
        sc = tk.Canvas(lo, bg=C["surface"], highlightthickness=0, bd=0)
        ssb = tk.Scrollbar(lo, orient="vertical", command=sc.yview,
                           bg=C["surface2"], troughcolor=C["bg"], width=6, relief="flat")
        sc.configure(yscrollcommand=ssb.set)
        ssb.grid(row=0, column=1, sticky="ns")
        sc.grid(row=0, column=0, sticky="nsew")
        self._stat_frame = tk.Frame(sc, bg=C["surface"])
        win_id = sc.create_window((0,0), window=self._stat_frame, anchor="nw")
        self._stat_frame.bind("<Configure>", lambda _: sc.configure(scrollregion=sc.bbox("all")))
        sc.bind("<Configure>", lambda e: sc.itemconfig(win_id, width=e.width))
        for ev in ("<MouseWheel>","<Button-4>","<Button-5>"):
            sc.bind(ev, lambda e, s=sc: s.yview_scroll(-1 if (e.delta>0 or e.num==4) else 1, "units"))

        # Sağ: dosya listesi
        ri = tk.Frame(rp, bg=C["surface"]); ri.grid(row=0, column=1, sticky="nsew")
        fhdr = tk.Frame(ri, bg=C["surface"]); fhdr.pack(fill="x", pady=(0,5))
        tk.Label(fhdr, text="DOSYA LİSTESİ", bg=C["surface"], fg=C["text_dim"],
                 font=("Segoe UI", 7, "bold")).pack(side="left")
        self._copy_btn = tk.Label(fhdr, text="[ KOPYALA ]", bg=C["surface"],
                                  fg=C["accent_dim"], font=("Courier", 8), cursor="hand2")
        self._copy_btn.pack(side="right")
        self._copy_btn.bind("<Button-1>", self._copy_list)
        self._copy_btn.bind("<Enter>", lambda _: self._copy_btn.config(fg=C["accent"]))
        self._copy_btn.bind("<Leave>", lambda _: self._copy_btn.config(fg=C["accent_dim"]))
        self._info_log = _Log(ri, h=14); self._info_log.pack(fill="both", expand=True)
        self._info_log.put("Vault seçin ve şifrenizi girerek metadata'yı görüntüleyin.")
        self._info_files: list = []
        self._render_tiles(None)

    def _do_integrity(self):
        v = self._info_path.get().strip()
        if not v: return self._toast("Vault dosyası seçin.", "error")
        vault = Path(v)
        if not vault.exists(): return self._toast("Dosya bulunamadı.", "error")
        ok, msg = CryptoEngine.verify_integrity(vault)
        if hasattr(self, "_int_lbl") and self._int_lbl.winfo_exists():
            self._int_lbl.config(text=msg, fg=C["green"] if ok else C["red"])
        self._toast(msg, "success" if ok else "error")

    def _do_wipe_vault(self):
        v = self._info_path.get().strip()
        if not v: return self._toast("Vault dosyası seçin.", "error")
        vault = Path(v)
        if not vault.exists(): return self._toast("Dosya bulunamadı.", "error")
        if not messagebox.askyesno("Güvenli Sil",
            f"{vault.name}\n\nBu vault dosyası kalıcı olarak silinecek!\nEmin misiniz?",
            parent=self): return
        ok = SecureWiper.wipe_file(vault)
        self._toast(f"{'✓ Silindi' if ok else '✗ Silinemedi'}: {vault.name}",
                    "success" if ok else "error")

    def _copy_list(self, _=None):
        if self._info_files:
            self.clipboard_clear(); self.clipboard_append("\n".join(self._info_files)); self.update()
            self._copy_btn.config(text="[ KOPYALANDI ✓ ]", fg=C["green"])
            self.after(2000, lambda: self._copy_btn.config(text="[ KOPYALA ]", fg=C["accent_dim"]))

    def _tile(self, parent, label, value, color=None):
        if not parent.winfo_exists(): return
        color = color or C["text"]
        t = tk.Frame(parent, bg=C["surface2"], highlightthickness=1, highlightbackground=C["border"])
        t.pack(fill="x", pady=2)
        inner = tk.Frame(t, bg=C["surface2"]); inner.pack(fill="both", padx=12, pady=8)
        k = tk.Label(inner, text=label, bg=C["surface2"], fg=C["text_muted"], font=("Segoe UI", 7,"bold"))
        k.pack(anchor="w")
        v = tk.Label(inner, text=value, bg=C["surface2"], fg=color, font=("Segoe UI", 12,"bold"))
        v.pack(anchor="w")
        def _fwd(e):
            try:
                cv = parent.master
                if hasattr(cv,"yview_scroll"): cv.yview_scroll(-1 if (e.delta>0 or e.num==4) else 1,"units")
            except: pass
        for w in (t, inner, k, v):
            w.bind("<MouseWheel>", _fwd); w.bind("<Button-4>", _fwd); w.bind("<Button-5>", _fwd)

    def _render_tiles(self, meta):
        if not hasattr(self,"_stat_frame") or not self._stat_frame.winfo_exists(): return
        for w in self._stat_frame.winfo_children(): w.destroy()
        if meta is None:
            for lb in ["KLASÖR","TARİH","DOSYA SAYISI","ORJ. BOYUT","VAULT BOYUTU","SIKIŞTIRMA","VERSİYON"]:
                self._tile(self._stat_frame, lb, "—")
            return
        vsz = meta.get("_vault_kb", 0); osz = meta.get("original_size", 0) // 1024
        ratio = ((1 - vsz/osz)*100) if osz > 0 and vsz > 0 else None
        cr = meta.get("created_at","—")
        try: cr = datetime.fromisoformat(cr).strftime("%d.%m.%Y  %H:%M")
        except: pass
        a2 = meta.get("argon2", {}); a2_str = (f"T={a2.get('time_cost','?')}  M={a2.get('memory_cost','?')}  P={a2.get('parallelism','?')}") if a2 else "—"
        rk = meta.get("rekeyed_at"); rk_str = "—"
        if rk:
            try: rk_str = datetime.fromisoformat(rk).strftime("%d.%m.%Y  %H:%M")
            except: rk_str = rk[:19]
        tiles = [
            ("KLASÖR ADI",    meta.get("folder_name","—"),              C["accent_glow"]),
            ("OLUŞTURULMA",   cr,                                        C["text"]),
            ("DOSYA SAYISI",  str(meta.get("file_count","?")),           C["green"]),
            ("ORJ. BOYUT",    f"{osz:,} KB",                             C["text"]),
            ("VAULT BOYUTU",  f"{vsz:,} KB",                             C["text"]),
            ("SIKIŞTIRMA",    f"%{ratio:.1f}" if ratio else "—",
             C["green"] if (ratio or 0) > 0 else C["orange"]),
            ("VERSİYON",      meta.get("version","—"),                   C["text_dim"]),
            ("ARGON2 PAR.",   a2_str,                                    C["text_dim"]),
            ("SON RE-KEY",    rk_str,                                    C["cyan"]),
        ]
        for l, v, c in tiles: self._tile(self._stat_frame, l, v, c)

    def _do_info(self):
        vs = self._info_path.get().strip(); pwd = self._ip.get()
        if not vs: return self._toast("Vault dosyası seçin.", "error")
        if not pwd.strip(): return self._toast("Şifre boş.", "error")
        lk, rs = self._lim.is_locked()
        if lk: return self._toast(f"Hesap kilitli. {rs}s bekleyin.", "warn")
        vault = Path(vs)
        if not vault.exists(): return self._toast("Dosya bulunamadı.", "error")
        self._info_btn.configure(state="disabled")
        self._info_log.put("Okunuyor…"); self._render_tiles(None)
        save_recent(vs, True)

        def _work():
            try:
                md = CryptoEngine(pwd).read_metadata(vault)
                self._lim.ok()
                md["_vault_kb"] = vault.stat().st_size // 1024
                files = md.get("file_names", []); self._info_files = files
                lines = [f"  {i+1:4}.  {fn}" for i,fn in enumerate(files[:300])]
                if len(files) > 300: lines.append(f"\n  … {len(files)-300} dosya daha")
                txt = "\n".join(lines) or "(boş)"
                def _fin():
                    if not self.winfo_exists(): return
                    self._render_tiles(md); self._info_log.put(txt)
                    self._toast(f"✓ {md.get('file_count','?')} dosya · {md.get('folder_name','—')}", "success")
                self._post(_fin)
            except ValueError as exc:
                self._lim.fail()
                self._post(lambda e=exc: (self._toast(str(e), "error"),
                                          self._info_log.put(f"HATA: {e}")))
            except Exception as exc:
                self._post(lambda e=exc: self._toast(str(e), "error"))
            finally:
                self._post(lambda: self._ip.set(""))
                self._post(lambda: self._info_btn.configure(state="normal"))
        threading.Thread(target=_work, daemon=True).start()

    # =========================================================================
    #  Re-Key ekranı
    # =========================================================================
    def _pg_rekey(self):
        self._hdr("ŞİFRE DEĞİŞTİR (RE-KEY)", "Vault'u Yeni Şifreyle Yeniden Şifrele")

        c1 = self._card("Vault Dosyası"); p1 = self._pad(c1)
        self._rk_path = _PathPicker(p1, ph=".vault dosyasını seçin…", vault=True, dnd=self.dnd)
        self._rk_path.pack(fill="x")

        c2 = self._card("Eski Şifre"); p2 = self._pad(c2)
        self._rk_old = _PwdField(p2, placeholder="Mevcut şifreyi girin")
        self._rk_old.pack(fill="x")

        c3 = self._card("Yeni Şifre"); p3 = self._pad(c3)
        cols = tk.Frame(p3, bg=C["surface"]); cols.pack(fill="x")
        cols.columnconfigure(0, weight=1); cols.columnconfigure(1, weight=1)
        lc = tk.Frame(cols, bg=C["surface"]); lc.grid(row=0, column=0, sticky="ew", padx=(0,8))
        tk.Label(lc, text="Yeni Şifre", bg=C["surface"], fg=C["text_muted"],
                 font=("Segoe UI", 8,"bold")).pack(anchor="w", pady=(0,3))

        self._rk_bar = _StrBar(p3) # Kart geneline yayılacak bar
        self._rk_new = _PwdField(lc, placeholder="Yeni şifre", linked_bar=self._rk_bar)
        self._rk_new.pack(fill="x")

        rc = tk.Frame(cols, bg=C["surface"]); rc.grid(row=0, column=1, sticky="ew", padx=(8,0))
        tk.Label(rc, text="Onay", bg=C["surface"], fg=C["text_muted"],
                 font=("Segoe UI", 8,"bold")).pack(anchor="w", pady=(0,3))
        self._rk_conf = _PwdField(rc, placeholder="Yeni şifreyi tekrar girin")
        self._rk_conf.pack(fill="x")
        self._rk_conf.bind_return(lambda _: self._do_rekey())

        self._rk_bar.pack(fill="x", pady=(10, 0)) # Sütunların altına, tam genişlikte yerleştir

        c4 = self._card(); p4 = self._pad(c4)
        self._rk_btn = _Btn(p4, "⟳  ŞİFREYİ DEĞİŞTİR", self._do_rekey)
        self._rk_btn.pack(fill="x")
        self._progress = _ProgRow(p4); self._progress.pack(fill="x", pady=(10,0))
        self._logbox   = _Log(p4, h=4);  self._logbox.pack(fill="x",  pady=(8,0))

        # Uyarı notu
        tk.Label(p4, text="⚠  Re-Key işlemi vault dosyasını yerinde değiştirir. "
                           "Önemli vault'ları işlemden önce yedekleyin.",
                 bg=C["surface"], fg=C["orange"], font=("Segoe UI", 8),
                 wraplength=700, justify="left").pack(anchor="w", pady=(8,0))

    def _do_rekey(self):
        vs = self._rk_path.get().strip()
        old = self._rk_old.get(); new = self._rk_new.get(); conf = self._rk_conf.get()
        if not vs:  return self._toast("Vault dosyası seçin.", "error")
        if not old: return self._toast("Eski şifre boş.", "error")
        if not new: return self._toast("Yeni şifre boş.", "error")
        if len(new) < MIN_PWD_LEN: return self._toast(f"Yeni şifre en az {MIN_PWD_LEN} karakter olmalı.", "error")
        if new != conf: return self._toast("Yeni şifreler eşleşmiyor!", "error")
        if old == new: return self._toast("Yeni şifre eski şifre ile aynı.", "warn")
        vault = Path(vs)
        if not vault.exists(): return self._toast("Vault bulunamadı.", "error")

        self._rk_btn.configure(state="disabled")
        self._progress.reset(); self._logbox.clear()

        def _work():
            try:
                CryptoEngine(old).rekey_vault(vault, new, cb=self._post_prog)
                SESSION.record_rekey()
                self._post(lambda: self._toast("✓ Şifre başarıyla değiştirildi!", "success"))
            except Exception as exc:
                self._post(lambda e=exc: self._toast(str(e), "error"))
            finally:
                self._post(lambda: self._rk_old.set(""))
                self._post(lambda: self._rk_new.set(""))
                self._post(lambda: self._rk_conf.set(""))
                self._post(lambda: self._rk_btn.configure(state="normal"))
        threading.Thread(target=_work, daemon=True).start()

    # =========================================================================
    #  Şifre Üretici ekranı
    # =========================================================================
    def _pg_generator(self):
        self._hdr("ŞİFRE ÜRETİCİ", "Kriptografik Güvenli Rastgele Şifre")

        # Ayarlar kartı
        c1 = self._card("Parametreler"); p1 = self._pad(c1)

        # Uzunluk
        len_row = tk.Frame(p1, bg=C["surface"]); len_row.pack(fill="x", pady=(0,8))
        tk.Label(len_row, text="UZUNLUK", bg=C["surface"], fg=C["text_dim"],
                 font=("Segoe UI", 8,"bold")).pack(side="left")
        self._gen_len_v = tk.IntVar(value=24)
        self._gen_len_lbl = tk.Label(len_row, text="24", bg=C["surface"], fg=C["accent"],
                                     font=("Segoe UI", 11,"bold"), width=3)
        self._gen_len_lbl.pack(side="right")
        sc = tk.Scale(len_row, from_=8, to=128, orient="horizontal",
                      variable=self._gen_len_v,
                      bg=C["surface"], fg=C["accent"], troughcolor=C["border"],
                      highlightthickness=0, bd=0, showvalue=False,
                      command=lambda v: self._gen_len_lbl.config(text=str(int(float(v)))))
        sc.pack(side="right", fill="x", expand=True, padx=(12,8))

        # Karakter seçenekleri
        opt_row = tk.Frame(p1, bg=C["surface"]); opt_row.pack(fill="x")
        self._gen_upper  = tk.BooleanVar(value=True)
        self._gen_digits = tk.BooleanVar(value=True)
        self._gen_sym    = tk.BooleanVar(value=True)
        self._gen_noamb  = tk.BooleanVar(value=False)
        self._checkbox(opt_row, "Büyük harf (A-Z)",          self._gen_upper).pack(side="left", padx=(0,16))
        self._checkbox(opt_row, "Rakam (0-9)",                self._gen_digits).pack(side="left", padx=(0,16))
        self._checkbox(opt_row, "Semboller (!@#…)",           self._gen_sym).pack(side="left", padx=(0,16))
        self._checkbox(opt_row, "Belirsiz karakter hariç",    self._gen_noamb).pack(side="left")

        # Üretilen şifre gösterimi
        c2 = self._card("Üretilen Şifre"); p2 = self._pad(c2)
        pwd_row = tk.Frame(p2, bg=C["surface"]); pwd_row.pack(fill="x")
        self._gen_out = tk.Text(pwd_row, bg=C["surface2"], fg=C["accent_glow"],
                                font=FONT_MONO,
                                height=2, relief="flat", bd=0,
                                insertbackground=C["accent"],
                                selectbackground=C["accent_dim"],
                                wrap="word")
        self._gen_out.pack(side="left", fill="x", expand=True, padx=12, pady=10)
        self._gen_out.configure(state="disabled")

        btn_col = tk.Frame(pwd_row, bg=C["surface"]); btn_col.pack(side="right", padx=(0,4))
        _Btn(btn_col, "↺", self._gen_generate, small=True).pack(fill="x", pady=(0,4))
        _Btn(btn_col, "⎘", self._gen_copy,     small=True).pack(fill="x")

        # Güç ve entropi
        c3 = self._card("Güç & Entropi"); p3 = self._pad(c3, py=10)
        self._gen_str_bar = _StrBar(p3); self._gen_str_bar.pack(fill="x")

        ent_row = tk.Frame(p3, bg=C["surface"]); ent_row.pack(fill="x", pady=(6,0))
        tk.Label(ent_row, text="ENTROPİ (bit):", bg=C["surface"], fg=C["text_dim"],
                 font=("Segoe UI", 8,"bold")).pack(side="left")
        self._gen_ent_lbl = tk.Label(ent_row, text="—", bg=C["surface"],
                                     fg=C["cyan"], font=("Segoe UI", 11,"bold"))
        self._gen_ent_lbl.pack(side="left", padx=(8,0))
        tk.Label(ent_row, text="  ≥128 bit önerilen", bg=C["surface"],
                 fg=C["text_muted"], font=("Segoe UI", 8)).pack(side="left")

        # Geçmiş
        c4 = self._card("Son Üretilen Şifreler (oturum)"); p4 = self._pad(c4, py=8)
        self._gen_hist = _Log(p4, h=5); self._gen_hist.pack(fill="x")

        # Büyük "Üret" butonu
        c5 = self._card(); p5 = self._pad(c5)
        _Btn(p5, "✦  YENİ ŞİFRE ÜRET", self._gen_generate).pack(fill="x")

        self._gen_history: list[str] = []
        self._gen_generate()

    def _gen_generate(self):
        try:
            pwd = generate_password(
                self._gen_len_v.get(),
                self._gen_upper.get(), self._gen_digits.get(),
                self._gen_sym.get(),   self._gen_noamb.get())
            self._gen_out.configure(state="normal")
            self._gen_out.delete("1.0","end"); self._gen_out.insert("1.0", pwd)
            self._gen_out.configure(state="disabled")
            # Güç
            try: sc = _zxcvbn_mod.zxcvbn(pwd)["score"]
            except: sc = min(4, len(pwd)//10)
            self._gen_str_bar.set(sc)
            # Entropi
            ent = password_entropy(pwd)
            self._gen_ent_lbl.config(text=f"{ent:.1f}", fg=C["green"] if ent >= 128 else C["orange"])
            # Geçmişe ekle
            self._gen_history.insert(0, pwd)
            if len(self._gen_history) > 20: self._gen_history.pop()
            self._gen_hist.put("\n".join(
                f"  {i+1:2}.  {p}" for i,p in enumerate(self._gen_history[:10])))
        except Exception as exc:
            self._toast(str(exc), "error")

    def _gen_copy(self):
        try:
            pwd = self._gen_out.get("1.0","end").strip()
            if pwd:
                self.clipboard_clear(); self.clipboard_append(pwd); self.update()
                self._toast("Şifre panoya kopyalandı!", "success")
        except Exception: pass

    # =========================================================================
    #  Toplu İşlem ekranı
    # =========================================================================
    def _pg_batch(self):
        self._hdr("TOPLU İŞLEM", "Çoklu Klasör Şifrele / Çoklu Vault Çöz")

        # Mod seçimi
        self._batch_mode = tk.StringVar(value="enc")
        mode_card = self._card("İşlem Modu"); mp = self._pad(mode_card, py=10)
        mode_row  = tk.Frame(mp, bg=C["surface"]); mode_row.pack(fill="x")

        for val, lbl in [("enc", "⬡  Klasörleri Şifrele"), ("dec", "⬢  Vault'ları Çöz")]:
            rb = tk.Radiobutton(mode_row, text=lbl, variable=self._batch_mode, value=val,
                                bg=C["surface"], fg=C["text_dim"],
                                selectcolor=C["surface2"], activebackground=C["surface"],
                                font=("Segoe UI", 10, "bold"), cursor="hand2",
                                command=self._batch_mode_changed)
            rb.pack(side="left", padx=(0, 24))

        # Kuyruk kartı
        q_card = self._card("İşlem Kuyruğu"); qp = self._pad(q_card)

        # Düğme satırı
        btn_row = tk.Frame(qp, bg=C["surface"]); btn_row.pack(fill="x", pady=(0, 8))
        _Btn(btn_row, "+ EKLE",        self._batch_add,        small=True).pack(side="left", padx=(0,6))
        _Btn(btn_row, "− SEÇİLİ SİL", self._batch_remove,     small=True).pack(side="left", padx=(0,6))
        _Btn(btn_row, "✕ TEMİZLE",    self._batch_clear,       small=True, danger=True).pack(side="left")
        self._batch_count_lbl = tk.Label(btn_row, text="0 öğe", bg=C["surface"],
                                         fg=C["text_dim"], font=("Segoe UI", 9))
        self._batch_count_lbl.pack(side="right")

        # Liste kutusu
        list_frame = tk.Frame(qp, bg=C["surface"], highlightthickness=1,
                              highlightbackground=C["border"])
        list_frame.pack(fill="x")
        sb2 = tk.Scrollbar(list_frame, orient="vertical", bg=C["surface2"],
                           troughcolor=C["bg"], width=7, relief="flat")
        self._batch_listbox = tk.Listbox(
            list_frame, bg=C["surface2"], fg=C["text"],
            font=FONT_MONO, relief="flat", bd=0, height=7,
            selectmode="extended",
            selectbackground=C["accent_dim"], selectforeground=C["text"],
            yscrollcommand=sb2.set,
            highlightthickness=0,
        )
        sb2.config(command=self._batch_listbox.yview)
        sb2.pack(side="right", fill="y")
        self._batch_listbox.pack(side="left", fill="both", expand=True, padx=4, pady=4)

        # Şifre
        pwd_card = self._card("Şifre  (tüm öğeler için aynı)"); pp = self._pad(pwd_card)
        self._batch_pwd = _PwdField(pp, placeholder="Toplu işlem şifresi")
        self._batch_pwd.pack(fill="x")

        # Seçenekler
        opt_card = self._card("Seçenekler"); op = self._pad(opt_card, py=10)
        opt_row  = tk.Frame(op, bg=C["surface"]); opt_row.pack(fill="x")
        self._batch_wipe_v   = tk.BooleanVar(value=False)
        self._batch_open_v   = tk.BooleanVar(value=False)
        self._batch_skip_v   = tk.BooleanVar(value=True)
        self._checkbox(opt_row, "Güvenli Sil (şifreleme sonrası orijinali sil)",
                       self._batch_wipe_v, danger=True).pack(side="left", padx=(0,20))
        self._checkbox(opt_row, "Hata durumunda devam et",
                       self._batch_skip_v).pack(side="left", padx=(0,20))
        self._checkbox(opt_row, "Tamamlanınca klasörü aç",
                       self._batch_open_v).pack(side="left")

        # Başlat butonu
        act_card = self._card(); ap = self._pad(act_card)
        self._batch_btn = _Btn(ap, "▶  TOPLU İŞLEMİ BAŞLAT", self._do_batch)
        self._batch_btn.pack(fill="x")

        # İlerleme: genel + mevcut öğe
        prog_outer = tk.Frame(ap, bg=C["surface"]); prog_outer.pack(fill="x", pady=(10,0))
        tk.Label(prog_outer, text="GENEL:", bg=C["surface"], fg=C["text_muted"],
                 font=("Segoe UI", 7,"bold")).pack(anchor="w")
        self._batch_prog_total = _ProgRow(prog_outer); self._batch_prog_total.pack(fill="x")
        tk.Label(prog_outer, text="MEVCUT:", bg=C["surface"], fg=C["text_muted"],
                 font=("Segoe UI", 7,"bold")).pack(anchor="w", pady=(6,0))
        self._progress = _ProgRow(prog_outer); self._progress.pack(fill="x")

        self._logbox = _Log(ap, h=6); self._logbox.pack(fill="x", pady=(8,0))

        # İç veri
        self._batch_items: list[str] = []
        self._batch_mode_changed()

    def _batch_mode_changed(self):
        if not hasattr(self, "_batch_listbox"): return
        self._batch_clear()

    def _batch_add(self):
        mode = self._batch_mode.get()
        if mode == "enc":
            paths = filedialog.askdirectory()
            if paths: self._batch_push(paths)
        else:
            paths = filedialog.askopenfilenames(
                filetypes=[("Vault", f"*{VAULT_EXTENSION}"), ("Tümü","*.*")])
            for p in paths: self._batch_push(p)

    def _batch_push(self, path: str):
        if path and path not in self._batch_items:
            self._batch_items.append(path)
            name = Path(path).name
            self._batch_listbox.insert("end", f"  {name}  [{Path(path).parent}]")
            self._batch_count_lbl.config(text=f"{len(self._batch_items)} öğe")

    def _batch_remove(self):
        sel = list(self._batch_listbox.curselection())[::-1]
        for i in sel:
            self._batch_listbox.delete(i)
            self._batch_items.pop(i)
        self._batch_count_lbl.config(text=f"{len(self._batch_items)} öğe")

    def _batch_clear(self):
        if hasattr(self, "_batch_listbox"): self._batch_listbox.delete(0, "end")
        if hasattr(self, "_batch_items"):   self._batch_items.clear()
        if hasattr(self, "_batch_count_lbl"): self._batch_count_lbl.config(text="0 öğe")

    def _do_batch(self):
        items = list(self._batch_items)
        pwd   = self._batch_pwd.get()
        mode  = self._batch_mode.get()
        if not items:  return self._toast("Kuyruğa en az bir öğe ekleyin.", "warn")
        if not pwd.strip(): return self._toast("Şifre boş olamaz.", "error")
        if mode == "enc" and len(pwd) < MIN_PWD_LEN:
            return self._toast(f"Şifre en az {MIN_PWD_LEN} karakter olmalı.", "error")

        do_wipe = self._batch_wipe_v.get()
        do_open = self._batch_open_v.get()
        do_skip = self._batch_skip_v.get()
        n_total = len(items)

        self._batch_btn.configure(state="disabled")
        self._logbox.clear()
        self._progress.reset()
        self._batch_prog_total.reset()

        def _work():
            ok_count = 0; fail_count = 0

            for idx, path_str in enumerate(items):
                path = Path(path_str)
                self._post_log(f"── [{idx+1}/{n_total}]  {path.name}")

                # Genel ilerleme (öğe başına)
                self._post(lambda i=idx, n=n_total:
                    self._batch_prog_total.winfo_exists() and
                    self._batch_prog_total.set(i / n, f"{i}/{n} tamamlandı"))

                try:
                    if mode == "enc":
                        if not path.is_dir():
                            raise ValueError(f"Klasör değil: {path.name}")
                        out_vault = path.with_suffix(VAULT_EXTENSION)
                        st = CryptoEngine(pwd).encrypt_folder(
                            path, out_vault, cb=self._post_prog)
                        SESSION.record_enc(st["file_count"], st["original_size"])
                        save_recent(str(out_vault), True)
                        if do_wipe:
                            self._post_log(f"   Güvenli siliniyor: {path.name}…")
                            SecureWiper.wipe_folder(path)
                        self._post_log(f"   ✓ Şifrelendi → {out_vault.name}")
                        ok_count += 1
                    else:
                        if not path.exists():
                            raise ValueError(f"Bulunamadı: {path.name}")
                        out_dir = path.parent / f"{path.stem}_unlocked"
                        md = CryptoEngine(pwd).decrypt_vault(
                            path, out_dir, cb=self._post_prog)
                        SESSION.record_dec()
                        save_recent(str(path), True)
                        dest = Path(md.get("extracted_to", str(out_dir)))
                        self._post_log(f"   ✓ Çözüldü → {dest.name}")
                        ok_count += 1
                        if do_open:
                            open_folder(dest)

                except Exception as exc:
                    fail_count += 1
                    self._post_log(f"   ✗ HATA: {exc}")
                    if not do_skip:
                        self._post_log("   Devam et seçeneği kapalı — durduruluyor.")
                        break

            # Genel ilerlemeyi %100 yap
            self._post(lambda ok=ok_count, fl=fail_count, n=n_total:
                self._batch_prog_total.winfo_exists() and
                self._batch_prog_total.set(1.0, f"{ok}/{n} başarılı · {fl} hata"))

            def _fin(ok=ok_count, fl=fail_count):
                if not self.winfo_exists(): return
                kind = "success" if fl == 0 else ("warn" if ok > 0 else "error")
                self._toast(f"Toplu işlem bitti: {ok} başarılı, {fl} hatalı", kind)
            self._post(_fin)

        def _finally():
            self._batch_pwd.set("")
            self._batch_btn.configure(state="normal")

        def _worker_wrap():
            try: _work()
            finally: self._post(_finally)

        threading.Thread(target=_worker_wrap, daemon=True).start()

    # =========================================================================
    #  Ayarlar ekranı
    # =========================================================================
    def _pg_settings(self):
        self._hdr("AYARLAR", "Argon2 · Arayüz · Varsayılanlar")

        # Argon2 parametreleri
        c1 = self._card("Argon2id Parametreleri  (Sonraki Şifrelemeden İtibaren Geçerli)")
        p1 = self._pad(c1)
        tk.Label(p1, text="Bu parametreler yalnızca YENİ vault'ları etkiler.\n"
                           "Mevcut vault'lar oluşturulduklarında kullanılan parametrelerle çözülür.",
                 bg=C["surface"], fg=C["text_dim"], font=("Courier", 8),
                 justify="left").pack(anchor="w", pady=(0,8))

        params = [
            ("Time Cost",   "argon2_time",  1, 10,  DEFAULT_ARGON2["time_cost"]),
            ("Memory (KB)", "argon2_mem",   16384, 524288, DEFAULT_ARGON2["memory_cost"]),
            ("Parallelism", "argon2_par",   1, 16,  DEFAULT_ARGON2["parallelism"]),
        ]
        self._a2_vars = {}
        for name, key, lo, hi, default in params:
            row = tk.Frame(p1, bg=C["surface"]); row.pack(fill="x", pady=3)
            tk.Label(row, text=f"{name:<16}", bg=C["surface"], fg=C["text_dim"],
                     font=("Segoe UI", 9, "bold")).pack(side="left")
            v = tk.IntVar(value=get_setting(key, default))
            self._a2_vars[key] = v
            lbl = tk.Label(row, text=str(v.get()), bg=C["surface"], fg=C["accent"],
                           font=("Segoe UI", 10, "bold"), width=8)
            lbl.pack(side="right")
            sc = tk.Scale(row, from_=lo, to=hi, orient="horizontal", variable=v,
                          bg=C["surface"], fg=C["accent"], troughcolor=C["border"],
                          highlightthickness=0, bd=0, showvalue=False,
                          command=lambda val, l=lbl: l.config(text=str(int(float(val)))))
            sc.pack(side="right", fill="x", expand=True, padx=(8,8))

        # Arayüz
        c2 = self._card("Arayüz"); p2 = self._pad(c2)
        row2 = tk.Frame(p2, bg=C["surface"]); row2.pack(fill="x")
        tk.Label(row2, text="Başlangıç Tab'ı:", bg=C["surface"], fg=C["text_dim"],
                 font=("Segoe UI", 9,"bold")).pack(side="left")
        self._start_tab_v = tk.IntVar(value=get_setting("start_tab", 0))
        tab_names = ["Şifrele","Çöz","Bilgi","Re-Key","Üretici","Ayarlar"]
        for i, n in enumerate(tab_names):
            rb = tk.Radiobutton(row2, text=n, variable=self._start_tab_v, value=i,
                                bg=C["surface"], fg=C["text_dim"],
                                selectcolor=C["surface2"], activebackground=C["surface"],
                                font=("Segoe UI", 9), cursor="hand2")
            rb.pack(side="left", padx=(12,0))

        # Kaydet butonu
        c3 = self._card(); p3 = self._pad(c3, py=10)
        _Btn(p3, "💾  AYARLARI KAYDET", self._save_settings).pack(fill="x")

        # Oturum istatistikleri
        c4 = self._card("Oturum İstatistikleri"); p4 = self._pad(c4, py=10)
        self._stats_frame = tk.Frame(p4, bg=C["surface"]); self._stats_frame.pack(fill="x")
        self._refresh_stats()
        _Btn(p4, "↺  YENİLE", self._refresh_stats, small=True).pack(anchor="e", pady=(8,0))

        # Hakkında
        c5 = self._card("Hakkında"); p5 = self._pad(c5, py=10)
        about = (f"Secure Folder RPM Encrypter  V{APP_VERSION}\n"
                 f"AES-256-GCM şifreleme · Argon2id anahtar türetme\n"
                 f"Vault formatı: SVPV2  |  Minimum şifre: {MIN_PWD_LEN} karakter\n"
                 f"Kısayollar: Ctrl+E Şifrele · Ctrl+D Çöz · Ctrl+I Bilgi · "
                 f"Ctrl+K Re-Key · Ctrl+G Üretici · Ctrl+S Ayarlar · Ctrl+Q Çıkış")
        tk.Label(p5, text=about, bg=C["surface"], fg=C["text_dim"],
                 font=("Segoe UI", 10), justify="left", wraplength=850).pack(anchor="w", padx=5, pady=5)

    # =========================================================================
    #  Görünüm Özelleştirme Ekranı
    # =========================================================================
    def _pg_customize(self):
        self._hdr("GÖRÜNÜMÜ ÖZELLEŞTİR", "Renkler, Yazı Tipleri ve Boyutlar")

        # --- RENK AYARLARI ---
        c1 = self._card("Renk Paleti"); p1 = self._pad(c1)
        color_items = [
            ("Arka Plan Rengi", "custom_bg", C["bg"]),
            ("Yazı Rengi", "custom_text_color", C["text"]),
            ("Vurgu (Accent) Rengi", "custom_accent_color", C["accent"])
        ]
        for label, key, current in color_items:
            row = tk.Frame(p1, bg=C["surface"]); row.pack(fill="x", pady=5)
            tk.Label(row, text=label, bg=C["surface"], fg=C["text"], font=FONT_UI).pack(side="left")
            _Btn(row, "Seç", lambda k=key, c=current: self._pick_custom_color(k, c), small=True).pack(side="right")
            tk.Frame(row, bg=current, width=20, height=20, highlightthickness=1, highlightbackground=C["border"]).pack(side="right", padx=10)

        # --- FONT AYARLARI ---
        c2 = self._card("Yazı Tipi ve Boyut"); p2 = self._pad(c2)
        
        # Font Ailesi
        f_row = tk.Frame(p2, bg=C["surface"]); f_row.pack(fill="x", pady=10)
        tk.Label(f_row, text="Yazı Tipi Ailesi:", bg=C["surface"], fg=C["text"], font=FONT_UI).pack(side="left")
        font_options = ["Segoe UI", "Arial", "Verdana", "Tahoma", "Consolas", "Courier New"]
        self._font_fam_var = tk.StringVar(value=get_setting("custom_font_family", "Segoe UI"))
        f_menu = tk.OptionMenu(f_row, self._font_fam_var, *font_options, command=lambda _: self._save_cust())
        f_menu.config(bg=C["surface2"], fg=C["text"], highlightthickness=0, relief="flat", font=FONT_UI)
        f_menu["menu"].config(bg=C["surface2"], fg=C["text"], font=FONT_UI)
        f_menu.pack(side="right")

        # Genel Yazı Boyutu
        sz_row = tk.Frame(p2, bg=C["surface"]); sz_row.pack(fill="x", pady=10)
        tk.Label(sz_row, text="Genel Yazı Boyutu:", bg=C["surface"], fg=C["text"], font=FONT_UI).pack(side="left")
        self._f_size_v = tk.IntVar(value=get_setting("custom_font_size", 10))
        tk.Scale(sz_row, from_=8, to=16, orient="horizontal", variable=self._f_size_v,
                 bg=C["surface"], fg=C["accent"], troughcolor=C["border"], highlightthickness=0,
                 command=lambda _: self._save_cust()).pack(side="right", fill="x", expand=True, padx=20)

        # Başlık Boyutu
        h_row = tk.Frame(p2, bg=C["surface"]); h_row.pack(fill="x", pady=10)
        tk.Label(h_row, text="Başlık Boyutu:", bg=C["surface"], fg=C["text"], font=FONT_UI).pack(side="left")
        self._h_size_v = tk.IntVar(value=get_setting("custom_header_size", 22))
        tk.Scale(h_row, from_=16, to=36, orient="horizontal", variable=self._h_size_v,
                 bg=C["surface"], fg=C["accent"], troughcolor=C["border"], highlightthickness=0,
                 command=lambda _: self._save_cust()).pack(side="right", fill="x", expand=True, padx=20)

        # --- SIFIRLAMA ---
        c3 = self._card(); p3 = self._pad(c3)
        _Btn(p3, "↺ GÖRÜNÜMÜ VARSAYILANA DÖNDÜR", self._reset_cust, danger=True).pack(fill="x")

    def _pick_custom_color(self, key, current):
        color = colorchooser.askcolor(initialcolor=current, title="Renk Seç")[1]
        if color:
            save_setting(key, color)
            self._theme(get_setting("theme", "Amber"))

    def _save_cust(self):
        save_setting("custom_font_family", self._font_fam_var.get())
        save_setting("custom_font_size", self._f_size_v.get())
        save_setting("custom_header_size", self._h_size_v.get())
        self._theme(get_setting("theme", "Amber"))

    def _reset_cust(self):
        save_setting("custom_bg", None)
        save_setting("custom_text_color", None)
        save_setting("custom_accent_color", None)
        save_setting("custom_font_family", "Segoe UI")
        save_setting("custom_font_size", 10)
        save_setting("custom_header_size", 22)
        self._theme(get_setting("theme", "Amber"))

    def _refresh_stats(self):
        if not hasattr(self, "_stats_frame") or not self._stats_frame.winfo_exists(): return
        for w in self._stats_frame.winfo_children(): w.destroy()
        items = [
            ("Şifrelenen vault",   SESSION.encrypted),
            ("Çözülen vault",      SESSION.decrypted),
            ("Re-Key işlemi",      SESSION.rekeyed),
            ("İşlenen dosya",      SESSION.files_enc),
            ("İşlenen veri",       f"{SESSION.bytes_enc//1024:,} KB"),
            ("Çalışma süresi",     SESSION.uptime()),
        ]
        cols = tk.Frame(self._stats_frame, bg=C["surface"]); cols.pack(fill="x")
        for i, (label, val) in enumerate(items):
            col = 0 if i % 2 == 0 else 1
            row_f = tk.Frame(cols, bg=C["surface2"], highlightthickness=1,
                             highlightbackground=C["border"])
            row_f.grid(row=i//2, column=col, sticky="ew", padx=(0,4) if col==0 else (4,0), pady=2)
            cols.columnconfigure(col, weight=1)
            inner = tk.Frame(row_f, bg=C["surface2"]); inner.pack(fill="both", padx=12, pady=8)
            tk.Label(inner, text=label, bg=C["surface2"], fg=C["text_dim"],
                     font=("Segoe UI", 7,"bold")).pack(anchor="w")
            tk.Label(inner, text=str(val), bg=C["surface2"], fg=C["accent"],
                     font=("Segoe UI", 13,"bold")).pack(anchor="w")

    def _save_settings(self):
        for key, var in self._a2_vars.items():
            save_setting(key, var.get())
        save_setting("start_tab", self._start_tab_v.get())
        self._toast("✓ Ayarlar kaydedildi.", "success")


# =============================================================================
#  Giriş noktası
# =============================================================================
if __name__ == "__main__":
    app = VaultGUI()
    app.mainloop()