#!/usr/bin/env python3
# StealthSeal Pro — single-file, same-extension sealing with Argon2id, header MAC, password, audit logs, progress, and custom foreign behavior.
# Deps: cryptography, reportlab, pillow, argon2-cffi
# Build EXE (Win): pyinstaller --onefile --noconsole stealthseal_pro.py

import os, sys, json, base64, hashlib, time, tempfile, subprocess, platform, threading
from pathlib import Path
from typing import Optional, Tuple
from tkinter import Tk, Button, Label, filedialog, messagebox, Toplevel, Text, StringVar, OptionMenu, simpledialog
from tkinter import ttk

# --- Optional decoy libs ---
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    HAVE_REPORTLAB = True
except Exception:
    HAVE_REPORTLAB = False

try:
    from PIL import Image, ImageDraw, ImageFont
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

# --- Crypto ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type as Argon2Type

APP_DIR = Path.home() / ".stealthseal"
CFG_FILE = APP_DIR / "config.json"
MASTER_KEY_FILE = APP_DIR / "master.key"
AUDIT_LOG = APP_DIR / "events.jsonl"

MARKER = b"\n%%STEALTHSEAL-PAYLOAD\n"  # separates visible decoy from encrypted header/payload

DEFAULT_CFG = {
    "foreign_action": "decoy",    # decoy | popup | block
    "foreign_popup_text": "This protected file cannot be opened on this device.",
    "default_require_password": False
}

# -------------------------- Utilities --------------------------

def ensure_app_dir():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    try: os.chmod(APP_DIR, 0o700)
    except Exception: pass

def load_cfg() -> dict:
    ensure_app_dir()
    if not CFG_FILE.exists():
        CFG_FILE.write_text(json.dumps(DEFAULT_CFG, indent=2), encoding="utf-8")
        return DEFAULT_CFG.copy()
    try:
        data = json.loads(CFG_FILE.read_text(encoding="utf-8"))
        for k, v in DEFAULT_CFG.items():
            data.setdefault(k, v)
        return data
    except Exception:
        return DEFAULT_CFG.copy()

def save_cfg(cfg: dict):
    ensure_app_dir()
    CFG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

def load_master_key() -> bytes:
    ensure_app_dir()
    if not MASTER_KEY_FILE.exists():
        k = os.urandom(32)
        MASTER_KEY_FILE.write_bytes(k)
        try: os.chmod(MASTER_KEY_FILE, 0o600)
        except Exception: pass
        return k
    return MASTER_KEY_FILE.read_bytes()

def export_master_key(dest: Path):
    data = load_master_key()
    dest.write_bytes(data)

def import_master_key(src: Path):
    data = Path(src).read_bytes()
    ensure_app_dir()
    MASTER_KEY_FILE.write_bytes(data)
    try: os.chmod(MASTER_KEY_FILE, 0o600)
    except Exception: pass

def machine_id() -> str:
    try:
        if sys.platform.startswith("win"):
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
            val, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(val)
        elif sys.platform == "darwin":
            out = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]).decode(errors="ignore")
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
            return platform.node()
        else:
            p = Path("/etc/machine-id")
            if p.exists():
                return p.read_text().strip()
            return platform.node()
    except Exception:
        return platform.node()

def dev_id_hash() -> str:
    return hashlib.sha256(machine_id().encode()).hexdigest()[:16]

def b64(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s)

def audit(event: str, file_id: str, decision: str, extra: Optional[dict] = None):
    ensure_app_dir()
    rec = {
        "ts": int(time.time()),
        "event": event,           # "open" | "seal"
        "decision": decision,     # "allow" | "decoy" | "block" | "tamper"
        "file": file_id,
        "host": platform.node(),
        "mid": dev_id_hash()
    }
    if extra: rec.update(extra)
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")

# ------------------ KDF / Keys / MAC ------------------

def argon2id(secret: bytes, salt: bytes, out_len: int = 64) -> bytes:
    # 64 MB, 2 iters, 1 thread → good baseline for desktops
    return hash_secret_raw(secret, salt, time_cost=2, memory_cost=64*1024,
                           parallelism=1, hash_len=out_len, type=Argon2Type.ID)

def derive_keys(salt: bytes, password: Optional[str]) -> Tuple[bytes, bytes]:
    """
    Returns (enc_key, mac_key), 32 bytes each.
    Secret includes: master_key || machine_id [|| pw_hash]
    """
    base = load_master_key() + machine_id().encode()
    if password:
        pw_digest = hashlib.sha256(password.encode("utf-8")).digest()
        base += pw_digest
    out = argon2id(base, salt, out_len=64)
    return out[:32], out[32:]

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", data, key, 1, dklen=32)  # HMAC-like via PBKDF2 (no extra deps)

def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

# ------------------ Decoys (same-format) ------------------

def decoy_text(name: str, note: str = "Public snapshot (no sensitive data).") -> bytes:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    return (f"{name}\n--------\n{note}\nGenerated: {ts}\n").encode()

def build_decoy_pdf() -> bytes:
    if not HAVE_REPORTLAB:
        return decoy_text("PDF")
    from io import BytesIO
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(w/2, h-120, "Public Snapshot")
    c.setFont("Helvetica", 12)
    c.drawCentredString(w/2, h-150, time.strftime("Generated: %Y-%m-%d %H:%M:%S"))
    c.setFont("Helvetica", 13)
    c.drawCentredString(w/2, h-210, "This edition contains no sensitive data.")
    c.setFont("Helvetica", 10)
    c.drawString(72, 72, "Protected by StealthSeal")
    c.showPage(); c.save()
    return buf.getvalue()

def build_decoy_image(ext: str = ".png") -> bytes:
    if not HAVE_PIL:
        return decoy_text("IMAGE")
    mode = "RGB"
    W, H = 1000, 600
    img = Image.new(mode, (W, H), (245, 245, 245))
    drw = ImageDraw.Draw(img)
    title = "Public Snapshot"
    sub = time.strftime("Generated: %Y-%m-%d %H:%M:%S")
    note = "This edition contains no sensitive data."
    try:
        font_title = ImageFont.truetype("arial.ttf", 40)
        font_sub   = ImageFont.truetype("arial.ttf", 22)
        font_note  = ImageFont.truetype("arial.ttf", 28)
    except Exception:
        font_title = ImageFont.load_default()
        font_sub   = ImageFont.load_default()
        font_note  = ImageFont.load_default()
    w1, _ = drw.textsize(title, font=font_title)
    drw.text(((W-w1)//2, 160), title, fill=(0,0,0), font=font_title)
    w2, _ = drw.textsize(sub, font=font_sub)
    drw.text(((W-w2)//2, 220), sub, fill=(20,20,20), font=font_sub)
    w3, _ = drw.textsize(note, font=font_note)
    drw.text(((W-w3)//2, 300), note, fill=(10,10,10), font=font_note)
    from io import BytesIO
    buf = BytesIO()
    if ext.lower() in (".jpg", ".jpeg"):
        img.save(buf, format="JPEG", quality=88)
    else:
        img.save(buf, format="PNG")
    return buf.getvalue()

def make_same_format_decoy(orig: Path) -> bytes:
    ext = orig.suffix.lower()
    if ext in (".txt", ".log", ".md", ".ini", ".cfg"):
        return decoy_text(orig.stem)
    if ext in (".csv", ".tsv"):
        hdr = "id,name,value\n"
        rows = [f"{i},sample_{i},0" for i in range(1, 51)]
        return (hdr + "\n".join(rows) + "\n").encode()
    if ext in (".json",):
        obj = {"status": "ok", "count": 0, "note": f"{orig.stem} (public snapshot)", "generated": time.strftime("%Y-%m-%d %H:%M:%S")}
        return (json.dumps(obj, indent=2) + "\n").encode()
    if ext in (".pdf",):
        return build_decoy_pdf()
    if ext in (".png", ".jpg", ".jpeg"):
        return build_decoy_image(ext)
    return decoy_text(orig.stem)

# ------------------ Sealing / Opening ------------------

def split_polyglot(b: bytes) -> Tuple[bytes, Optional[dict]]:
    parts = b.split(MARKER, 1)
    if len(parts) != 2:
        return b, None
    head, tail = parts
    try:
        info = json.loads(tail.decode("utf-8"))
        return head, info
    except Exception:
        return b, None

def seal_file_same_ext(input_path: str, output_path: Optional[str], cfg: dict, progress_cb=None) -> str:
    """
    Polyglot layout: [decoy-bytes][MARKER][header+payload JSON]
    Header v2 is MACed; payload uses AES-GCM with AAD (filename/size/ctime).
    """
    src = Path(input_path).expanduser().resolve()
    if not src.exists() or not src.is_file():
        raise FileNotFoundError("File not found.")
    if output_path is None:
        output_path = str(src.with_name(src.stem + "_sealed" + src.suffix))

    # Read file with progress
    size = src.stat().st_size
    chunk = 1024 * 1024
    parts = []
    read = 0
    with open(src, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf: break
            parts.append(buf); read += len(buf)
            if progress_cb and size > 0:
                progress_cb(min(read/size, 0.95))  # leave some for crypto/IO
    real = b"".join(parts)

    decoy = make_same_format_decoy(src)

    # AAD (bind properties)
    try:
        ctime = int(src.stat().st_ctime)
    except Exception:
        ctime = int(time.time())
    aad = {"orig": src.name, "size": size, "ctime": ctime}

    # Password (optional)
    require_pw = bool(cfg.get("default_require_password", False))
    ask = messagebox.askyesno("Password", "Add a password on top of device lock?\n(Recommended for very sensitive files)") if not require_pw else True
    password = None
    if ask:
        pw = simpledialog.askstring("Password", "Enter password (leave empty to skip):", show="*")
        if pw: password = pw

    salt = os.urandom(16)
    enc_key, mac_key = derive_keys(salt, password)
    aes = AESGCM(enc_key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, real, canonical_json(aad))  # AEAD AAD

    header = {
        "v": 2,
        "salt": b64(salt),
        "nonce": b64(nonce),
        "payload": b64(ct),
        "aad": aad,
        "policy": {
            "foreign_action": cfg.get("foreign_action", "decoy"),
            "foreign_popup_text": cfg.get("foreign_popup_text", DEFAULT_CFG["foreign_popup_text"]),
            "password_required": bool(password)
        },
        "meta": {
            "orig_ext": src.suffix.lower(),
            "orig_name": src.name,
            "created": int(time.time()),
            "device": dev_id_hash()
        },
        "key_version": 1
    }
    # MAC over header-without-mac to detect tampering
    header_for_mac = header.copy()
    header_for_mac.pop("mac", None)
    mac = hmac_sha256(mac_key, canonical_json(header_for_mac))
    header["mac"] = b64(mac)

    blob = json.dumps(header).encode("utf-8")

    outp = Path(output_path)
    with open(outp, "wb") as f:
        f.write(decoy)
        f.write(MARKER)
        f.write(blob)

    try: os.chmod(outp, 0o600)
    except Exception: pass

    audit("seal", outp.name, "allow", {"size": size})
    if progress_cb: progress_cb(1.0)
    return str(outp)

def open_sealed(path: str, cfg: dict, progress_cb=None) -> Optional[Path]:
    b = Path(path).read_bytes()
    head, info = split_polyglot(b)
    if info is None:
        # Not sealed → open as-is
        audit("open", Path(path).name, "allow", {"sealed": False})
        return Path(path)

    file_id = Path(path).name
    # Verify MAC first (tamper-evident)
    salt = b64d(info["salt"])
    nonce = b64d(info["nonce"])
    ct = b64d(info["payload"])
    aad = info.get("aad", {})
    policy = info.get("policy", {})
    meta = info.get("meta", {})
    password_required = bool(policy.get("password_required", False))

    # Optional password prompt
    password = None
    if password_required:
        password = simpledialog.askstring("Password", "Enter password:", show="*")
        if not password:
            audit("open", file_id, "block", {"reason": "no_password"})
            messagebox.showerror("Error", "Password required.")
            return None

    # Derive keys, recompute MAC
    enc_key, mac_key = derive_keys(salt, password)
    header_for_mac = info.copy()
    header_for_mac.pop("mac", None)
    expect_mac_b64 = info.get("mac", "")
    calc_mac = b64(hmac_sha256(mac_key, canonical_json(header_for_mac)))
    if calc_mac != expect_mac_b64:
        audit("open", file_id, "tamper", {"reason": "mac_mismatch"})
        # Follow foreign policy on tamper: treat as foreign/decoy
        return _foreign_behavior(path, head, policy)

    # Decrypt with AEAD + AAD
    try:
        aes = AESGCM(enc_key)
        # Basic "progress": simulate small step
        if progress_cb: progress_cb(0.90)
        plain = aes.decrypt(nonce, ct, canonical_json(aad))
    except Exception:
        # Wrong machine or wrong password
        decision = "block" if policy.get("foreign_action") == "block" else "decoy"
        audit("open", file_id, decision, {"reason": "decrypt_fail"})
        return _foreign_behavior(path, head, policy)

    # Success → write temp with original extension and open
    ext = meta.get("orig_ext") or ".bin"
    tf = Path(tempfile.gettempdir()) / f"stealthseal_{int(time.time()*1000)}{ext}"
    # Write with small chunk progress
    total = len(plain)
    if progress_cb and total > 0:
        with open(tf, "wb") as f:
            sent = 0
            chunk = 1024 * 1024
            for i in range(0, total, chunk):
                blk = plain[i:i+chunk]
                f.write(blk)
                sent += len(blk)
                progress_cb(0.90 + 0.10 * min(sent/total, 1.0))
    else:
        tf.write_bytes(plain)

    audit("open", file_id, "allow", {"bytes": total})
    return tf

def _foreign_behavior(src_path: str, decoy_head: bytes, policy: dict) -> Optional[Path]:
    action = policy.get("foreign_action", "decoy")
    msg = policy.get("foreign_popup_text", DEFAULT_CFG["foreign_popup_text"])
    if action == "block":
        messagebox.showwarning("Blocked", "This protected file cannot be opened on this device.")
        return None
    if action == "popup":
        _popup(msg)
        return None
    # default: decoy → write head to temp with same extension
    tf = Path(tempfile.gettempdir()) / f"public_{int(time.time()*1000)}{Path(src_path).suffix}"
    tf.write_bytes(decoy_head)
    return tf

# ------------------ GUI ------------------

def _popup(msg: str):
    top = Toplevel()
    top.title("Notice")
    top.geometry("420x180")
    Label(top, text=msg, wraplength=380, pady=20, justify="left").pack()
    Button(top, text="OK", command=top.destroy, width=12).pack(pady=10)
    top.lift(); top.attributes("-topmost", True); top.after(300, lambda: top.attributes("-topmost", False))

class SettingsDialog:
    def __init__(self, root, cfg: dict):
        self.top = Toplevel(root)
        self.top.title("Settings")
        self.top.geometry("520x360")
        self.cfg = cfg

        Label(self.top, text=f"My Device ID: {dev_id_hash()}", pady=6, fg="#444").pack()

        row = Toplevel(self.top) if False else self.top
        Label(self.top, text="Action on other PCs:", pady=6).pack()
        self.action_var = StringVar(self.top, value=cfg.get("foreign_action","decoy"))
        OptionMenu(self.top, self.action_var, "decoy", "popup", "block").pack()

        Label(self.top, text="Popup message (when 'popup' is selected):", pady=6).pack()
        self.txt = Text(self.top, height=5, width=60)
        self.txt.pack()
        self.txt.insert("1.0", cfg.get("foreign_popup_text", DEFAULT_CFG["foreign_popup_text"]))

        self.pw_req = StringVar(self.top, value="Yes" if cfg.get("default_require_password", False) else "No")
        Label(self.top, text="Suggest password when sealing:", pady=6).pack()
        OptionMenu(self.top, self.pw_req, "Yes", "No").pack()

        Button(self.top, text="Export Master Key", command=self.do_export, width=16).pack(pady=6)
        Button(self.top, text="Import Master Key", command=self.do_import, width=16).pack(pady=2)

        Button(self.top, text="Save", command=self.save, width=12).pack(pady=10)

    def save(self):
        self.cfg["foreign_action"] = self.action_var.get()
        self.cfg["foreign_popup_text"] = self.txt.get("1.0", "end").strip()
        self.cfg["default_require_password"] = (self.pw_req.get() == "Yes")
        save_cfg(self.cfg)
        messagebox.showinfo("Saved", "Settings saved.")
        self.top.destroy()

    def do_export(self):
        dst = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key file", "*.key"), ("All files","*.*")])
        if not dst: return
        try:
            export_master_key(Path(dst))
            messagebox.showinfo("Exported", f"Master key exported to:\n{dst}\n\n(Keep it secret and safe.)")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_import(self):
        src = filedialog.askopenfilename(title="Import Master Key", filetypes=[("Key file", "*.key"), ("All files","*.*")])
        if not src: return
        try:
            import_master_key(Path(src))
            messagebox.showinfo("Imported", "Master key imported. This device can now open files sealed by devices sharing this key.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

class App:
    def __init__(self, root: Tk):
        self.cfg = load_cfg()
        root.title("StealthSeal Pro")
        root.geometry("480x300")
        Label(root, text="Seal files to this machine.\nElsewhere: decoy / popup / block.\nArgon2id • Header MAC • Optional Password • Audit logs", pady=8).pack()

        self.pb = ttk.Progressbar(root, orient="horizontal", mode="determinate", length=360)
        self.pb.pack(pady=4)

        Button(root, text="Seal File (same extension)", width=30, command=self.do_seal).pack(pady=8)
        Button(root, text="Open (sealed or normal)", width=30, command=self.do_open).pack(pady=2)
        Button(root, text="Settings", width=30, command=self.do_settings).pack(pady=6)
        Button(root, text="Open Audit Log", width=30, command=self.do_log).pack(pady=2)
        Label(root, text=f"Device: {platform.node()} • ID: {dev_id_hash()}", fg="#666").pack(side="bottom", pady=6)

    def set_progress(self, v: float):
        self.pb["value"] = max(0, min(100, int(v*100)))
        self.pb.update_idletasks()

    def do_seal(self):
        path = filedialog.askopenfilename(title="Pick a file to protect")
        if not path: return
        self.set_progress(0.0)
        def run():
            try:
                out = seal_file_same_ext(path, None, self.cfg, progress_cb=self.set_progress)
                messagebox.showinfo("Done", f"Protected:\n{out}\n\nDouble-click elsewhere → decoy.\nUse 'Open' here → real content.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.set_progress(0.0)
        threading.Thread(target=run, daemon=True).start()

    def do_open(self):
        path = filedialog.askopenfilename(title="Open a file (sealed or normal)")
        if not path: return
        self.set_progress(0.0)
        def run():
            try:
                out = open_sealed(path, self.cfg, progress_cb=self.set_progress)
                if out is None:
                    return
                open_with_default(out)
            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.set_progress(0.0)
        threading.Thread(target=run, daemon=True).start()

    def do_settings(self):
        SettingsDialog(root, self.cfg)

    def do_log(self):
        ensure_app_dir()
        if not AUDIT_LOG.exists():
            AUDIT_LOG.write_text("", encoding="utf-8")
        open_with_default(AUDIT_LOG)

def open_with_default(p: Path):
    if p is None: return
    if sys.platform.startswith("win"):
        os.startfile(str(p))  # type: ignore
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(p)])
    else:
        subprocess.Popen(["xdg-open", str(p)])

def main():
    ensure_app_dir()
    load_master_key()  # bootstrap
    global root
    root = Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
