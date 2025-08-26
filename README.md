# DecoyBox 🔒

**Same-extension file sealing with believable decoys, host-locking, optional passwords, and one-click UX.**

> Files open normally on **your** device.
> On other devices they open a **decoy**, show a **popup**, or **block** — your choice.

<p align="center">
  <img alt="StealthSeal GUI" src="https://pbs.twimg.com/media/E31zHcLVEAgcEBK?format=jpg&name=small" width="520">
</p>

## ✨ Features

- 🖱️ **Two-click GUI** (Seal / Open / Settings)
- 🧠 **Host-locked** keys (device ID + local master key)
- 🛡️ **Argon2id** KDF + **AES-GCM** with AAD (binds filename/size/ctime)
- 🔏 **Tamper-evident header MAC** — edited files auto switch to foreign behavior
- 🔐 **Optional per-file password** on top of device lock
- 🧪 **Decoys that look real** for PDF/PNG/JPG/TXT/CSV/JSON (generic fallback for others)
- 🧰 **Same extension** output (e.g., `report.pdf` stays `.pdf`) using polyglot layout
- 🗝️ **Master key import/export** (authorize a second device if desired)
- ⚙️ **Foreign behavior policy** per file: `decoy` | `popup` (custom text) | `block`

> ⚠️ Executables (`.exe/.dll/.msi/.sys/.com/.bat/.cmd/.ps1`) should be sealed as **containers** (via the app’s Open→Seal flow) — not same-extension — to avoid Windows loader errors.

---

## 🚀 Quick start

### 1) Install

```bash
python -m pip install --upgrade pip
pip install cryptography reportlab pillow argon2-cffi
```
