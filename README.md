# LOCKERIT

LockereIt is a cross-platform, offline encryption utility for protecting folders and portable storage devices. It features dynamic encryption keys, password + voice authentication, device/folder binding, and a BitLocker-like flow with enhanced security.

## Features
- Dynamic encryption keys (rotated on each unlock/re-encrypt)
- Password + voice authentication (offline speaker & phrase verification)
- Device/folder binding (USB, microSD, folder signature)
- AES-256-GCM and XChaCha20-Poly1305 encryption
- Optional VHDL AES module for hardware acceleration
- Usable CLI and optional desktop UI
- Automated tests (unit + integration)
 - Container mode encryption (single sealed archive with wrapped data key)
 - Argon2id key derivation (fallback PBKDF2) + voice embedding hash diversification
 - Optional offline transcription (Vosk) to display your spoken phrase before confirming

## Requirements
- Python 3.9+
- pip (for dependencies)
- Cross-platform: Windows, macOS, Linux
 - (Optional) Install `vosk` model files manually for transcription (see below)

## Setup
1. Clone or download Lockerette locally.
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
   (Optional: If you want offline transcription, download a Vosk model, e.g. small English:
   ```sh
   # Example (Linux/macOS); choose a directory to store models
   curl -L -o vosk-model.zip https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip
   unzip vosk-model.zip -d models
   set VOSK_MODEL_PATH=./models/vosk-model-small-en-us-0.15   # Windows PowerShell: $env:VOSK_MODEL_PATH="models/vosk-model-small-en-us-0.15"
   ```
   )
3. (Optional) Build desktop UI:
   ```sh
   python src/ui_desktop.py
   ```
4. Run CLI:
   ```sh
   python src/cli.py --help
   ```

## Usage Examples
Encrypt a folder:
```sh
python src/cli.py encrypt --folder /path/to/folder
```
Unlock a folder:
```sh
python src/cli.py unlock --folder /path/to/folder
```

Container mode (single sealed archive) with optional dual key wrap (password + phrase):
```sh
python src/cli.py encrypt --folder /path/to/folder --container
python src/cli.py unlock  --folder /path/to/folder --container
```

If voice template mismatch or migrated from older version, force re-enrollment (OTP protected):
# Enable phrase recovery (auto from transcript or explicit --phrase). If password later mistyped you can supply the phrase on unlock.
```sh
python src/cli.py unlock --folder /path/to/folder --container --revoice
```
Recovery unlock example (wrong password, correct phrase):
```sh
python src/cli.py unlock --folder /path/to/folder --container --phrase "your recorded phrase"
```

Live voice verification (default on unlock): captures a fresh sample and compares to stored template. To skip (headless scripts):
```sh
python src/cli.py unlock --folder /path/to/folder --container --no-live-voice
```

Revoice OTP flow prints a 6-digit code you must re-enter to confirm template overwrite.

## Voice Authentication
- On first use, record your voice phrase (offline, encrypted template)
- On unlock, repeat the phrase for verification
 - If Vosk is installed and a model path is available, a transcript of what you said is displayed for confirmation

## Device/Folder Binding
- Keys are tied to device/folder signature (volume ID, hash, etc.)
 - Container mode wraps a random DEK with a KEK derived from (password + voice + device)

## Tests
Run all tests:
```sh
pytest tests/
```
 (Tests currently exercise per-file mode; container mode is validated via UI.)

## VHDL AES Module
- See `vhdl/` for optional hardware acceleration

## Documentation
- See `docs/` for detailed guides and architecture

---
Lockerette is fully offline, open-source, and designed for maximum privacy and security.
 
## Security Notes
 - Argon2id parameters target interactive usage; increase memory/time cost for higher security on powerful hosts.
 - Voice password + embedding hash expand salt space; never reuse your voice password across critical systems.
 - Container archive uses AES-256-GCM with random DEK; KEK derived via Argon2id.
