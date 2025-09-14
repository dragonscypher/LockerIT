# Lockerette Documentation

## Architecture Overview
Lockerette consists of:
- Core encryption/decryption logic (AES-256-GCM, XChaCha20-Poly1305)
- Dynamic key derivation (password + voiceprint + device/folder binding)
- Voice authentication (offline, encrypted template)
- Device/folder binding (volume ID, hash, etc.)
- CLI and optional desktop UI
- Automated tests
- Optional VHDL AES module

## Security Practices
- All cryptography uses trusted libraries (cryptography, PyNaCl)
- No home-rolled algorithms
- Voice templates are encrypted locally
- Keys rotate on every unlock/re-encrypt
- Device/folder binding prevents key reuse on other devices

## Usage Flow
1. User selects folder/device to protect
2. Sets password and records voice phrase
3. Lockerette binds encryption to device/folder signature
4. To unlock, user provides password and repeats voice phrase
5. Keys rotate after each unlock/re-encrypt

## Voice Authentication
- Uses Resemblyzer for speaker verification
- Phrase is not stored, only embedding
- Template is encrypted with user password

## Device/Folder Binding
- Uses platform-specific device info (volume ID, device node, folder hash)
- Key derivation includes device signature

## VHDL AES Module
- Minimal AES core for hardware acceleration
- Testbench included

## File Structure
- src/: Core logic, CLI, UI
- tests/: Automated tests
- build/: Output binaries
- docs/: Documentation
- assets/: Voice fixtures, test data
- vhdl/: AES module and testbench

## Setup Guide
See README.md for installation and usage instructions.
