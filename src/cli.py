import argparse
import getpass
import hashlib
import os
import secrets
import sys

from src.core import LockeretteCore
from src.device import DeviceBinder
from src.voice import VoiceAuth


def main():
    parser = argparse.ArgumentParser(description="Lockerette Encryption Utility")
    subparsers = parser.add_subparsers(dest="command")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a folder/device")
    encrypt_parser.add_argument("--folder", required=True, help="Path to folder/device")
    encrypt_parser.add_argument("--container", action="store_true", help="Use container mode (single sealed archive)")
    encrypt_parser.add_argument("--no-transcript", action="store_true", help="Disable voice transcription prompt")
    encrypt_parser.add_argument("--phrase", help="Provide a recovery phrase explicitly (skips transcript prompt)")

    unlock_parser = subparsers.add_parser("unlock", help="Unlock a folder/device")
    unlock_parser.add_argument("--folder", required=True, help="Path to folder/device")
    unlock_parser.add_argument("--container", action="store_true", help="Use container mode (single sealed archive)")
    unlock_parser.add_argument("--revoice", action="store_true", help="Force voice re-enrollment before unlock (OTP protected)")
    unlock_parser.add_argument("--phrase", help="Supply recovery phrase for unlock (if password wrong)")
    unlock_parser.add_argument("--no-live-voice", action="store_true", help="Skip live voice capture (use stored hash only)")

    args = parser.parse_args()
    core = LockeretteCore()
    voice = VoiceAuth()
    device = DeviceBinder()

    if args.command == "encrypt":
        folder: str = args.folder
        device_id_opt = device.get_device_id(folder)
        if device_id_opt is None:
            print("Error: Could not determine a stable device identifier.")
            sys.exit(1)
        device_id: str = device_id_opt
        password: str = getpass.getpass("Password: ")
        print("Recording / verifying voice...")
        voiceprint, transcript = voice.record_and_verify(password, want_transcript=not args.no_transcript)
        phrase_hash = None
        phrase_source = None
        chosen_phrase = None
        explicit_phrase = getattr(args, 'phrase', None)
        if explicit_phrase:
            chosen_phrase = explicit_phrase.strip()
        elif transcript:
            ans = input(f"Detected phrase: '{transcript}'. Use as recovery phrase? [Y/n]: ").strip().lower()
            if ans in ('', 'y', 'yes'):
                chosen_phrase = transcript
        if chosen_phrase:
            norm = chosen_phrase.strip().lower()
            if len(norm) < 8:
                print("[WARN] Phrase too short (<8); ignoring.")
            else:
                phrase_hash = hashlib.sha256(norm.encode()).hexdigest()
                phrase_source = 'transcript' if not explicit_phrase else 'explicit'
                print(f"Recovery phrase enabled ({phrase_source}).")
        if getattr(args, 'container', False):
            core.encrypt_container(folder, password, voiceprint, device_id, phrase_hash=phrase_hash)
            print("[OK] Container encrypted.")
        else:
            core.encrypt_folder(folder, password, voiceprint, device_id)
            print("[OK] Files encrypted.")
    elif args.command == "unlock":
        folder: str = args.folder
        device_id_opt = device.get_device_id(folder)
        if device_id_opt is None:
            print("Error: Could not determine a stable device identifier.")
            sys.exit(1)
        device_id: str = device_id_opt
        password: str = getpass.getpass("Password: ")
        # If template exists, derive stable voiceprint without re-recording
        otp_verified = False
        try:
            if getattr(args, 'revoice', False):
                code = f"{secrets.randbelow(10**6):06d}"
                print(f"OTP: {code}")
                entered = getpass.getpass("Enter OTP to confirm revoice: ")
                if entered != code:
                    print("OTP mismatch.")
                    sys.exit(1)
                otp_verified = True
                print("Re-enrolling voice template...")
                voiceprint = voice.reenroll(password)
            else:
                if voice.has_template():
                    if getattr(args,'no_live_voice', False):
                        voiceprint = voice.get_voiceprint(password)
                        print("Voice (hash only, no live capture).")
                    else:
                        print("Capture live voice for verification...")
                        voiceprint = voice.verify_only(password)
                        print("Voice verified.")
                else:
                    print("No template found, enrolling voice...")
                    voiceprint, _ = voice.record_and_verify(password)
        except Exception as e:
            print(f"Voice auth failed: {e}")
            sys.exit(1)
        if getattr(args, 'container', False):
            try:
                phrase_arg = getattr(args, 'phrase', None)
                core.decrypt_container(folder, password, voiceprint, device_id, phrase=phrase_arg)
                print("[OK] Container decrypted.")
            except ValueError as e:
                print(f"Decrypt failed: {e}")
                if not getattr(args,'phrase',None):
                    print("Hint: supply --phrase <recovery phrase> if set during encryption.")
                print("Hint: try --revoice (with OTP) if template mismatch suspected.")
                sys.exit(1)
        else:
            core.unlock_folder(folder, password, voiceprint, device_id)
            print("[OK] Files decrypted.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
