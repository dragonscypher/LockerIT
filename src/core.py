import hashlib
import io
import os
import secrets
import tarfile

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class LockeretteCore:
    def __init__(self):
        pass

    def derive_key(self, password, voiceprint, device_id):
        base_salt = hashlib.sha256((voiceprint + device_id).encode()).digest()
        try:
            from argon2.low_level import Type, hash_secret_raw

            # Argon2id parameters tuned for interactive use; can be increased.
            salt = base_salt[:16]
            key = hash_secret_raw(
                secret=password.encode(),
                salt=salt,
                time_cost=3,
                memory_cost=64 * 1024,  # 64 MB
                parallelism=2,
                hash_len=32,
                type=Type.ID
            )
            return key
        except Exception:
            # Fallback PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=base_salt,
                iterations=200_000,
                backend=default_backend()
            )
            return kdf.derive(password.encode())

    def encrypt_folder(self, folder, password, voiceprint, device_id):
        key = self.derive_key(password, voiceprint, device_id)
        for root, _, files in os.walk(folder):
            for file in files:
                path = os.path.join(root, file)
                with open(path, 'rb') as f:
                    data = f.read()
                nonce = secrets.token_bytes(12)
                aesgcm = AESGCM(key)
                encrypted = aesgcm.encrypt(nonce, data, None)
                with open(path + '.locked', 'wb') as f:
                    f.write(nonce + encrypted)
                os.remove(path)
        # Hide folder contents after encryption (Windows only)
        if os.name == 'nt':
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            for root, _, files in os.walk(folder):
                for file in files:
                    path = os.path.join(root, file)
                    ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)

    def unlock_folder(self, folder, password, voiceprint, device_id):
        key = self.derive_key(password, voiceprint, device_id)
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith('.locked'):
                    path = os.path.join(root, file)
                    with open(path, 'rb') as f:
                        nonce = f.read(12)
                        encrypted = f.read()
                    aesgcm = AESGCM(key)
                    try:
                        data = aesgcm.decrypt(nonce, encrypted, None)
                    except Exception:
                        raise ValueError('Decryption failed: wrong credentials or device.')
                    orig_path = path[:-7]
                    with open(orig_path, 'wb') as f:
                        f.write(data)
                    os.remove(path)
        # Unhide folder contents after decryption (Windows only)
        if os.name == 'nt':
            import ctypes
            FILE_ATTRIBUTE_NORMAL = 0x80
            for root, _, files in os.walk(folder):
                for file in files:
                    path = os.path.join(root, file)
                    ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL)

    def _container_paths(self, folder: str):
        return (os.path.join(folder, '.lockerette_container.bin'), os.path.join(folder, 'LOCKERETTE_LOCKED.txt'))

    def is_encrypted(self, folder: str) -> bool:
        container, _ = self._container_paths(folder)
        return os.path.exists(container)

    def encrypt_container(self, folder: str, password: str, voiceprint: str, device_id: str, phrase_hash: str | None = None):
        if self.is_encrypted(folder):
            return
        container_path, marker_path = self._container_paths(folder)
        # Pack folder (excluding container and marker if exist preemptively)
        buf = io.BytesIO()
        with tarfile.open(mode='w:gz', fileobj=buf) as tar:
            for root, dirs, files in os.walk(folder):
                for name in files:
                    p = os.path.join(root, name)
                    if p == container_path or p == marker_path:
                        continue
                    arcname = os.path.relpath(p, folder)
                    tar.add(p, arcname=arcname)
        data = buf.getvalue()
        # Generate random DEK
        dek = secrets.token_bytes(32)
        # Derive KEK
        kek = self.derive_key(password, voiceprint, device_id)
        # Primary wrap
        wrap_nonce = secrets.token_bytes(12)
        aes_wrap = AESGCM(kek)
        wrapped_dek = aes_wrap.encrypt(wrap_nonce, dek, None)
        alt_wrap_nonce = b''
        alt_wrapped_dek = b''
        if phrase_hash:
            alt_kek = self.derive_key('PHRASE-'+phrase_hash, voiceprint, device_id)
            alt_wrap_nonce = secrets.token_bytes(12)
            alt_wrapped_dek = AESGCM(alt_kek).encrypt(alt_wrap_nonce, dek, None)
        # Encrypt data with DEK
        data_nonce = secrets.token_bytes(12)
        aes_data = AESGCM(dek)
        ciphertext = aes_data.encrypt(data_nonce, data, None)
        version = b'\x02' if phrase_hash else b'\x01'
        header = b'LOCKERETTE' + version
        # v1: header | wrap_nonce(12)|len_wrapped(2)|wrapped_dek|data_nonce(12)|len_ct(8)|ciphertext
        # v2 adds: alt_wrap_nonce(12)|alt_len_wrapped(2)|alt_wrapped_dek between primary wrap and data nonce
        out = io.BytesIO()
        out.write(header)
        out.write(wrap_nonce)
        out.write(len(wrapped_dek).to_bytes(2,'big'))
        out.write(wrapped_dek)
        if phrase_hash:
            out.write(alt_wrap_nonce)
            out.write(len(alt_wrapped_dek).to_bytes(2,'big'))
            out.write(alt_wrapped_dek)
        out.write(data_nonce)
        out.write(len(ciphertext).to_bytes(8,'big'))
        out.write(ciphertext)
        with open(container_path, 'wb') as f:
            f.write(out.getvalue())
        # Delete originals
        for root, dirs, files in os.walk(folder):
            for name in files:
                p = os.path.join(root, name)
                if p == container_path or p == marker_path:
                    continue
                os.remove(p)
        # Write marker
        with open(marker_path, 'w') as f:
            f.write('Folder encrypted by Lockerette. Do not delete container file.')

    def decrypt_container(self, folder: str, password: str, voiceprint: str, device_id: str, phrase: str | None = None):
        container_path, marker_path = self._container_paths(folder)
        if not os.path.exists(container_path):
            raise ValueError('Folder not in container-encrypted state.')
        with open(container_path, 'rb') as f:
            blob = f.read()
        mv = memoryview(blob)
        if not bytes(mv[:10]) == b'LOCKERETTE':
            raise ValueError('Invalid container magic.')
        ver = mv[10]
        if ver not in (0x01, 0x02):
            raise ValueError('Unsupported container version.')
        idx = 11  # after magic+ver
        wrap_nonce = mv[idx:idx+12].tobytes(); idx += 12
        len_wrapped = int.from_bytes(mv[idx:idx+2], 'big'); idx += 2
        wrapped_dek = mv[idx:idx+len_wrapped].tobytes(); idx += len_wrapped
        alt_wrap_nonce = alt_wrapped_dek = None
        if ver == 0x02:
            alt_wrap_nonce = mv[idx:idx+12].tobytes(); idx += 12
            alt_len = int.from_bytes(mv[idx:idx+2], 'big'); idx += 2
            alt_wrapped_dek = mv[idx:idx+alt_len].tobytes(); idx += alt_len
        data_nonce = mv[idx:idx+12].tobytes(); idx += 12
        len_ct = int.from_bytes(mv[idx:idx+8], 'big'); idx += 8
        ciphertext = mv[idx:idx+len_ct].tobytes()
        kek = self.derive_key(password, voiceprint, device_id)
        aes_wrap = AESGCM(kek)
        try:
            dek = aes_wrap.decrypt(wrap_nonce, wrapped_dek, None)
        except Exception:
            # Attempt phrase recovery if available and provided
            if ver == 0x02 and phrase and alt_wrap_nonce and alt_wrapped_dek:
                phrase_norm = phrase.strip().lower()
                phrase_hash = hashlib.sha256(phrase_norm.encode()).hexdigest()
                alt_kek = self.derive_key('PHRASE-'+phrase_hash, voiceprint, device_id)
                try:
                    dek = AESGCM(alt_kek).decrypt(alt_wrap_nonce, alt_wrapped_dek, None)
                except Exception:
                    raise ValueError('Wrong credentials (cannot unwrap key).')
            else:
                raise ValueError('Wrong credentials (cannot unwrap key).')
        aes_data = AESGCM(dek)
        try:
            data = aes_data.decrypt(data_nonce, ciphertext, None)
        except Exception:
            raise ValueError('Decryption failed (data corrupted).')
        buf = io.BytesIO(data)
        def _safe_members(t):
            for m in t.getmembers():
                p = os.path.normpath(os.path.join(folder, m.name))
                if not p.startswith(os.path.abspath(folder)):
                    continue
                yield m
        with tarfile.open(mode='r:gz', fileobj=buf) as tar:
            tar.extractall(path=folder, members=_safe_members(tar))
        # Cleanup
        os.remove(container_path)
        if os.path.exists(marker_path):
            os.remove(marker_path)
