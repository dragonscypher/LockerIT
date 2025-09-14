import hashlib
import os

import numpy as np
import sounddevice as sd

try:
    import json

    import vosk
    _VOSK_AVAILABLE = True
except Exception:
    _VOSK_AVAILABLE = False
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from resemblyzer import VoiceEncoder


class VoiceAuth:
    def __init__(self):
        self.encoder = VoiceEncoder()
        self.template_path = os.path.expanduser("~/.lockerette_voice.enc")

    def record_and_verify(self, base_password: str, want_transcript: bool = True):
        if not base_password:
            raise ValueError("Base password required before recording.")
        fs = 16000
        audio = sd.rec(int(3 * fs), samplerate=fs, channels=1)
        sd.wait()
        wav = np.squeeze(audio)
        transcript = None
        if want_transcript and _VOSK_AVAILABLE:
            try:
                # Simple energy-based VAD trimming to improve recognition
                import numpy as _np
                model = vosk.Model(lang="en-us")
                rec = vosk.KaldiRecognizer(model, fs)
                # Normalize
                w = wav.astype(float)
                if _np.max(_np.abs(w)) > 0:
                    w = w / _np.max(_np.abs(w))
                frame_len = int(0.02 * fs)  # 20 ms
                energies = []
                for i in range(0, len(w), frame_len):
                    frame = w[i:i+frame_len]
                    if len(frame) == 0:
                        continue
                    energies.append(float(_np.sqrt(_np.mean(frame**2))))
                if energies:
                    thr = max(0.02, float(0.4 * float(_np.median(energies))))
                else:
                    thr = 0.02
                # Collect frames above threshold (with padding)
                voiced = []
                for i in range(0, len(w), frame_len):
                    frame = w[i:i+frame_len]
                    if len(frame) == 0:
                        continue
                    rms = float(_np.sqrt(_np.mean(frame**2)))
                    if rms >= thr:
                        voiced.append(frame)
                if voiced:
                    w_proc = _np.concatenate(voiced)
                else:
                    w_proc = w
                wav_int16 = (w_proc * 32767).astype(_np.int16)
                # Feed in chunks for better partial results
                chunk = int(0.3 * fs)
                for i in range(0, len(wav_int16), chunk):
                    rec.AcceptWaveform(wav_int16[i:i+chunk].tobytes())
                res = json.loads(rec.FinalResult())
                t = (res.get('text') or '').strip()
                transcript = t or None
            except Exception:
                transcript = None
        emb = np.array(self.encoder.embed_utterance(wav), dtype=np.float32)
        emb_bytes = emb.tobytes()
        key_material = hashlib.sha256((base_password + '::voice').encode()).digest()
        if not os.path.exists(self.template_path):
            nonce = os.urandom(12)
            enc = AESGCM(key_material).encrypt(nonce, emb_bytes, None)
            with open(self.template_path, 'wb') as f:
                f.write(nonce + enc)
            template_bytes = emb_bytes
        else:
            with open(self.template_path, 'rb') as f:
                nonce = f.read(12); enc = f.read()
            aesgcm = AESGCM(key_material)
            template = aesgcm.decrypt(nonce, enc, None)
            t_emb = np.frombuffer(template, dtype=np.float32)
            score = np.dot(emb, t_emb) / (np.linalg.norm(emb) * np.linalg.norm(t_emb))
            if score < 0.85:
                raise ValueError("Voice verification failed.")
            template_bytes = template
        return base_password + ':' + hashlib.sha256(template_bytes).hexdigest(), transcript

    def get_voiceprint(self, base_password: str):
        if not os.path.exists(self.template_path):
            raise FileNotFoundError("No voice template enrolled.")
        key_material = hashlib.sha256((base_password + '::voice').encode()).digest()
        with open(self.template_path, 'rb') as f:
            nonce = f.read(12); enc = f.read()
        tmpl = AESGCM(key_material).decrypt(nonce, enc, None)
        return base_password + ':' + hashlib.sha256(tmpl).hexdigest()

    def has_template(self) -> bool:
        return os.path.exists(self.template_path)

    def reenroll(self, base_password: str):
        if not base_password:
            raise ValueError('Base password required.')
        fs = 16000
        audio = sd.rec(int(3 * fs), samplerate=fs, channels=1)
        sd.wait()
        wav = np.squeeze(audio)
        emb = np.array(self.encoder.embed_utterance(wav), dtype=np.float32)
        emb_bytes = emb.tobytes()
        key_material = hashlib.sha256((base_password + '::voice').encode()).digest()
        nonce = os.urandom(12)
        enc = AESGCM(key_material).encrypt(nonce, emb_bytes, None)
        with open(self.template_path, 'wb') as f:
            f.write(nonce + enc)
        return base_password + ':' + hashlib.sha256(emb_bytes).hexdigest()

    def verify_only(self, base_password: str):
        if not self.has_template():
            raise ValueError('No template enrolled.')
        key_material = hashlib.sha256((base_password + '::voice').encode()).digest()
        with open(self.template_path, 'rb') as f:
            nonce = f.read(12); enc = f.read()
        tmpl = AESGCM(key_material).decrypt(nonce, enc, None)
        fs = 16000
        audio = sd.rec(int(3 * fs), samplerate=fs, channels=1)
        sd.wait()
        wav = np.squeeze(audio)
        emb_live = np.array(self.encoder.embed_utterance(wav), dtype=np.float32)
        emb_t = np.frombuffer(tmpl, dtype=np.float32)
        score = np.dot(emb_live, emb_t) / (np.linalg.norm(emb_live) * np.linalg.norm(emb_t))
        if score < 0.85:
            raise ValueError('Voice verification failed.')
        return base_password + ':' + hashlib.sha256(tmpl).hexdigest()
