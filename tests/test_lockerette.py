import hashlib
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core import LockeretteCore
from src.device import DeviceBinder
from src.voice import VoiceAuth

TEST_FOLDER = "test_data"
TEST_FILE = os.path.join(TEST_FOLDER, "sample.txt")
VOICE_PASSWORD = "testvoicepass"
USER_PASSWORD = "testpass"
DEVICE_ID = "testdeviceid"

@pytest.fixture(scope="module", autouse=True)
def setup_test_folder():
    os.makedirs(TEST_FOLDER, exist_ok=True)
    with open(TEST_FILE, "w") as f:
        f.write("Hello Lockerette!")
    yield
    for f in os.listdir(TEST_FOLDER):
        os.remove(os.path.join(TEST_FOLDER, f))
    os.rmdir(TEST_FOLDER)

@pytest.fixture
def core():
    return LockeretteCore()

@pytest.fixture
def voice():
    v = VoiceAuth()
    # Mock voice embedding
    emb = np.random.rand(256).astype(np.float32)
    emb_bytes = emb.tobytes()
    # Save encrypted template
    import hashlib

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    key = hashlib.sha256(VOICE_PASSWORD.encode()).digest()
    aesgcm = AESGCM(key)
    enc = aesgcm.encrypt(nonce, emb_bytes, None)
    with open(v.template_path, 'wb') as f:
        f.write(nonce + enc)
    return v

@pytest.fixture
def device():
    return DeviceBinder()

def test_encrypt_decrypt_roundtrip(core, voice, device):
    password = USER_PASSWORD
    voiceprint = password + ':vp'
    device_id = DEVICE_ID
    core.encrypt_folder(TEST_FOLDER, password, voiceprint, device_id)
    assert os.path.exists(TEST_FILE + ".locked")
    core.unlock_folder(TEST_FOLDER, password, voiceprint, device_id)
    with open(TEST_FILE) as f:
        assert f.read() == "Hello Lockerette!"

def test_key_rotation(core, voice, device):
    password = USER_PASSWORD
    voiceprint = password + ':vp'
    device_id = DEVICE_ID
    core.encrypt_folder(TEST_FOLDER, password, voiceprint, device_id)
    core.encrypt_folder(TEST_FOLDER, password + "2", voiceprint, device_id)
    with pytest.raises(ValueError):
        core.unlock_folder(TEST_FOLDER, password, voiceprint, device_id)

def test_device_binding(core, voice, device):
    password = USER_PASSWORD
    voiceprint = password + ':vp'
    device_id = DEVICE_ID
    core.encrypt_folder(TEST_FOLDER, password, voiceprint, device_id)
    with pytest.raises(ValueError):
        core.unlock_folder(TEST_FOLDER, password, voiceprint, device_id + "x")

def test_voice_verification(voice):
    import os

    import numpy as np
    fixed_emb = np.ones(256, dtype=np.float32)
    enc_fun_orig = voice.encoder.embed_utterance
    voice.encoder.embed_utterance = lambda wav: fixed_emb
    import sounddevice as sd
    rec_orig = sd.rec; wait_orig = sd.wait
    def _fake_rec(n, samplerate=16000, channels=1):
        return np.zeros((n, channels), dtype=np.float32)
    sd.rec = _fake_rec
    sd.wait = lambda: None
    try:
        if os.path.exists(voice.template_path):
            os.remove(voice.template_path)
        vp1 = voice.record_and_verify("basepass")
        vp2 = voice.record_and_verify("basepass")
        assert vp1.split(':')[0] == "basepass" and vp2.split(':')[0] == "basepass"
    finally:
        voice.encoder.embed_utterance = enc_fun_orig
        sd.rec = rec_orig; sd.wait = wait_orig

def test_container_roundtrip(tmp_path):
    from src.core import LockeretteCore
    from src.device import DeviceBinder
    device = DeviceBinder(); core = LockeretteCore()
    folder = tmp_path / "vault"; folder.mkdir()
    (folder / "a.txt").write_text("AAA"); (folder / "b.txt").write_text("BBB")
    device_id = device.get_device_id(str(folder)) or "fallback-device"
    password = "pass123"
    voiceprint = password + ':hash1'
    core.encrypt_container(str(folder), password, voiceprint, device_id)
    assert not (folder / "a.txt").exists()
    core.decrypt_container(str(folder), password, voiceprint, device_id)
    assert (folder / "a.txt").read_text() == "AAA"
    assert (folder / "b.txt").read_text() == "BBB"


def test_container_wrong_password(tmp_path):
    from src.core import LockeretteCore
    from src.device import DeviceBinder
    device = DeviceBinder(); core = LockeretteCore()
    folder = tmp_path / "vault"; folder.mkdir()
    (folder / "a.txt").write_text("AAA")
    device_id = device.get_device_id(str(folder)) or "fallback-device"
    pw = "pass123"; vp = pw + ':h1'
    core.encrypt_container(str(folder), pw, vp, device_id)
    with pytest.raises(ValueError):
        core.decrypt_container(str(folder), "wrong", vp, device_id)

def test_container_wrong_device(tmp_path):
    from src.core import LockeretteCore
    from src.device import DeviceBinder
    device = DeviceBinder(); core = LockeretteCore()
    folder = tmp_path / "vault"; folder.mkdir()
    (folder / "a.txt").write_text("AAA")
    device_id = device.get_device_id(str(folder)) or "fallback-device"
    pw = "pass123"; vp = pw + ':h1'
    core.encrypt_container(str(folder), pw, vp, device_id)
    with pytest.raises(ValueError):
        core.decrypt_container(str(folder), pw, vp, device_id + 'x')

def test_container_wrong_voice(tmp_path):
    from src.core import LockeretteCore
    from src.device import DeviceBinder
    device = DeviceBinder(); core = LockeretteCore()
    folder = tmp_path / "vault"; folder.mkdir()
    (folder / "a.txt").write_text("AAA")
    device_id = device.get_device_id(str(folder)) or "fallback-device"
    pw = "pass123"; vp = pw + ':h1'
    core.encrypt_container(str(folder), pw, vp, device_id)
    with pytest.raises(ValueError):
        core.decrypt_container(str(folder), pw, pw + ':DIFF', device_id)


def test_container_phrase_recovery(tmp_path):
    from src.core import LockeretteCore
    from src.device import DeviceBinder
    device = DeviceBinder(); core = LockeretteCore()
    folder = tmp_path / "vaultp"; folder.mkdir()
    (folder / "file.txt").write_text("DATA")
    device_id = device.get_device_id(str(folder)) or "dev"
    pw = "pass123"; vp = pw + ':vp'
    phrase = 'my secure phrase'
    phrase_hash = hashlib.sha256(phrase.strip().lower().encode()).hexdigest()
    core.encrypt_container(str(folder), pw, vp, device_id, phrase_hash=phrase_hash)
    # Wrong password but correct phrase should succeed
    core.decrypt_container(str(folder), "wrongpw", vp, device_id, phrase=phrase)
    assert (folder / "file.txt").read_text() == "DATA"

def test_container_phrase_recovery_fail(tmp_path):
    from src.core import LockeretteCore
    from src.device import DeviceBinder
    device = DeviceBinder(); core = LockeretteCore()
    folder = tmp_path / "vaultf"; folder.mkdir()
    (folder / "file.txt").write_text("DATA")
    device_id = device.get_device_id(str(folder)) or "dev"
    pw = "pass123"; vp = pw + ':vp'
    phrase = 'another phrase'
    phrase_hash = hashlib.sha256(phrase.strip().lower().encode()).hexdigest()
    core.encrypt_container(str(folder), pw, vp, device_id, phrase_hash=phrase_hash)
    with pytest.raises(ValueError):
        core.decrypt_container(str(folder), "wrongpw", vp, device_id, phrase="incorrect phrase")
