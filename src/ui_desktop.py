
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QApplication, QDialog, QFileDialog, QLabel,
                             QLineEdit, QMessageBox, QPushButton, QVBoxLayout,
                             QWidget)

from src.core import LockeretteCore
from src.device import DeviceBinder
from src.voice import VoiceAuth


class EnrollDialog(QDialog):
    def __init__(self, password: str, voice: VoiceAuth, parent=None):
        super().__init__(parent)
        self.password = password
        self.voice = voice
        self.voiceprint = None
        self.phrase_hash = None
        self.setWindowTitle('Enroll Voice')
        self.setModal(True)
        self.setFixedSize(420, 200)
        layout = QVBoxLayout()
        self.status = QLabel('Ready to record.')
        # Use Qt.AlignCenter for PyQt5 compatibility
        # Align center with compatibility for different PyQt API styles
        align_center = getattr(Qt, 'AlignCenter', None)
        if align_center is None:
            # Fallback for newer enum style
            try:
                align_center = Qt.AlignmentFlag.AlignCenter
            except Exception:
                align_center = None
        if align_center is not None:
            try:
                self.status.setAlignment(align_center)
            except Exception:
                pass
        layout.addWidget(self.status)
        self.phrase_input = QLineEdit()
        self.phrase_input.setPlaceholderText('Optional: recovery phrase (leave blank to use transcript)')
        layout.addWidget(self.phrase_input)
        self.ok_btn = QPushButton('Start Recording')
        self.ok_btn.clicked.connect(self._do_enroll)
        layout.addWidget(self.ok_btn)
        self.setLayout(layout)

    def _do_enroll(self):
        pwd = self.password
        if not pwd:
            QMessageBox.warning(self, 'Password', 'Enter password first in main window.')
            return
        self.status.setText('Capturing & processing...')
        QApplication.processEvents()
        try:
            explicit_phrase = self.phrase_input.text().strip() or None
            vp, transcript = self.voice.record_and_verify(pwd, want_transcript=True)
            self.voiceprint = vp
            chosen = explicit_phrase or transcript
            if chosen:
                norm = chosen.strip().lower()
                if len(norm) >= 8:
                    import hashlib
                    self.phrase_hash = hashlib.sha256(norm.encode()).hexdigest()
                    source = 'explicit' if explicit_phrase else 'transcript'
                    self.status.setText(f'Voice enrolled. Phrase set ({source}).')
                else:
                    self.status.setText('Voice enrolled. Phrase too short ignored.')
            else:
                self.status.setText('Voice enrolled (no recovery phrase).')
            self.ok_btn.setText('Done')
            try:
                self.ok_btn.clicked.disconnect()
            except Exception:
                pass
            self.ok_btn.clicked.connect(self.accept)
        except Exception as e:
            # If a template exists and verification failed, offer overwrite via reenroll
            if self.voice.has_template():
                resp = QMessageBox.question(
                    self,
                    'Re-Enroll Voice',
                    f'Enrollment failed: {e}\nOverwrite existing voice template?',
                    QMessageBox.Yes | QMessageBox.No
                )
                if resp == QMessageBox.Yes:
                    try:
                        vp = self.voice.reenroll(pwd)
                        self.voiceprint = vp
                        self.status.setText('Template overwritten.')
                        self.ok_btn.setText('Done')
                        try:
                            self.ok_btn.clicked.disconnect()
                        except Exception:
                            pass
                        self.ok_btn.clicked.connect(self.accept)
                        return
                    except Exception as e2:
                        QMessageBox.critical(self, 'Re-Enroll Error', str(e2))
                        self.status.setText('Overwrite failed.')
                        return
            QMessageBox.critical(self, 'Enroll Error', str(e))
            self.status.setText('Failed. Try again.')

class LockeretteUI(QWidget):
    def __init__(self):
        super().__init__()
        self.core = LockeretteCore()
        self.voice = VoiceAuth()
        self.device = DeviceBinder()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Lockerette Encryption Utility')
        layout = QVBoxLayout()
        self.folder_label = QLabel('No folder selected')
        self.select_btn = QPushButton('Select Folder')
        self.select_btn.clicked.connect(self.select_folder)
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.Password)
        self.pw_input.setPlaceholderText('Enter base password')
        self.voice_btn = QPushButton('Enroll / Re-Enroll Voice')
        self.voice_btn.clicked.connect(self.enroll_voice)
        self.encrypt_btn = QPushButton('Encrypt (Container)')
        self.encrypt_btn.clicked.connect(self.encrypt_folder)
        self.unlock_btn = QPushButton('Unlock')
        self.unlock_btn.clicked.connect(self.unlock_folder)
        self.recovery_input = QLineEdit()
        self.recovery_input.setPlaceholderText('Optional recovery phrase for unlock')
        self.status_label = QLabel('Idle')
        layout.addWidget(self.folder_label)
        layout.addWidget(self.select_btn)
        layout.addWidget(self.pw_input)
        layout.addWidget(self.voice_btn)
        layout.addWidget(self.recovery_input)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.unlock_btn)
        layout.addWidget(self.status_label)
        self.setLayout(layout)
        self.setStyleSheet("""
            QWidget { font-family: Segoe UI, Arial; font-size: 11pt; }
            QPushButton { padding:6px 10px; }
            QLabel { padding:2px; }
            QLineEdit { padding:4px; }
        """)
        self.folder = None
        self.voiceprint = None
        self.phrase_hash = None
        self._refresh_buttons()

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Select Folder')
        if folder:
            self.folder = folder
            self.folder_label.setText(folder)
            self._refresh_buttons()

    def _refresh_buttons(self):
        if not self.folder:
            self.encrypt_btn.setEnabled(False)
            self.unlock_btn.setEnabled(False)
            return
        core = self.core
        if core.is_encrypted(self.folder):
            self.encrypt_btn.setEnabled(False)
            self.unlock_btn.setEnabled(True)
            self.folder_label.setText(self.folder + ' (Encrypted)')
        else:
            self.encrypt_btn.setEnabled(True)
            self.unlock_btn.setEnabled(False)

    def enroll_voice(self):
        dlg = EnrollDialog(self.pw_input.text(), self.voice, self)
        if dlg.exec_() == QDialog.Accepted:
            if dlg.voiceprint:
                self.voiceprint = dlg.voiceprint
                self.phrase_hash = dlg.phrase_hash
                QMessageBox.information(self, 'Voice', 'Enrollment complete.')
            else:
                QMessageBox.warning(self, 'Voice', 'Enrollment not completed.')

    def encrypt_folder(self):
        if not self.folder:
            self.folder_label.setText('Select a folder first!')
            return
        password = self.pw_input.text()
        device_id = self.device.get_device_id(self.folder)
        if not self.voice.has_template():
            QMessageBox.warning(self, 'Voice', 'Enroll voice first.')
            return
        if device_id is None:
            QMessageBox.warning(self, 'Device', 'Device ID could not be determined.')
            return
        try:
            # If no enrollment yet, force it now
            if not self.voiceprint:
                QMessageBox.warning(self, 'Voice', 'Enroll voice first.')
                return
            self.core.encrypt_container(self.folder, password, self.voiceprint, device_id, phrase_hash=self.phrase_hash)
            self.folder_label.setText(self.folder + ' (Encrypted)')
            self.status_label.setText('Encryption complete.')
        except Exception as e:
            QMessageBox.critical(self, 'Encrypt Error', str(e))
            self.status_label.setText('Encryption failed.')
        self._refresh_buttons()

    def unlock_folder(self):
        if not self.folder:
            self.folder_label.setText('Select a folder first!')
            return
        password = self.pw_input.text()
        device_id = self.device.get_device_id(self.folder)
        # Live verification each unlock
        if not self.voice.has_template():
            QMessageBox.warning(self, 'Voice', 'Enroll voice first.')
            return
        try:
            voiceprint = self.voice.verify_only(password)
        except Exception as e:
            QMessageBox.critical(self, 'Voice', f'Live voice verification failed: {e}')
            return
        if device_id is None:
            QMessageBox.warning(self, 'Device', 'Device ID could not be determined.')
            return
        try:
            phrase = self.recovery_input.text().strip() or None
            self.core.decrypt_container(self.folder, password, voiceprint, device_id, phrase=phrase)
            self.folder_label.setText(self.folder)
            self.status_label.setText('Decryption complete.')
        except Exception as e:
            QMessageBox.critical(self, 'Decrypt Error', str(e))
            self.status_label.setText('Decryption failed.')
        self._refresh_buttons()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = LockeretteUI()
    win.show()
    app.exec_()
