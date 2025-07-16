import sys
import re
import random
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit,
                             QComboBox, QPushButton, QVBoxLayout,
                             QTextEdit, QGridLayout)
from PyQt5.QtGui import (QFont, QIcon, QPixmap, QCursor)
from PyQt5.QtCore import Qt, QEvent
import des
import dec
import re128
import base64alg
import re512
import nebula


class CoderDecoderApp(QWidget):
    def __init__(self):
        super().__init__()
        with open("styles.qss", "r") as f:
            stylesheet = f.read()
        self.setStyleSheet(stylesheet)
        app_icon = QIcon('iconself.png')
        self.setWindowIcon(app_icon)
        self.setWindowTitle("Whisper encryption/decryption tool")
        self.setFixedSize(800, 360)

        # Input/Output Area
        self.message_edit = QTextEdit()
        self.message_edit.setPlaceholderText("Enter or paste input message here...")
        self.message_edit.setAcceptRichText(False)
        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)

        self.message_edit.setFixedHeight(286)
        self.output_edit.setFixedHeight(286)

        input_output_layout = QGridLayout()
        input_output_layout.addWidget(QLabel("Input"), 0, 0)
        input_output_layout.addWidget(self.message_edit, 1, 0)
        input_output_layout.addWidget(QLabel("Output"), 0, 1)
        input_output_layout.addWidget(self.output_edit, 1, 1)

        # Control Area
        self.faq_label = QLabel()
        self.faq_label.setPixmap(QPixmap('question.png'))
        self.clipboard = QApplication.clipboard()
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["DES", "DEC", "RE128", "RE512", "Nebula", "XCrypt", "Base64"])

        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("Example: F505C2")

        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.setObjectName("encryptButton")
        self.encrypt_button.clicked.connect(self.encrypt_message)

        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.setObjectName("decryptButton")
        self.decrypt_button.clicked.connect(self.decrypt_message)

        # Generate Key Button
        generate_key_button = QPushButton("Generate key")
        generate_key_button.clicked.connect(self.generate_key)

        # Copy buttons
        copy_input_button = QPushButton("Copy input")
        copy_input_button.clicked.connect(lambda: self.copy_to_clipboard(self.message_edit))

        copy_output_button = QPushButton("Copy output")
        copy_output_button.clicked.connect(lambda: self.copy_to_clipboard(self.output_edit))

        version_label = QLabel("Whisper 27.65   Build: Beta 01.12.24")
        version_label.setStyleSheet("color: lightgray;")
        version_label.setFont(QFont('Arial', 8))
        control_layout = QVBoxLayout()
        control_layout.addWidget(QLabel("Algorithm"))
        control_layout.addWidget(self.algo_combo)
        control_layout.addWidget(QLabel("Key"))
        control_layout.addWidget(self.key_edit)
        control_layout.addWidget(self.encrypt_button)
        control_layout.addWidget(self.decrypt_button)
        control_layout.addWidget(generate_key_button)
        control_layout.addWidget(copy_input_button)
        control_layout.addWidget(copy_output_button)



        # Main Layout
        main_layout = QGridLayout()
        main_layout.addLayout(input_output_layout, 0, 0, 1, 1)
        main_layout.addLayout(control_layout, 0, 1)
        main_layout.addWidget(version_label, 1, 1, alignment=Qt.AlignRight | Qt.AlignBottom)
        self.setLayout(main_layout)

    def copy_to_clipboard(self, textedit):
        self.clipboard.setText(textedit.toPlainText())

    def generate_key(self):
        key = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=6))
        self.key_edit.setText(key)

    def encrypt_message(self):
        self.process_message("encrypt")

    def decrypt_message(self):
        self.process_message("decrypt")

    def process_message(self, action):
        message = self.message_edit.toPlainText()
        selected_algo = self.algo_combo.currentText()
        key = self.key_edit.text()

        # Key validation
        try:
            if not re.fullmatch(r"^[A-Z0-9]+$", key):
                self.output_edit.setText("Error: Key must contain only uppercase letters and digits.")
                return
            if selected_algo == "DES":
                if action == "encrypt":
                    encrypted = des.encrypt(message, key)
                else:
                    encrypted = des.decrypt(message, key)
            elif selected_algo == "DEC":
                if action == "encrypt":
                    encrypted = dec.encrypt(message, key)
                else:
                    encrypted = dec.decrypt(message, key)
            elif selected_algo == "RE128":
                if action == "encrypt":
                    encrypted = re128.encrypt(message, key)
                else:
                    encrypted = re128.decrypt(message, key)
            elif selected_algo == "Base64":
                if action == "encrypt":
                    encrypted = base64alg.encrypt(message, key)
                else:
                    encrypted = base64alg.decrypt(message, key)
            elif selected_algo == "RE512":
                if action == "encrypt":
                    encrypted = re512.encrypt(message, key)
                else:
                    encrypted = re512.decrypt(message, key)
            else:
                encrypted = "Algorithm not implemented"

            self.output_edit.setText(encrypted)
        except Exception as e:
            self.output_edit.setText(f"Error: {e}")
        except ValueError as e:
            self.output_edit.setText(f"Error: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CoderDecoderApp()
    window.show()
    sys.exit(app.exec_())
