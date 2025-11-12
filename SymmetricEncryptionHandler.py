"""
Symmetric Encryption Handler (SEH) - Burp Suite Extension

Detects, decrypts, modifies, and re-encrypts symmetric encrypted HTTP payloads.
Supports multiple algorithms: AES, DES, 3DES, Blowfish.

Author: Justice
Version: 1.0.0
"""

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from burp import ITab, IScannerCheck, IScanIssue
from burp import IExtensionStateListener, IHttpListener
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from javax.swing import JPanel, JLabel, JTextField, JTextArea, JCheckBox, JButton, JComboBox
from javax.swing import JScrollPane, BoxLayout, Box, BorderFactory, JSplitPane
from java.awt import Component, Dimension, BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener
import base64
import json
import re
import traceback

VERSION = "1.0.0"
EXTENSION_NAME = "Symmetric Encryption Handler"
DEFAULT_AES_KEY = ""
DEFAULT_IV = ""
DEFAULT_REQUEST_FIELDS = "message"
DEFAULT_RESPONSE_FIELDS = "Data"
MAX_SCAN_SIZE = 1048576

class AlgorithmConfig:
    """Algorithm-specific configuration"""
    def __init__(self, name, key_sizes, iv_size, needs_iv):
        self.name = name
        self.key_sizes = key_sizes
        self.iv_size = iv_size
        self.needs_iv = needs_iv
    
    def validate_key_size(self, key_len):
        """Validate key length"""
        if isinstance(self.key_sizes, list):
            return key_len in self.key_sizes
        else:
            return key_len in self.key_sizes
    
    def get_key_size_description(self):
        """Get key size description"""
        if isinstance(self.key_sizes, list):
            return ", ".join(str(s) for s in self.key_sizes) + " bytes"
        else:
            return "{}-{} bytes".format(min(self.key_sizes), max(self.key_sizes))

ALGORITHM_CONFIGS = {
    "AES": AlgorithmConfig("AES", [16, 24, 32], 16, True),
    "DES": AlgorithmConfig("DES", [8], 8, True),
    "DESede": AlgorithmConfig("DESede", [24], 8, True),
    "Blowfish": AlgorithmConfig("Blowfish", range(4, 57), 8, True)
}

class CryptoHelper:
    """Handles symmetric encryption/decryption using Java crypto"""
    
    def __init__(self, key, iv, cipher_string="AES/CBC/PKCS5Padding"):
        self.key = key
        self.iv = iv
        self.cipher_string = cipher_string
        self.algorithm_name = cipher_string.split('/')[0]
        self.mode = cipher_string.split('/')[1] if '/' in cipher_string else "CBC"
        self.config = ALGORITHM_CONFIGS.get(self.algorithm_name)
        self.update_key_bytes()
    
    def update_key_bytes(self):
        """Convert strings to byte arrays"""
        try:
            self.key_bytes = bytearray(self.key.encode('utf-8'))
            self.iv_bytes = bytearray(self.iv.encode('utf-8'))
        except Exception as e:
            raise ValueError("Failed to convert key/IV: {}".format(str(e)))
    
    def decrypt_message(self, encrypted_base64):
        """Decrypt base64 data"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_base64)
            key_spec = SecretKeySpec(self.key_bytes, self.algorithm_name)
            cipher = Cipher.getInstance(self.cipher_string)
            
            if "GCM" in self.cipher_string:
                from javax.crypto.spec import GCMParameterSpec
                gcm_spec = GCMParameterSpec(128, self.iv_bytes)
                cipher.init(Cipher.DECRYPT_MODE, key_spec, gcm_spec)
            elif self.mode == "ECB":
                cipher.init(Cipher.DECRYPT_MODE, key_spec)
            else:
                iv_spec = IvParameterSpec(self.iv_bytes)
                cipher.init(Cipher.DECRYPT_MODE, key_spec, iv_spec)
            
            decrypted = cipher.doFinal(encrypted_bytes)
            decrypted_str = ''.join(chr(b & 0xFF) for b in decrypted)
            return json.loads(decrypted_str)
        except Exception:
            return None
    
    def encrypt_message(self, data):
        """Encrypt data"""
        try:
            json_str = json.dumps(data)
            data_bytes = bytearray(json_str.encode('utf-8'))
            key_spec = SecretKeySpec(self.key_bytes, self.algorithm_name)
            cipher = Cipher.getInstance(self.cipher_string)
            
            if "GCM" in self.cipher_string:
                from javax.crypto.spec import GCMParameterSpec
                gcm_spec = GCMParameterSpec(128, self.iv_bytes)
                cipher.init(Cipher.ENCRYPT_MODE, key_spec, gcm_spec)
            elif self.mode == "ECB":
                cipher.init(Cipher.ENCRYPT_MODE, key_spec)
            else:
                iv_spec = IvParameterSpec(self.iv_bytes)
                cipher.init(Cipher.ENCRYPT_MODE, key_spec, iv_spec)
            
            encrypted = cipher.doFinal(data_bytes)
            encrypted_str = ''.join(chr(b & 0xFF) for b in encrypted)
            return base64.b64encode(encrypted_str).decode('ascii')
        except Exception:
            return None
    
    @staticmethod
    def validate_base64(s):
        """Check if string is valid base64"""
        try:
            if len(s) < 10:
                return False
            base64.b64decode(s)
            return True
        except Exception:
            return False
    
    @staticmethod
    def is_likely_encrypted(data):
        """Check if base64 data is likely encrypted"""
        try:
            decoded = base64.b64decode(data)
            non_printable = sum(1 for b in decoded if (b & 0xFF) < 32 or (b & 0xFF) > 126)
            ratio = float(non_printable) / len(decoded)
            return ratio > 0.3
        except Exception:
            return False

class AlgorithmChangeListener(ActionListener):
    """Algorithm selection change listener"""
    def __init__(self, config_panel):
        self.config_panel = config_panel
    
    def actionPerformed(self, event):
        self.config_panel.on_algorithm_changed()

class ConfigPanel(ITab):
    """Settings panel for SEH configuration"""
    
    def __init__(self, callbacks, extender):
        self.callbacks = callbacks
        self.extender = extender
        self.panel = JPanel()
        self.build_ui()
        self.load_settings()
    
    def build_ui(self):
        """Build settings UI"""
        self.panel.setLayout(BorderLayout())
        settings_panel = JPanel()
        settings_panel.setLayout(GridBagLayout())
        settings_panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        row = 0
        
        # Title
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.HORIZONTAL
        title = JLabel("Symmetric Encryption Handler Settings")
        title_font = title.getFont()
        title.setFont(title_font.deriveFont(title_font.getStyle() | 1, 16.0))
        settings_panel.add(title, gbc)
        row += 1
        
        # Subtitle
        gbc.gridy = row
        gbc.insets = Insets(0, 5, 5, 5)
        subtitle = JLabel("by Justice")
        subtitle_font = subtitle.getFont()
        subtitle.setFont(subtitle_font.deriveFont(10.0))
        settings_panel.add(subtitle, gbc)
        row += 1
        
        # Spacing
        gbc.gridy = row
        gbc.insets = Insets(15, 5, 10, 5)
        settings_panel.add(JLabel(" "), gbc)
        row += 1
        
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.gridwidth = 1
        
        # Algorithm selection
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        algorithm_options = [
            "AES/CBC/PKCS5Padding",
            "AES/GCM/NoPadding",
            "AES/ECB/PKCS5Padding",
            "DES/CBC/PKCS5Padding",
            "DES/ECB/PKCS5Padding",
            "DESede/CBC/PKCS5Padding",
            "DESede/ECB/PKCS5Padding",
            "Blowfish/CBC/PKCS5Padding",
            "Blowfish/ECB/PKCS5Padding"
        ]
        self.algorithm_combo = JComboBox(algorithm_options)
        self.algorithm_combo.addActionListener(AlgorithmChangeListener(self))
        settings_panel.add(self.algorithm_combo, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        algo_label = JLabel("Encryption Algorithm")
        settings_panel.add(algo_label, gbc)
        row += 1
        
        # Key field
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        self.key_field = JTextField(DEFAULT_AES_KEY, 40)
        settings_panel.add(self.key_field, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.key_label = JLabel("Encryption Key (16, 24, or 32 bytes)")
        settings_panel.add(self.key_label, gbc)
        row += 1
        
        # IV field
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        self.iv_field = JTextField(DEFAULT_IV, 40)
        settings_panel.add(self.iv_field, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.iv_label = JLabel("Initialization Vector (16 bytes)")
        settings_panel.add(self.iv_label, gbc)
        row += 1
        
        # Request patterns
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        self.request_fields = JTextField(DEFAULT_REQUEST_FIELDS, 40)
        settings_panel.add(self.request_fields, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        req_label = JLabel("Request Field Names (comma-separated, supports regex)")
        settings_panel.add(req_label, gbc)
        row += 1
        
        # Response patterns
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        self.response_fields = JTextField(DEFAULT_RESPONSE_FIELDS, 40)
        settings_panel.add(self.response_fields, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        resp_label = JLabel("Response Field Names (comma-separated, supports regex)")
        settings_panel.add(resp_label, gbc)
        row += 1
        
        # Spacing before checkboxes
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.insets = Insets(15, 5, 5, 5)
        settings_panel.add(JLabel(" "), gbc)
        row += 1
        
        gbc.insets = Insets(5, 5, 5, 5)
        
        # Checkboxes
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.auto_detect_check = JCheckBox("Enable auto-detection", True)
        settings_panel.add(self.auto_detect_check, gbc)
        row += 1
        
        gbc.gridy = row
        self.scanner_highlight_check = JCheckBox("Highlight encrypted payloads in HTTP history", True)
        settings_panel.add(self.scanner_highlight_check, gbc)
        row += 1
        
        # Spacing before buttons
        gbc.gridy = row
        gbc.insets = Insets(15, 5, 5, 5)
        settings_panel.add(JLabel(" "), gbc)
        row += 1
        
        # Buttons
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.NONE
        button_panel = JPanel()
        button_panel.setLayout(BoxLayout(button_panel, BoxLayout.X_AXIS))
        save_button = JButton("Save Settings", actionPerformed=self.save_settings)
        reset_button = JButton("Reset to Defaults", actionPerformed=self.reset_settings)
        button_panel.add(save_button)
        button_panel.add(Box.createRigidArea(Dimension(10, 0)))
        button_panel.add(reset_button)
        button_panel.add(Box.createHorizontalGlue())
        settings_panel.add(button_panel, gbc)
        row += 1
        
        # Status label
        gbc.gridy = row
        self.status_label = JLabel(" ")
        settings_panel.add(self.status_label, gbc)
        row += 1
        
        # Filler
        gbc.gridy = row
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.BOTH
        settings_panel.add(JLabel(""), gbc)
        
        scroll = JScrollPane(settings_panel)
        self.panel.add(scroll, BorderLayout.CENTER)
    
    def on_algorithm_changed(self):
        """Update UI when algorithm changes"""
        try:
            cipher_string = self.algorithm_combo.getSelectedItem()
            algo_name = cipher_string.split('/')[0]
            mode = cipher_string.split('/')[1]
            
            config = ALGORITHM_CONFIGS.get(algo_name)
            if not config:
                return
            
            self.key_label.setText("Encryption Key ({})".format(config.get_key_size_description()))
            
            if mode == "ECB":
                self.iv_field.setEnabled(False)
                self.iv_label.setText("IV (not used in ECB mode)")
            else:
                self.iv_field.setEnabled(True)
                self.iv_label.setText("Initialization Vector ({} bytes)".format(config.iv_size))
        except Exception as e:
            self.callbacks.printError("Error updating UI: {}".format(str(e)))
    
    def validate_settings(self):
        """Validate configuration"""
        try:
            cipher_string = self.algorithm_combo.getSelectedItem()
            algo_name = cipher_string.split('/')[0]
            mode = cipher_string.split('/')[1]
            
            config = ALGORITHM_CONFIGS.get(algo_name)
            if not config:
                return False, "Unknown algorithm"
            
            key_len = len(self.key_field.getText())
            if not config.validate_key_size(key_len):
                return False, "{} requires key size: {}".format(algo_name, config.get_key_size_description())
            
            if mode != "ECB":
                iv_len = len(self.iv_field.getText())
                if iv_len != config.iv_size:
                    return False, "{} {} requires IV size: {} bytes".format(algo_name, mode, config.iv_size)
            
            return True, None
        except Exception as e:
            return False, "Validation error"
    
    def save_settings(self, event=None):
        """Save settings"""
        try:
            valid, error_msg = self.validate_settings()
            if not valid:
                self.status_label.setText("Error: {}".format(error_msg))
                return
            
            key = self.key_field.getText()
            iv = self.iv_field.getText()
            algorithm = self.algorithm_combo.getSelectedItem()
            
            self.callbacks.saveExtensionSetting("encryption_key", key)
            self.callbacks.saveExtensionSetting("encryption_iv", iv)
            self.callbacks.saveExtensionSetting("algorithm", algorithm)
            self.callbacks.saveExtensionSetting("request_fields", self.request_fields.getText())
            self.callbacks.saveExtensionSetting("response_fields", self.response_fields.getText())
            self.callbacks.saveExtensionSetting("auto_detect", str(self.auto_detect_check.isSelected()))
            self.callbacks.saveExtensionSetting("scanner_highlight", str(self.scanner_highlight_check.isSelected()))
            
            self.extender.update_crypto_helper(key, iv, algorithm)
            self.status_label.setText("Settings saved!")
        except Exception as e:
            self.status_label.setText("Error: {}".format(str(e)))
    
    def load_settings(self):
        """Load settings"""
        try:
            # Load algorithm
            algorithm = self.callbacks.loadExtensionSetting("algorithm")
            if not algorithm:
                key = self.callbacks.loadExtensionSetting("aes_key")
                algorithm = "AES/CBC/PKCS5Padding" if key else "AES/CBC/PKCS5Padding"
            
            for i in range(self.algorithm_combo.getItemCount()):
                if self.algorithm_combo.getItemAt(i) == algorithm:
                    self.algorithm_combo.setSelectedIndex(i)
                    break
            
            # Load key
            key = self.callbacks.loadExtensionSetting("encryption_key")
            if not key:
                key = self.callbacks.loadExtensionSetting("aes_key")
            if key:
                self.key_field.setText(key)
            
            # Load IV
            iv = self.callbacks.loadExtensionSetting("encryption_iv")
            if not iv:
                iv = self.callbacks.loadExtensionSetting("aes_iv")
            if iv:
                self.iv_field.setText(iv)
            
            # Load patterns
            req = self.callbacks.loadExtensionSetting("request_fields")
            if req:
                self.request_fields.setText(req)
            
            resp = self.callbacks.loadExtensionSetting("response_fields")
            if resp:
                self.response_fields.setText(resp)
            
            # Load checkboxes
            auto = self.callbacks.loadExtensionSetting("auto_detect")
            if auto:
                self.auto_detect_check.setSelected(auto == "True")
            
            scan = self.callbacks.loadExtensionSetting("scanner_highlight")
            if scan:
                self.scanner_highlight_check.setSelected(scan == "True")
            
            self.on_algorithm_changed()
        except Exception as e:
            self.callbacks.printError("Error loading settings: {}".format(str(e)))
    
    def reset_settings(self, event=None):
        """Reset to defaults"""
        self.algorithm_combo.setSelectedItem("AES/CBC/PKCS5Padding")
        self.key_field.setText(DEFAULT_AES_KEY)
        self.iv_field.setText(DEFAULT_IV)
        self.request_fields.setText(DEFAULT_REQUEST_FIELDS)
        self.response_fields.setText(DEFAULT_RESPONSE_FIELDS)
        self.auto_detect_check.setSelected(True)
        self.scanner_highlight_check.setSelected(True)
        self.on_algorithm_changed()
        self.status_label.setText("Settings reset")
    
    def getTabCaption(self):
        return EXTENSION_NAME
    
    def getUiComponent(self):
        return self.panel

class DecryptorTab(IMessageEditorTab):
    """Custom editor tab for decrypt/modify/re-encrypt"""
    
    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.controller = controller
        self.editable = editable
        self.txt_input = self.extender.callbacks.createTextEditor()
        self.txt_input.setEditable(editable)
        self.current_message = None
        self.is_request = False
        self.encrypted_field = None
        self.encrypted_value = None
        self.original_json = None
        self.decrypted = False
        self.decryption_error = None
    
    def getTabCaption(self):
        return "Decrypted"
    
    def getUiComponent(self):
        """Return UI and trigger lazy decryption"""
        if not self.decrypted and self.encrypted_value:
            self.perform_decryption()
        return self.txt_input.getComponent()
    
    def isEnabled(self, content, isRequest):
        """Check if tab should be enabled"""
        if not self.extender.config_panel.auto_detect_check.isSelected():
            return False
        
        try:
            if isRequest:
                info = self.extender.helpers.analyzeRequest(content)
            else:
                info = self.extender.helpers.analyzeResponse(content)
            
            body_offset = info.getBodyOffset()
            body_bytes = content[body_offset:]
            body = self.extender.helpers.bytesToString(body_bytes)
            
            if not body or len(body) < 10:
                return False
            
            try:
                json_data = json.loads(body)
            except:
                return False
            
            if isRequest:
                patterns = self.extender.config_panel.request_fields.getText().split(',')
            else:
                patterns = self.extender.config_panel.response_fields.getText().split(',')
            
            for pattern in patterns:
                pattern = pattern.strip()
                if not pattern:
                    continue
                
                if pattern in json_data:
                    value = json_data[pattern]
                    if isinstance(value, basestring) and CryptoHelper.validate_base64(value):
                        return True
                
                try:
                    regex = re.compile(pattern)
                    for key in json_data.keys():
                        if regex.match(key):
                            value = json_data[key]
                            if isinstance(value, basestring) and CryptoHelper.validate_base64(value):
                                return True
                except:
                    pass
            
            return False
        except Exception:
            return False
    
    def setMessage(self, content, isRequest):
        """Set message and prepare for decryption"""
        if content is None:
            self.txt_input.setText(None)
            self.current_message = None
            return
        
        self.current_message = content
        self.is_request = isRequest
        self.decrypted = False
        self.decryption_error = None
        
        try:
            if isRequest:
                info = self.extender.helpers.analyzeRequest(content)
            else:
                info = self.extender.helpers.analyzeResponse(content)
            
            body_offset = info.getBodyOffset()
            body_bytes = content[body_offset:]
            body = self.extender.helpers.bytesToString(body_bytes)
            self.original_json = json.loads(body)
            
            if isRequest:
                patterns = self.extender.config_panel.request_fields.getText().split(',')
            else:
                patterns = self.extender.config_panel.response_fields.getText().split(',')
            
            self.encrypted_field = None
            self.encrypted_value = None
            
            for pattern in patterns:
                pattern = pattern.strip()
                if not pattern:
                    continue
                
                if pattern in self.original_json:
                    value = self.original_json[pattern]
                    if isinstance(value, basestring) and CryptoHelper.validate_base64(value):
                        self.encrypted_field = pattern
                        self.encrypted_value = value
                        break
                
                try:
                    regex = re.compile(pattern)
                    for key in self.original_json.keys():
                        if regex.match(key):
                            value = self.original_json[key]
                            if isinstance(value, basestring) and CryptoHelper.validate_base64(value):
                                self.encrypted_field = key
                                self.encrypted_value = value
                                break
                except:
                    pass
                
                if self.encrypted_field:
                    break
            
            if not self.encrypted_value:
                self.txt_input.setText(bytearray("No encrypted field found"))
        except Exception as e:
            self.txt_input.setText(bytearray("Error: {}".format(str(e))))
    
    def perform_decryption(self):
        """Lazy decrypt"""
        self.decrypted = True
        
        if not self.encrypted_value:
            return
        
        if not self.extender.crypto_helper:
            error_msg = "=== CONFIGURATION REQUIRED ===\nConfigure encryption key and IV in settings tab"
            self.txt_input.setText(bytearray(error_msg))
            return
        
        try:
            decrypted_data = self.extender.crypto_helper.decrypt_message(self.encrypted_value)
            
            if decrypted_data is None:
                error_msg = "=== DECRYPTION ERROR ===\nInvalid key/IV or corrupted data\n\nRaw Base64:\n" + self.encrypted_value
                self.txt_input.setText(bytearray(error_msg))
            else:
                pretty_json = json.dumps(decrypted_data, indent=2)
                self.txt_input.setText(bytearray(pretty_json))
        except Exception as e:
            error_msg = "=== DECRYPTION ERROR ===\n{}\n\nRaw Base64:\n{}".format(str(e), self.encrypted_value)
            self.txt_input.setText(bytearray(error_msg))
    
    def getMessage(self):
        """Get modified message with re-encryption"""
        if not self.current_message or not self.txt_input.isTextModified():
            return self.current_message
        
        if not self.extender.crypto_helper:
            self.extender.callbacks.printError("Configure encryption keys first")
            return self.current_message
        
        try:
            modified_text = self.extender.helpers.bytesToString(self.txt_input.getText())
            
            if modified_text.startswith("=== DECRYPTION ERROR ==="):
                return self.current_message
            
            try:
                modified_data = json.loads(modified_text)
            except Exception:
                self.extender.callbacks.printError("Invalid JSON")
                return self.current_message
            
            encrypted = self.extender.crypto_helper.encrypt_message(modified_data)
            if encrypted is None:
                self.extender.callbacks.printError("Encryption failed")
                return self.current_message
            
            new_json = dict(self.original_json)
            new_json[self.encrypted_field] = encrypted
            new_body = json.dumps(new_json)
            
            if self.is_request:
                info = self.extender.helpers.analyzeRequest(self.current_message)
                headers = info.getHeaders()
                return self.extender.helpers.buildHttpMessage(headers, bytearray(new_body))
            else:
                info = self.extender.helpers.analyzeResponse(self.current_message)
                headers = info.getHeaders()
                return self.extender.helpers.buildHttpMessage(headers, bytearray(new_body))
        except Exception as e:
            self.extender.callbacks.printError("Error: {}".format(str(e)))
            return self.current_message
    
    def isModified(self):
        return self.txt_input.isTextModified()
    
    def getSelectedData(self):
        return self.txt_input.getSelectedText()

class EncryptedPayloadScanIssue(IScanIssue):
    """Scan issue for encrypted payloads"""
    
    def __init__(self, http_service, url, http_messages, field_name, confidence):
        self.http_service = http_service
        self.url = url
        self.http_messages = http_messages
        self.field_name = field_name
        self.confidence_level = confidence
    
    def getUrl(self):
        return self.url
    
    def getIssueName(self):
        return "Encrypted Message Payload Detected"
    
    def getIssueType(self):
        return 0
    
    def getSeverity(self):
        return "Information"
    
    def getConfidence(self):
        return self.confidence_level
    
    def getIssueBackground(self):
        return ("SEH detected base64-encoded encrypted data in JSON fields. "
                "This may indicate symmetric encryption of HTTP payloads.")
    
    def getRemediationBackground(self):
        return None
    
    def getIssueDetail(self):
        return ("Encrypted payload in field: <b>{}</b><br><br>"
                "SEH detected high-entropy base64 data suggesting encryption. "
                "If keys are hardcoded client-side, encryption provides no security.<br><br>"
                "Review encryption implementation and key management."
                .format(self.field_name))
    
    def getRemediationDetail(self):
        return ("Recommendations:<br><ul>"
                "<li>Avoid client-side encryption with hardcoded keys</li>"
                "<li>Use HTTPS for transport security</li>"
                "<li>Implement server-side encryption with proper key management</li>"
                "<li>Use secure session cookies</li>"
                "<li>Regular key rotation</li>"
                "</ul>")
    
    def getHttpMessages(self):
        return self.http_messages
    
    def getHttpService(self):
        return self.http_service

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IScannerCheck, IHttpListener):
    """SEH main extension class"""
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)
        
        # Initialize with empty keys - user must configure
        if DEFAULT_AES_KEY:
            self.crypto_helper = CryptoHelper(DEFAULT_AES_KEY, DEFAULT_IV, "AES/CBC/PKCS5Padding")
        else:
            self.crypto_helper = None
        self.config_panel = ConfigPanel(callbacks, self)
        callbacks.addSuiteTab(self.config_panel)
        
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)
        
        callbacks.printOutput("="*60)
        callbacks.printOutput("{} v{} loaded".format(EXTENSION_NAME, VERSION))
        callbacks.printOutput("="*60)
        callbacks.printOutput("Features:")
        callbacks.printOutput("  - Auto-detect encrypted JSON payloads")
        callbacks.printOutput("  - Decrypt and modify in Repeater")
        callbacks.printOutput("  - HTTP history highlighting")
        callbacks.printOutput("  - Multi-algorithm support")
        callbacks.printOutput("")
        callbacks.printOutput("Algorithms: AES, DES, 3DES, Blowfish (CBC/GCM/ECB)")
        callbacks.printOutput("Default: AES/CBC/PKCS5Padding")
        callbacks.printOutput("")
        callbacks.printOutput("IMPORTANT: Configure encryption key and IV in settings")
        callbacks.printOutput("Configure in '{}' tab".format(EXTENSION_NAME))
        callbacks.printOutput("="*60)
    
    def update_crypto_helper(self, key, iv, cipher_string):
        """Update crypto configuration"""
        try:
            self.crypto_helper = CryptoHelper(key, iv, cipher_string)
            self.callbacks.printOutput("Updated: {}".format(cipher_string))
        except Exception as e:
            self.callbacks.printError("Update failed: {}".format(str(e)))
    
    def createNewInstance(self, controller, editable):
        return DecryptorTab(self, controller, editable)
    
    def doPassiveScan(self, baseRequestResponse):
        """Passive scan for encrypted payloads"""
        if not self.config_panel.scanner_highlight_check.isSelected():
            return None
        
        issues = []
        try:
            request = baseRequestResponse.getRequest()
            if request:
                issue = self.check_for_encrypted_payload(baseRequestResponse, request, True)
                if issue:
                    issues.append(issue)
            
            response = baseRequestResponse.getResponse()
            if response and len(response) < MAX_SCAN_SIZE:
                issue = self.check_for_encrypted_payload(baseRequestResponse, response, False)
                if issue:
                    issues.append(issue)
        except Exception:
            pass
        
        return issues if issues else None
    
    def check_for_encrypted_payload(self, baseRequestResponse, content, is_request):
        """Check for encrypted payload"""
        try:
            if is_request:
                info = self.helpers.analyzeRequest(content)
            else:
                info = self.helpers.analyzeResponse(content)
            
            body_offset = info.getBodyOffset()
            body_bytes = content[body_offset:]
            body = self.helpers.bytesToString(body_bytes)
            
            if not body or len(body) < 10:
                return None
            
            try:
                json_data = json.loads(body)
            except:
                return None
            
            if is_request:
                patterns = self.config_panel.request_fields.getText().split(',')
            else:
                patterns = self.config_panel.response_fields.getText().split(',')
            
            for pattern in patterns:
                pattern = pattern.strip()
                if not pattern:
                    continue
                
                if pattern in json_data:
                    value = json_data[pattern]
                    if isinstance(value, basestring) and len(value) > 100:
                        if CryptoHelper.validate_base64(value) and CryptoHelper.is_likely_encrypted(value):
                            url = self.helpers.analyzeRequest(baseRequestResponse).getUrl()
                            return EncryptedPayloadScanIssue(
                                baseRequestResponse.getHttpService(),
                                url,
                                [baseRequestResponse],
                                pattern,
                                "Certain"
                            )
                
                try:
                    regex = re.compile(pattern)
                    for key in json_data.keys():
                        if regex.match(key):
                            value = json_data[key]
                            if isinstance(value, basestring) and len(value) > 100:
                                if CryptoHelper.validate_base64(value) and CryptoHelper.is_likely_encrypted(value):
                                    url = self.helpers.analyzeRequest(baseRequestResponse).getUrl()
                                    return EncryptedPayloadScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        url,
                                        [baseRequestResponse],
                                        key,
                                        "Tentative"
                                    )
                except:
                    pass
            
            return None
        except Exception:
            return None
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Highlight encrypted payloads in HTTP history"""
        if not self.config_panel.scanner_highlight_check.isSelected():
            return
        
        if toolFlag not in [4, 64]:
            return
        
        try:
            if messageIsRequest:
                request = messageInfo.getRequest()
                if self.has_encrypted_payload(request, True):
                    messageInfo.setHighlight("cyan")
            else:
                response = messageInfo.getResponse()
                if response and self.has_encrypted_payload(response, False):
                    messageInfo.setHighlight("cyan")
        except Exception:
            pass
    
    def has_encrypted_payload(self, content, is_request):
        """Quick check for encrypted payload"""
        try:
            if is_request:
                info = self.helpers.analyzeRequest(content)
            else:
                info = self.helpers.analyzeResponse(content)
            
            body_offset = info.getBodyOffset()
            body_bytes = content[body_offset:]
            body = self.helpers.bytesToString(body_bytes)
            
            if not body or len(body) < 10:
                return False
            
            try:
                json_data = json.loads(body)
            except:
                return False
            
            if is_request:
                patterns = self.config_panel.request_fields.getText().split(',')
            else:
                patterns = self.config_panel.response_fields.getText().split(',')
            
            for pattern in patterns:
                pattern = pattern.strip()
                if not pattern:
                    continue
                
                if pattern in json_data:
                    value = json_data[pattern]
                    if isinstance(value, basestring) and len(value) > 50:
                        if CryptoHelper.validate_base64(value):
                            return True
                
                try:
                    regex = re.compile(pattern)
                    for key in json_data.keys():
                        if regex.match(key):
                            value = json_data[key]
                            if isinstance(value, basestring) and len(value) > 50:
                                if CryptoHelper.validate_base64(value):
                                    return True
                except:
                    pass
            
            return False
        except Exception:
            return False

