# Symmetric Encryption Handler (SEH)

Burp Suite extension for detecting, decrypting, modifying, and re-encrypting symmetric encrypted HTTP payloads.

## Features

- **Multi-Algorithm Support**: AES, DES, 3DES, and Blowfish
- **Custom Editor Tabs**: Decrypt and modify payloads directly in Burp Repeater
- **HTTP History Highlighting**: Automatically highlights requests with encrypted payloads
- **Pattern Matching**: Configurable field detection with regex support
- **Lazy Decryption**: Performance focused on-demand decryption
- **Real-time Re-encryption**: Automatically re-encrypts modified content

## Installation

### Prerequisites
- Burp Suite Professional or Community Edition
- Jython 2.7.2+ standalone JAR

### Steps

1. Download `SymmetricEncryptionHandler.py`
2. In Burp Suite: **Extender** > **Options**
3. Under Python Environment, set Jython standalone JAR location
4. Go to **Extender** > **Extensions** > **Add**
5. Set Extension Type to **Python**
6. Select `SymmetricEncryptionHandler.py`
7. Click **Next**
8. Verify "Extension loaded" appears in output

## Supported Algorithms

| Algorithm | Modes | Key Size | IV Size |
|-----------|-------|----------|---------|
| AES | CBC, GCM, ECB | 16, 24, or 32 bytes | 16 bytes |
| DES | CBC, ECB | 8 bytes | 8 bytes |
| 3DES (DESede) | CBC, ECB | 24 bytes | 8 bytes |
| Blowfish | CBC, ECB | 4-56 bytes | 8 bytes |

**Note:** ECB mode does not use an IV. GCM mode uses authenticated encryption.

## Configuration

### Initial Setup

1. Open the **Symmetric Encryption Handler** tab in Burp
2. Select encryption algorithm from dropdown
3. Configure key and IV (if applicable)
4. Set field patterns for detection
5. Click **Save Settings**

### Detection Patterns

SEH detects encrypted fields by JSON field names:

- **Exact match**: `message`
- **Multiple fields**: `message, data, payload`
- **Regex pattern**: `.*[Mm]essage.*`

Default patterns:
- **Request field**: `message`
- **Response field**: `Data`

### Settings

- **Enable auto-detection**: Show tabs when encrypted payloads detected
- **Highlight encrypted payloads**: Highlight requests in HTTP history (cyan)

## Usage

### Basic Workflow

1. Capture encrypted request in Proxy
2. Send to Repeater
3. Click **Decrypted** tab
4. View plaintext JSON
5. Modify as needed
6. Send - SEH automatically re-encrypts

### Testing for Injection Vulnerabilities

SEH enables testing through encrypted channels:

```json
Original decrypted:
{"userId": 123, "action": "getData"}

Modified for testing:
{"userId": "1' OR '1'='1", "action": "getData"}
```

SEH re-encrypts the modified payload, allowing injection testing through encryption layers.

### XSS Through Encrypted Channel

```json
{
  "name": "\"><marquee direction=\"up\">Chocolate rain",
  "email": "test@test.com"
}
```


## How It Works

1. **Detection**: SEH scans JSON request/response bodies for configured field names
2. **Validation**: Checks if field contains valid base64 with high entropy
3. **Lazy Decryption**: Decrypts only when "Decrypted" tab is viewed
4. **Modification**: User edits plaintext JSON in tab
5. **Re-encryption**: SEH encrypts modified content using configured algorithm
6. **Highlighting**: Cyan highlight applied to encrypted messages in HTTP history

## Requirements

- Burp Suite Professional or Community Edition (2023.x+)
- Jython 2.7.2+ standalone JAR
- Java 8+ (bundled with Burp)

## Troubleshooting

### Tab doesn't appear
- Check "Enable auto-detection" is enabled
- Verify JSON body contains configured field name
- Confirm field value is valid base64

### Decryption fails
- Verify key/IV match application's configuration
- Check selected algorithm is correct
- Ensure key/IV sizes match algorithm requirements

### Extension won't load
- Verify Jython standalone JAR is configured
- Check Extender > Errors tab for details
- Ensure Python environment is set correctly

## Disclaimer

For authorized security testing only. Use only on applications you own or have explicit permission to test.

