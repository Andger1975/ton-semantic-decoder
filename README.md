# 💎 TON Semantic Decoder

**Zero-dependency, high-performance Python module to turn raw TON blockchain events into human-readable insights.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-green)](https://github.com/your-repo)

> 🏗 **Extracted from the core of [TonWise Security Bot](https://t.me/TonWise_Bot).**

---

## ❓ Why use this?

Parsing TON events is painful. You have to deal with raw Hex, base64 payloads, NanoTON conversion, and malicious string obfuscation.

We built this module because standard libraries were too heavy for high-frequency trading streams.
* **Zero Dependencies:** No `pydantic`, `aiohttp`, or `tonsdk`. Just pure Python standard library.
* **Insane Speed:** Designed for WebSocket streams (<0.2ms parsing time).
* **Security First:** Built-in protection against IDN Homograph attacks, URL obfuscation, and invisible Unicode characters.

## 🚀 Features

* **🛡 Hardened Link Parser:** Safely decodes `ton://` deep links, removing "invisible" characters and validating strict address formats.
* **👀 Anti-Phishing:** Automatically "defangs" malicious URLs (e.g., converts `https://evil.com` to `hxxps://evil[.]com`) to prevent accidental clicks.
* **⚡ Event Normalization:** Turns complex JSON structures (TonAPI/dTon) into a flat, readable dictionary: `{'action': 'Sent USDT', 'amount': 500}`.
* **🚨 Threat Detection:** Flags suspicious comments (e.g., "CLAIM", "GIFT") and malformed Base64 payloads.

---

## 📦 Installation

Since this is a lightweight, zero-dependency module, you don't even need `pip`.
**Just copy the `ton_semantic_decoder.py` file into your project.**

Yes, it's that simple.

---

## ⚡ Usage Examples

### 1. Parsing a Deep Link (Wallet Connect / Transfer)
Detects if a link is trying to trick you (e.g., by hiding parameters).

```python
from ton_semantic_decoder import TonDecoder

# A "dirty" link with obfuscation attempts
sus_link = "ton://transfer/EQ...Address...?amount=500000000&text=h%74tps://scam.site"

data = TonDecoder.parse_ton_link(sus_link)

print(f"Destination: {data['destination']}")
print(f"Amount:      {data['amount']} TON")
print(f"Comment:     {data['comment']}") # Output: hxxps://scam[.]site (Defanged!)

if data['warning']:
    print(f"⚠️ Warning: {data['warning']}")