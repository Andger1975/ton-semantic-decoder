# 💎 TON Semantic Decoder

> **Zero-dependency Python module to turn raw TON blockchain events into human-readable insights.** > *Extracted from the core of [TonWise Security Bot](https://t.me/TonWise_Bot).*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Performance](https://img.shields.io/badge/latency-%3C200ms-green.svg)](https://tonapi.io)

## ❓ Why?
Developers asked us: *"How do you parse hex codes so fast?"*

Parsing raw `TonAPI` events (converting `0x5fcc3d14`, handling decimals, detecting spam) is tedious. We built this module to handle it automatically.

**"Speed is extremely high"** — Verified by Top TON Traders (see [TonDev discussion](https://t.me/tondev)).

## 🚀 Features
- **Lightweight:** Pure Python. No `pydantic`, `aiohttp`, or heavy frameworks.
- **Fast:** Designed for WebSocket streams (<200ms inference).
- **OpCode Parsing:** Automatically recognizes `Call Contract`, `NFT Transfer`, `Jetton Mint`, `DeDust Swap`.
- **Security:** Built-in heuristics for scam tokens (e.g., "CLAIM", "GIFT") and URL sanitization.

## 📦 Installation

Just copy `ton_semantic_decoder.py` into your project. Yes, it's that simple.

## ⚡ Usage

```python
from ton_semantic_decoder import TonDecoder

# event = response_from_tonapi
# my_wallet = "EQ..."

parsed = TonDecoder.parse_event(event, my_wallet)

print(parsed['action']) 
# Output: "💸 Sent USDT"