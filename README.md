<!-- README.md for github.com/Andger1975/ton-semantic-decoder -->

<div align="center">

# 💎 TON Semantic Decoder

**Zero-dependency, high-performance Python module to turn raw TON blockchain events into human-readable insights.**

[![PyPI: not yet](https://img.shields.io/badge/install-just_copy_the_file-00D4FF?style=flat-square)](#-installation)
[![License: MIT](https://img.shields.io/badge/license-MIT-success?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)](https://www.python.org/)
[![Powered by: TonWise](https://img.shields.io/badge/used_in_production_by-TonWise_🛡-FFB800?style=flat-square)](https://tonguard.app)

Extracted from the parsing core of [**@TonWise_Bot**](https://t.me/TonWise_Bot) — the real-time TON fraud-detection layer used in production. This module is the open-source primitive; the hardened production version with threat-intelligence, holder-graph analysis, and decision API lives at [**tonguard.app/docs**](https://tonguard.app/docs).

</div>

---

## ❓ Why use this?

Parsing TON events is painful. You have to deal with raw hex, base64 payloads, NanoTON conversion, and malicious string obfuscation. Standard libraries are too heavy for high-frequency streams (WebSocket trading bots, real-time scanners, MEV pipelines).

This module is what we extracted from the TonWise security engine when we needed sub-millisecond parsing without dragging `pydantic` / `aiohttp` / `tonsdk` into a hot path.

- **Zero Dependencies.** Pure Python standard library. No transitive resolve hell.
- **Insane Speed.** Designed for WebSocket streams — **<0.2ms parsing time** per event.
- **Security First.** Built-in protection against IDN Homograph attacks, URL obfuscation, and invisible Unicode characters.

---

## 🚀 Features

| Capability | What it does |
|---|---|
| **🛡 Hardened Link Parser** | Safely decodes `ton://` deep links. Removes invisible Unicode characters. Validates strict address formats. |
| **👀 Anti-Phishing Defanger** | Converts malicious URLs into neutered form: `https://evil.com` → `hxxps://evil[.]com`. Prevents accidental clicks in logs, support tickets, channel posts. |
| **⚡ Event Normalization** | Flattens complex TonAPI / dTon JSON into readable dictionaries: `{"action": "Sent USDT", "amount": 500}`. |
| **🚨 Threat Detection** | Flags suspicious comments (e.g. `CLAIM`, `GIFT`) and malformed Base64 payloads. |

---

## 📦 Installation

This is a lightweight, zero-dependency module — **you don't even need `pip`**.

```bash
# Option 1 — drop the file in
curl -O https://raw.githubusercontent.com/Andger1975/ton-semantic-decoder/main/ton_semantic_decoder.py

# Option 2 — git clone
git clone https://github.com/Andger1975/ton-semantic-decoder.git
```

Then `from ton_semantic_decoder import TonDecoder`. That's it.

---

## ⚡ Usage

### Parsing a deep link (Wallet Connect / Transfer)

Detects obfuscation attempts and defangs malicious links inside the comment field.

```python
from ton_semantic_decoder import TonDecoder

# A "dirty" link with obfuscation attempts hidden in the comment
sus_link = "ton://transfer/EQ...Address...?amount=500000000&text=h%74tps://scam.site"

data = TonDecoder.parse_ton_link(sus_link)

print(f"Destination: {data['destination']}")
print(f"Amount:      {data['amount']} TON")
print(f"Comment:     {data['comment']}")   # → hxxps://scam[.]site (defanged)

if data['warning']:
    print(f"⚠️ Warning: {data['warning']}")
```

### Normalizing a TonAPI event

```python
from ton_semantic_decoder import TonDecoder

raw_event = {...}  # raw TonAPI / dTon WebSocket payload
clean = TonDecoder.normalize_event(raw_event)

# Returns a flat dict, predictable schema, ready for logging or alerting
# {"action": "Sent USDT", "amount": 500, "from": "EQ...", "to": "EQ...", "comment": "Hi"}
```

### Spotting an IDN homograph attack

```python
suspicious_token_name = "ТONсoin"   # looks like "TONcoin" — actually Cyrillic letters
if TonDecoder.is_homograph(suspicious_token_name):
    print("⚠ IDN homograph attempt — refuse to render")
```

---

## 🔬 What this module covers — and what it doesn't

This OSS module covers **parsing and surface-level security** (links, comments, payloads, Unicode hygiene). It does **not** include the parts of TonWise that require continuous infrastructure: threat-intelligence pools, holder-graph analysis, sybil clustering, decision API.

| Capability | This OSS module | [TonWise](https://tonguard.app/docs) production |
|---|:---:|:---:|
| Parse `ton://` deep links | ✅ | ✅ |
| Defang malicious URLs | ✅ | ✅ |
| IDN homograph detection | ✅ | ✅ |
| Invisible Unicode filtering | ✅ | ✅ |
| Event normalization | ✅ | ✅ |
| Threat-intel address lookup (Lazarus pool) | ❌ | ✅ 100+ known bad actors, growing |
| Holder cluster / sybil detection | ❌ | ✅ Real-time graph analysis |
| PuppetMaster attribution | ❌ | ✅ Multi-wallet collusion mapping |
| AI Agent decision API (ALLOW/REVIEW/BLOCK) | ❌ | ✅ HMAC-signed receipts |
| Real-time scan endpoint | ❌ | ✅ `GET /api/v1/shield` |
| Per-agent anomaly scoring | ❌ | ✅ Pro tier |

Use the OSS module if you need fast, safe parsing inside your own pipeline. Use TonWise if you need to know **whether** an address or contract is part of a coordinated scam pattern — that requires continuously updated threat intelligence and graph state that does not fit inside a single Python file.

---

## 🏗 Built for production traffic

This module is hot-path code from a system that processes thousands of TON scans per day. Design constraints we honored:

- No allocations in steady-state paths beyond what Python forces
- All Unicode normalization done once on input, cached
- Defanging uses string-builder, not regex sub (avoids regex compile thrash)
- No async overhead — pure synchronous, fits any event loop

If you find a TON event that breaks the parser, please open an issue with the raw payload — those are the cases that improve the OSS for everyone.

---

## 🤝 Used by / built on

- [**@TonWise_Bot**](https://t.me/TonWise_Bot) — production TON security bot (scan UI, agent-decision API)
- [**@tonwise_intel**](https://t.me/tonwise_intel) — public threat-intel alert channel
- [**tonguard.app**](https://tonguard.app) — TonWise commercial layer, partner integrations

If you ship something interesting built on this — open a PR adding it here, or DM [@Andger1975](https://t.me/Andger1975).

---

## 📜 License

MIT. Use it in commercial code, modify it, redistribute it. Attribution appreciated, not required.

---

## 🔗 Related

- **[TonWise Docs](https://tonguard.app/docs)** — full Shield + Agent Guard API documentation
- **[TonWise Partners](https://tonguard.app/partners)** — integration shapes for wallets, DEXes, launchpads, KOL tools
- **[TonWise Trust Badge](https://tonguard.app/badge)** — drop-in JS widget for DEX swap UIs
- **[Audit Signature Verification Recipe](https://tonguard.app/docs/audit-signatures)** — offline HMAC verify in any language

---

<sub>Maintained by [Andrey German (@Andger1975)](https://github.com/Andger1975). Built in service of the TON ecosystem.</sub>
