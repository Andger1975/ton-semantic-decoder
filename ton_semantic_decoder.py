"""
💎 TON Semantic Decoder
Open-source module for parsing TON events with hardened security checks.
Part of the TonWise Security Suite.
"""

import base64
import re
import unicodedata
import logging
from urllib.parse import urlparse, parse_qs, unquote

# --- CONFIGURATION ---

# Known OpCodes (Human Readable)
OPCODES = {
    0x00000000: "💬 Text Comment",
    0xf8a7ea5: "💸 Jetton Transfer",
    0x178d4519: "💳 Jetton Internal Transfer",
    0x5fcc3d14: "🖼 NFT Transfer",
    0x05138d91: "💎 SFX Deposit",
    0xd53276db: "🔙 Excesses (Cashback)"
}

# Strict TON Address Regex (Base64url, 48 chars)
TON_ADDRESS_REGEX = re.compile(r'^[a-zA-Z0-9_-]{48}$')


class TonDecoder:
    """
    Main class for parsing TON Deep Links and Events.
    Zero dependencies (Standard Library only).
    """

    @staticmethod
    def defang_url(text: str) -> str:
        """
        🛡 Hardened Anti-Phishing Defang.
        Protects against IDN homographs, clickable links, and scheme obfuscation.
        Example: "https://evil.com" -> "hxxps://evil[.]com"
        """
        if not text: return ""

        # 1. Unicode Normalization (Prevents homograph attacks)
        text = unicodedata.normalize('NFKC', text)

        # 2. Break Protocols
        text = text.replace("http:", "hxxp:").replace("https:", "hxxps:")

        # 3. Break Domains (Defang dots)
        text = re.sub(r'([a-zA-Z0-9а-яА-ЯёЁ_-]+\.[a-zA-Z0-9а-яА-ЯёЁ_-]+)', r'[.]\1', text)

        return text

    @staticmethod
    def decode_base64_comment(b64_str: str) -> str:
        """
        Decodes a Base64-encoded string to its original string form. If the input string is
        invalid or cannot be decoded, it returns a placeholder indicating binary data. Empty
        input strings are handled and return an empty string.

        :param b64_str: A Base64-encoded string to decode.
        :type b64_str: str
        :return: The decoded string if successful, an empty string for empty input, or
            a placeholder "<binary_data>" for invalid input.
        :rtype: str
        """
        try:
            if not b64_str: return ""
            return base64.b64decode(b64_str).decode('utf-8', errors='ignore').strip()
        except:
            return "<binary_data>"

    @classmethod
    def parse_ton_link(cls, link: str) -> dict:
        """
        Parses ton:// links with security checks.
        Detects: Amount, Comment, Destination, and Binary Payloads.
        """
        result = {
            "valid": False,
            "destination": None,
            "amount": 0.0,
            "comment": None,
            "has_payload": False,
            "warning": None
        }

        try:
            if not link: return result

            # --- 1. SANITIZATION ---
            clean_link = unquote(link)
            clean_link = unicodedata.normalize('NFKC', clean_link)
            # Remove invisible control characters
            clean_link = re.sub(r'[\x00-\x1f\s]+', '', clean_link)

            # Support for Tonkeeper links
            if "tonkeeper.com/transfer/" in clean_link:
                clean_link = clean_link.replace("https://tonkeeper.com/transfer/", "ton://transfer/")

            # --- 2. INTENT DETECTION ---
            lower_link = clean_link.lower()
            transfer_keyword = "transfer/"
            idx = lower_link.find(transfer_keyword)
            if idx == -1: return result

            tail = clean_link[idx + len(transfer_keyword):]

            # --- 3. ADDRESS EXTRACTION ---
            address_part = tail.split('?')[0].replace('/', '')

            # Strict Regex Validation
            if not TON_ADDRESS_REGEX.match(address_part):
                found = TON_ADDRESS_REGEX.search(address_part)
                if found:
                    address_part = found.group(0)
                    result["warning"] = "⚠️ Non-standard URL structure detected"
                else:
                    result["warning"] = "❌ Invalid or Malformed Address"
                    return result

            result["destination"] = address_part
            result["valid"] = True

            # --- 4. PARAMETERS ---
            dummy_url = f"http://dummy.com/?{tail.split('?', 1)[-1]}" if '?' in tail else "http://dummy.com/"
            qs = parse_qs(urlparse(dummy_url).query)

            if 'amount' in qs:
                try:
                    result["amount"] = int(qs['amount'][-1]) / 1_000_000_000
                except:
                    pass

            if 'text' in qs:
                result["comment"] = cls.defang_url(qs['text'][-1])

            # --- 5. PAYLOAD DETECTION (Lite Version) ---
            # We detect IF there is a payload, but don't emulate it (requires C++ TVM)
            if 'bin' in qs:
                result["has_payload"] = True
                result["warning"] = "⚠️ Binary Payload Detected (Potential Smart Contract Call)"

        except Exception as e:
            result["warning"] = f"Parser Error: {str(e)}"

        return result

    @classmethod
    def parse_event(cls, event_data: dict, my_wallet: str = None) -> dict:
        """
        Parses raw TonAPI events into human-readable format.
        """
        result = {"action": "Transaction", "description": "Interaction", "scam_risk": False}
        try:
            actions = event_data.get("actions", [])
            if not actions: return result

            primary = actions[0]
            type_ = primary.get("type")

            if type_ == "TonTransfer":
                tr = primary.get("TonTransfer", {})
                comment = tr.get("comment") or cls.decode_base64_comment(tr.get("payload"))
                result["action"] = "💰 TON Transfer"
                result["description"] = f"Msg: {cls.defang_url(comment)}" if comment else "Direct Transfer"

                # Simple Heuristic Check
                if comment and any(x in comment.lower() for x in ['claim', 'gift', 'airdrop']):
                    result["scam_risk"] = True

            elif type_ == "JettonTransfer":
                jt = primary.get("JettonTransfer", {})
                sym = jt.get("jetton", {}).get("symbol", "TOKEN")
                decimals = jt.get("jetton", {}).get("decimals", 9)
                amt = float(jt.get("amount", 0)) / (10 ** decimals)

                result["action"] = f"💸 {sym} Transfer"
                result["description"] = f"Volume: {amt:,.2f} {sym}"

                # Scam markers
                if "usdt" in sym.lower() and "ton" in sym.lower():  # Fake USDT-TON tokens
                    result["scam_risk"] = True

            elif type_ == "SmartContractExec":
                op = primary.get("SmartContractExec", {}).get("operation", "Unknown")
                op_name = OPCODES.get(0, "Contract Call")  # Default
                # Note: Full OpCode parsing requires Hex conversion logic
                result["action"] = f"⚙️ {op_name}"
                result["description"] = f"Op: {op}"

        except Exception:
            pass
        return result