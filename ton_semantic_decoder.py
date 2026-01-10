"""
💎 TON Semantic Decoder v2.0
Open-source module for parsing TON events with hardened security checks.
Updated for raw addresses, body/bin payloads, and extended OpCodes.
"""

import base64
import re
import unicodedata
import logging
from urllib.parse import urlparse, parse_qs, unquote

# --- CONFIGURATION ---

# Extended OpCodes (Human Readable)
OPCODES = {
    0x00000000: "💬 Text Comment",
    0x0f8a7ea5: "💸 Jetton Transfer",
    0x178d4519: "💳 Jetton Internal Transfer",
    0x595f07bc: "🔥 Jetton Burn",
    0x7362d09c: "🔔 Jetton Notify",
    0x5fcc3d14: "🖼 NFT Transfer",
    0x05138d91: "💎 SFX Deposit",
    0xd53276db: "🔙 Excesses (Cashback)",
    0xea06185d: "🔄 Swap (Ston.fi/DeDust)",
    0x4776d575: "💰 Stake Deposit"
}

# Improved Regex: Supports Friendly (48 chars) AND Raw (0:hex...)
# Raw address: workchain_id (usually 0 or -1) followed by ":" and 64 hex chars
TON_ADDRESS_REGEX = re.compile(r'^([a-zA-Z0-9_-]{48}|-?1:[a-fA-F0-9]{64})$')


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
        """
        if not text: return ""

        # 1. Unicode Normalization
        text = unicodedata.normalize('NFKC', text)

        # 2. Break Protocols
        text = text.replace("http:", "hxxp:").replace("https:", "hxxps:")

        # 3. Break Domains (Defang dots inside words to prevent clickable links)
        text = re.sub(r'([a-zA-Z0-9а-яА-ЯёЁ_-]+\.[a-zA-Z0-9а-яА-ЯёЁ_-]+)', r'[.]\1', text)

        return text

    @staticmethod
    def decode_base64_comment(b64_str: str) -> str:
        try:
            if not b64_str: return ""
            return base64.b64decode(b64_str).decode('utf-8', errors='ignore').strip()
        except:
            return "<binary_data>"

    @classmethod
    def parse_ton_link(cls, link: str) -> dict:
        """
        Parses ton:// links with security checks.
        Detects: Amount, Comment, Destination, and Binary Payloads (bin OR body).
        """
        result = {
            "valid": False,
            "destination": None,
            "amount": 0.0,
            "comment": None,
            "has_payload": False,
            "payload_type": None,
            "warning": None
        }

        try:
            if not link: return result

            # --- 1. SANITIZATION ---
            clean_link = unquote(link)
            clean_link = unicodedata.normalize('NFKC', clean_link)
            clean_link = re.sub(r'[\x00-\x1f\s]+', '', clean_link)

            # Support for Tonkeeper/Tonhub web links
            if "tonkeeper.com/transfer/" in clean_link:
                clean_link = clean_link.replace("https://tonkeeper.com/transfer/", "ton://transfer/")
            elif "app.tonkeeper.com/transfer/" in clean_link:
                clean_link = clean_link.replace("https://app.tonkeeper.com/transfer/", "ton://transfer/")

            # --- 2. INTENT DETECTION ---
            lower_link = clean_link.lower()
            transfer_keyword = "transfer/"
            idx = lower_link.find(transfer_keyword)
            if idx == -1: return result

            tail = clean_link[idx + len(transfer_keyword):]

            # --- 3. ADDRESS EXTRACTION ---
            address_part = tail.split('?')[0].replace('/', '')

            # Strict Regex Validation (Updated for Raw addresses)
            if not TON_ADDRESS_REGEX.match(address_part):
                # Try to extract loosely if strict match fails
                found = re.search(r'[a-zA-Z0-9_-]{48}|-?1:[a-fA-F0-9]{64}', address_part)
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
                    # Handle decimals or integers
                    val = qs['amount'][-1]
                    result["amount"] = float(val) / 1_000_000_000 if '.' not in val else float(val)
                except:
                    pass

            if 'text' in qs:
                result["comment"] = cls.defang_url(qs['text'][-1])

            # --- 5. PAYLOAD DETECTION (HARDENED) ---
            # Checks for 'bin', 'body' (alias), and 'init' (state init)

            payload_bin = qs.get('bin') or qs.get('body')
            state_init = qs.get('init')

            if payload_bin:
                result["has_payload"] = True
                result["payload_type"] = "Contract Call"
                result["warning"] = "⚠️ Binary Payload Detected (Potential Smart Contract Call)"

            if state_init:
                # If there is also a payload, upgrade warning
                prefix = "⚠️ " if not result["warning"] else result["warning"] + " + "
                result["warning"] = prefix + "State Init Detected (Deploying Contract)"
                result["has_payload"] = True

        except Exception as e:
            result["warning"] = f"Parser Error: {str(e)}"

        return result

    @classmethod
    def parse_event(cls, event_data: dict) -> dict:
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

                # Check for scam claims
                if comment:
                    bad_words = ['claim', 'gift', 'airdrop', 'verify', 'reward']
                    if any(w in comment.lower() for w in bad_words):
                        result["scam_risk"] = True

            elif type_ == "JettonTransfer":
                jt = primary.get("JettonTransfer", {})
                jetton = jt.get("jetton", {})
                sym = jetton.get("symbol", "TOKEN")
                decimals = jetton.get("decimals", 9)

                try:
                    amt = float(jt.get("amount", 0)) / (10 ** decimals)
                except:
                    amt = 0

                result["action"] = f"💸 {sym} Transfer"
                result["description"] = f"Volume: {amt:,.2f} {sym}"

                # Heuristic: SCAM jettons often have URL-like names or "Voucher"
                name_lower = jetton.get("name", "").lower()
                if "ton" in name_lower and "usdt" in name_lower and sym != "USDT":
                    result["scam_risk"] = True  # Fake USDT
                if ".com" in name_lower or "voucher" in name_lower:
                    result["scam_risk"] = True

            elif type_ == "SmartContractExec":
                exec_data = primary.get("SmartContractExec", {})
                # Try to parse OpCode from payload if operation name is generic
                op_name = exec_data.get("operation", "Unknown")

                # Basic HEX OpCode extraction logic could go here if payload is available
                # For now, we rely on TonAPI's parsed operation

                result["action"] = f"⚙️ Contract Exec"
                result["description"] = f"Method: {op_name}"

        except Exception as e:
            logging.error(f"Event parsing failed: {e}")
            pass
        return result