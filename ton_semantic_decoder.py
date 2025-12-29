import base64
import logging
from decimal import Decimal, InvalidOperation
from typing import Dict, Any, Optional

# --- CONFIGURATION 2025 ---
# Expanded OpCodes list based on Tonalytica & TonAPI standards
OPCODES: Dict[str, str] = {
    "0x00000000": "💬 Text Comment",
    "0xf8a7ea5": "💸 Jetton Transfer",
    "0x178d4519": "💳 Jetton Internal Transfer",
    "0x5fcc3d14": "🖼 NFT Transfer",
    "0x05138d91": "💎 SFX Deposit",
    "0xd53276db": "🔙 Excesses (Cashback)",
    "0xea06185d": "💎 Jetton Mint",
    "0x595f07bc": "🔥 Jetton Burn",
    "0x88e2c913": "⚡️ Swap (DeDust/STON)",
    "0x25938561": "🏦 Stake / Add Liquidity"
}


class TonDecoder:
    """
    Handles the decoding and parsing of blockchain event data, including base64 decoding
    and determining semantic interpretations of blockchain interactions. The class includes
    security measures to ensure safe decoding and processing of untrusted data.

    """

    @staticmethod
    def decode_base64_comment(b64_str: Optional[str]) -> str:
        """Decodes base64 payload to utf-8 text safely. Defangs URLs. Prevents DoS."""
        try:
            if not b64_str:
                return ""

            # Security Fix 1: Limit input size to prevent DoS (max 4KB)
            if len(b64_str) > 4096:
                return "<encoded payload too large>"

            decoded = base64.b64decode(b64_str)
            text = decoded.decode('utf-8', errors='ignore').strip()

            # Security Fix 2 & 3: Remove control characters (Log Forging / Terminal Injection)
            # Keep only printable characters. This removes \n, \r, \t and ANSI codes.
            text = "".join(ch for ch in text if ch.isprintable())

            # Security: Defang links to prevent accidental clicks in logs
            return text.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
        except Exception:
            return ""

    @staticmethod
    def parse_event(event_data: Dict[str, Any], my_wallet: str) -> Dict[str, Any]:
        """
        Parses blockchain event data and determines the action performed, direction of the
        transaction, and other relevant information such as amount, sender, and currency.

        This method processes various types of events, including TON transfers, Jetton
        transfers, contract deployments, and smart contract executions. It determines
        attributes like transaction direction (inflow/outflow/neutral), potential scam
        risks based on specific heuristics, and provides a descriptive summary for the event.

        :param event_data: A dictionary containing blockchain event data. The structure of
            the dictionary is expected to include an "actions" key, where each entry
            provides information on the specific event actions.
        :type event_data: Dict[str, Any]

        :param my_wallet: The blockchain address of the wallet performing the operations,
            used to determine the direction of transactions (incoming or outgoing).
        :type my_wallet: str

        :return: A dictionary summarizing the event details, including:
            - action: A textual representation of the event type (e.g., "Received TON").
            - direction: The transaction direction ("in" for incoming, "out" for outgoing,
              or "neutral" for neither).
            - description: Descriptive information about the event.
            - is_scam_risk: A boolean indicating whether the event bears characteristics
              of potential scams.
            - sender: The address of the sender in the transaction, or "Unknown" if not
              provided.
            - amount: The amount involved in the transaction, converted to a floating-point
              representation and adjusted for decimals when applicable.
            - currency: The currency or token involved in the transaction (e.g., "TON" or
              a specific Jetton symbol).
        :rtype: Dict[str, Any]
        """
        result = {
            "action": "Unknown",
            "direction": "neutral",  # in, out, neutral
            "description": "Blockchain interaction",
            "is_scam_risk": False,
            "sender": "Unknown",
            "amount": 0.0,
            "currency": "TON"
        }

        try:
            actions = event_data.get("actions", [])
            if not actions:
                return result

            # Analyze the first primary action
            primary_action = actions[0]
            action_type = primary_action.get("type")

            # --- 1. TON TRANSFER ---
            if action_type == "TonTransfer":
                tr = primary_action.get("TonTransfer", {})

                # Robust comment handling (API v2 might return raw text or base64)
                raw_comment = tr.get("comment")
                if raw_comment:
                    # Attempt decode if it looks like b64, otherwise sanitize raw text
                    decoded = TonDecoder.decode_base64_comment(raw_comment)
                    if not decoded:  # Maybe it was plain text already?
                        decoded = "".join(ch for ch in str(raw_comment) if ch.isprintable())
                    comment = decoded
                else:
                    comment = ""

                sender = tr.get("sender", {}).get("address", "")

                # Fix 4: Use Decimal for financial calculations
                try:
                    amount = float(Decimal(str(tr.get("amount", 0))) / Decimal("1000000000"))
                except (ValueError, InvalidOperation):
                    amount = 0.0

                result["sender"] = sender
                result["amount"] = amount

                # Direction Logic
                if sender == my_wallet:
                    result["direction"] = "out"
                    result["action"] = "💸 Sent TON"
                else:
                    result["direction"] = "in"
                    result["action"] = "💰 Received TON"

                result["description"] = f"Comment: {comment}" if comment else "Direct Transfer"

            # --- 2. JETTON TRANSFER ---
            elif action_type == "JettonTransfer":
                jt = primary_action.get("JettonTransfer", {})
                sender = jt.get("sender", {}).get("address", "")
                symbol = jt.get("jetton", {}).get("symbol", "TOKEN")

                # Security Fix: Cap decimals to prevent CPU exhaustion (DoS) via huge exponentiation
                # Most tokens have 9 or 18 decimals. We cap at 30 to be safe.
                raw_decimals = jt.get("jetton", {}).get("decimals", 9)
                try:
                    decimals = int(raw_decimals)
                    if not (0 <= decimals <= 30):
                        decimals = 9
                except (ValueError, TypeError):
                    decimals = 9

                # Fix 4: Use Decimal here as well
                try:
                    raw_amt = Decimal(str(jt.get("amount", 0)))
                    real_amt = float(raw_amt / (Decimal("10") ** decimals))
                except (ValueError, InvalidOperation):
                    real_amt = 0.0

                result["currency"] = symbol
                result["amount"] = real_amt
                result["sender"] = sender

                if sender == my_wallet:
                    result["direction"] = "out"
                    result["action"] = f"💸 Sent {symbol}"
                else:
                    result["direction"] = "in"
                    result["action"] = f"💰 Received {symbol}"

                result["description"] = f"Volume: {real_amt:,.2f} {symbol}"

                # Scam Heuristics
                if any(x in symbol.lower() for x in ["claim", "gift", "subs", "free", "voucher"]):
                    result["is_scam_risk"] = True
                    result["description"] += " (⚠️ SUSPICIOUS - DO NOT INTERACT)"

            # --- 3. CONTRACT DEPLOY ---
            elif action_type == "ContractDeploy":
                result["action"] = "🏗 Contract Deploy"
                result["description"] = "New wallet initialized"

            # --- 4. SMART CONTRACT EXEC ---
            elif action_type == "SmartContractExec":
                op_code = primary_action.get("SmartContractExec", {}).get("operation", "Unknown")
                op_name = OPCODES.get(op_code, "Call Contract")
                result["action"] = f"⚙️ {op_name}"
                result["description"] = f"OpCode: {op_code}"

        except Exception as e:
            logging.error(f"TonDecoder Error: {e}")
            result["description"] = f"Error parsing: {str(e)}"

        return result