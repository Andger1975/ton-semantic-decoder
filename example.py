import json
from ton_semantic_decoder import TonDecoder

# 1. Mock Data (Typical Jetton Transfer from TonAPI)
mock_event = {
    "event_id": "5555...",
    "timestamp": 1735390000,
    "actions": [
        {
            "type": "JettonTransfer",
            "JettonTransfer": {
                "sender": {"address": "EQ_SCAM_ADDRESS..."},
                "recipient": {"address": "EQ_YOUR_WALLET..."},
                "amount": "1000000000",
                "jetton": {
                    "symbol": "FREE-GIFT",
                    "decimals": 9
                }
            }
        }
    ]
}

my_wallet = "EQ_YOUR_WALLET..."

# 2. Run Decoder
print("--- Parsing Event ---")
info = TonDecoder.parse_event(mock_event, my_wallet)

# 3. Output
print(f"Action:    {info['action']}")
print(f"Direction: {info['direction'].upper()}")
print(f"Details:   {info['description']}")
print(f"Risk:      {'🚨 SCAM DETECTED' if info['is_scam_risk'] else '✅ Safe'}")

if info['is_scam_risk']:
    print("\n[!] TonWise Tip: Never interact with tokens labeled as 'GIFT' or 'CLAIM'.")