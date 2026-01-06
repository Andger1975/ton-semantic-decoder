from ton_semantic_decoder import TonDecoder

print("💎 TON Semantic Decoder Demo\n")

# --- SCENARIO 1: Parsing a suspicious Deep Link ---
print("1️⃣  Deep Link Analysis")
suspicious_link = "ton://transfer/EQ_FAKE_ADDRESS...?amount=1000000000&text=h%74tps://scam.site&bin=te6ccgEBAQE..."

print(f"Input: {suspicious_link[:30]}...")
link_data = TonDecoder.parse_ton_link(suspicious_link)

print(f"➜ Destination: {link_data['destination']}")
print(f"➜ Comment:     {link_data['comment']}")  # Notice how it defanged 'https' to 'hxxps'
print(f"➜ Payload:     {'YES (Risk of hidden logic)' if link_data['has_payload'] else 'NO'}")

if link_data['warning']:
    print(f"⚠️  WARNING: {link_data['warning']}")

print("-" * 40)

# --- SCENARIO 2: Parsing a Blockchain Event ---
print("2️⃣  Blockchain Event Parsing")

# Mock data simulating a fake "Gift" token transfer
mock_event = {
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

event_data = TonDecoder.parse_event(mock_event)

print(f"➜ Action:      {event_data['action']}")
print(f"➜ Details:     {event_data['description']}")
print(f"➜ Risk Status: {'🚨 SCAM DETECTED' if event_data['scam_risk'] else '✅ Safe'}")

if event_data['scam_risk']:
    print("\n💡 TonWise Tip: Never interact with tokens that claim to be a 'GIFT' or 'AIRDROP'.")

print("\nDone.")