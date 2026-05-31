import os
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

from web3 import Web3

SEPOLIA_RPC         = os.getenv("SEPOLIA_RPC_URL")
ARBITRUM_RPC        = os.getenv("ARBITRUM_SEPOLIA_RPC_URL")

w3_sepolia   = Web3(Web3.HTTPProvider(SEPOLIA_RPC))
w3_arbitrum  = Web3(Web3.HTTPProvider(ARBITRUM_RPC))

TRANSACTIONS = {
    "Sepolia": {
        "w3": w3_sepolia,
        "txs": [
            ("registerFile", "art1.pdf (409 KB)",  "0xc7a4155ee204625b727dcb45ffeea6c5eec35326c6340e67a67cdfbaab2d893a"),
            ("logAccess",    "art1.pdf (409 KB)",  "0xcaeceadb1635221c99373212a8422a5804459b263f1b2faa8e4d63c0facc099e"),
            ("registerFile", "Claude.dmg (268 MB)","0x30c118f265c3cadd3c86d063b510293f339f9859e46affe372cff8041bb0ee50"),
            ("logAccess",    "Claude.dmg (268 MB)","0xdf593b2d0f6241e62e6d85315f19829214a59d83eb3b2f45860087d998074d4f"),
        ],
    },
    "Arbitrum Sepolia": {
        "w3": w3_arbitrum,
        "txs": [
            ("registerFile", "art1.pdf (409 KB)",  "0x1b6d64ab8386be2bc211f07fdcf367d50890fecf5184597e0c90d1845a1bd887"),
            ("logAccess",    "art1.pdf (409 KB)",  "0xbc36c98936bd72dcefc12260cae0f7888256835693c8c51fe26b53061ea69679"),
            ("registerFile", "Claude.dmg (268 MB)","0xca0a7d2962964d94f9ca5f6f70543ef31b49d595e11e6fa7ec0be125236909ca"),
            ("logAccess",    "Claude.dmg (268 MB)","0x36b85c7f4527a890cd7adec042e03231db5833e29e727515eeac0f7364396506"),
        ],
    },
}

def fetch_gas(w3: Web3, tx_hash: str) -> dict:
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        tx      = w3.eth.get_transaction(tx_hash)
        gas_used       = receipt["gasUsed"]
        gas_price_wei  = tx["gasPrice"]
        fee_wei        = gas_used * gas_price_wei
        fee_eth        = fee_wei / 1e18
        gas_price_gwei = gas_price_wei / 1e9
        return {
            "gas_used":       gas_used,
            "gas_price_gwei": gas_price_gwei,
            "fee_eth":        fee_eth,
            "status":         receipt["status"],
        }
    except Exception as e:
        return {"error": str(e)}

print(f"\n{'='*80}")
print("  GAS COST ANALYSIS — reading from already-mined transactions")
print(f"{'='*80}\n")

all_data = {}

for chain_name, info in TRANSACTIONS.items():
    w3 = info["w3"]
    print(f"  {'─'*70}")
    print(f"  {chain_name}")
    print(f"  {'─'*70}")
    connected = w3.is_connected()
    print(f"  RPC connected: {connected}\n")
    if not connected:
        print("  ✗ Cannot reach RPC — skipping\n")
        continue

    rows = []
    for op, label, txhash in info["txs"]:
        g = fetch_gas(w3, txhash)
        if "error" in g:
            print(f"  ✗ {op:<14} {label:<22}  ERROR: {g['error']}")
            rows.append((op, label, None))
        else:
            ok = "✓" if g["status"] == 1 else "✗ REVERTED"
            print(
                f"  {ok}  {op:<14} {label:<22}"
                f"  gas={g['gas_used']:>7,}"
                f"  price={g['gas_price_gwei']:>8.4f} Gwei"
                f"  fee={g['fee_eth']:.8f} ETH"
            )
            rows.append((op, label, g))
    all_data[chain_name] = rows
    print()

print(f"\n{'='*80}")
print("  GAS SUMMARY TABLE")
print(f"{'='*80}")
print(f"  {'Operation':<14} {'File':<22} {'Chain':<20} {'Gas used':>10} {'Gas price':>12} {'Fee (ETH)':>16}")
print(f"  {'-'*14} {'-'*22} {'-'*20} {'-'*10} {'-'*12} {'-'*16}")

total_eth = {"Sepolia": 0.0, "Arbitrum Sepolia": 0.0}

for chain_name, rows in all_data.items():
    for op, label, g in rows:
        if g is None:
            print(f"  {op:<14} {label:<22} {chain_name:<20} {'N/A':>10}")
        else:
            total_eth[chain_name] += g["fee_eth"]
            print(
                f"  {op:<14} {label:<22} {chain_name:<20}"
                f"  {g['gas_used']:>9,}"
                f"  {g['gas_price_gwei']:>9.4f} Gwei"
                f"  {g['fee_eth']:>14.8f} ETH"
            )

print(f"  {'─'*96}")
for chain_name, total in total_eth.items():
    if total > 0:
        print(f"  {'TOTAL':<14} {'4 transactions':<22} {chain_name:<20}  {'':>9}  {'':>12}  {total:>14.8f} ETH")

print(f"\n{'='*80}\n")
