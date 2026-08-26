"""One-time deploy script for the AuditAnchor contract to a local Ganache dev chain.

Usage:
    1. docker compose -f infrastructure/docker-compose.yml up -d ganache
    2. python scripts/deploy_contract.py
    3. Copy the printed contract address into BLOCKCHAIN_CONTRACT_ADDRESS in .env
"""
import json
import os

import solcx
from eth_account import Account
from web3 import Web3

from app.core.config import get_settings

CONTRACT_SOURCE = os.path.join(
    os.path.dirname(__file__), "..", "app", "blockchain", "contracts", "AuditAnchor.sol"
)
ABI_OUTPUT = os.path.join(
    os.path.dirname(__file__), "..", "app", "blockchain", "AuditAnchor.abi.json"
)
SOLC_VERSION = "0.8.19"


def compile_contract() -> tuple[list, str]:
    solcx.install_solc(SOLC_VERSION)

    with open(CONTRACT_SOURCE, "r") as handle:
        source = handle.read()

    compiled = solcx.compile_source(
        source,
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
    )
    contract_interface = compiled["<stdin>:AuditAnchor"]
    return contract_interface["abi"], contract_interface["bin"]


def deploy() -> str:
    settings = get_settings()
    if not settings.blockchain_deployer_private_key:
        raise SystemExit("Set BLOCKCHAIN_DEPLOYER_PRIVATE_KEY in .env before deploying")

    abi, bytecode = compile_contract()

    with open(ABI_OUTPUT, "w") as handle:
        json.dump(abi, handle, indent=2)
    print(f"Wrote ABI to {ABI_OUTPUT}")

    w3 = Web3(Web3.HTTPProvider(settings.blockchain_rpc_url))
    account = Account.from_key(settings.blockchain_deployer_private_key)

    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract.constructor().build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address, "pending"),
            "chainId": settings.blockchain_chain_id,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    print(f"Deployed AuditAnchor at {receipt['contractAddress']}")
    print("Set this as BLOCKCHAIN_CONTRACT_ADDRESS in backend/.env")
    return receipt["contractAddress"]


if __name__ == "__main__":
    deploy()
