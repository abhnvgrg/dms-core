import json
import os
from functools import lru_cache

from eth_account import Account
from web3 import Web3
from web3.contract import Contract

from app.core.config import get_settings

ABI_FILE = os.path.join(os.path.dirname(__file__), "..", "blockchain", "AuditAnchor.abi.json")


class BlockchainNotConfigured(Exception):
    pass


@lru_cache
def _load_abi() -> list:
    with open(ABI_FILE, "r") as handle:
        return json.load(handle)


@lru_cache
def get_web3() -> Web3:
    settings = get_settings()
    return Web3(Web3.HTTPProvider(settings.blockchain_rpc_url))


def get_contract() -> Contract:
    settings = get_settings()
    if not settings.blockchain_contract_address:
        raise BlockchainNotConfigured("BLOCKCHAIN_CONTRACT_ADDRESS is not set")

    w3 = get_web3()
    return w3.eth.contract(
        address=Web3.to_checksum_address(settings.blockchain_contract_address),
        abi=_load_abi(),
    )


def get_deployer_account() -> Account:
    settings = get_settings()
    if not settings.blockchain_deployer_private_key:
        raise BlockchainNotConfigured("BLOCKCHAIN_DEPLOYER_PRIVATE_KEY is not set")

    return Account.from_key(settings.blockchain_deployer_private_key)


def anchor_entry_onchain(
    ledger_entry_id: int, entity_type: str, entity_id: str, entry_hash_hex: str
) -> dict:
    settings = get_settings()
    w3 = get_web3()
    contract = get_contract()
    account = get_deployer_account()

    tx = contract.functions.anchorHash(
        ledger_entry_id,
        entity_type,
        entity_id,
        bytes.fromhex(entry_hash_hex),
    ).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address, "pending"),
            "chainId": settings.blockchain_chain_id,
        }
    )

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    return {"tx_hash": receipt["transactionHash"].hex(), "block_number": receipt["blockNumber"]}


def get_onchain_anchor(ledger_entry_id: int) -> dict | None:
    contract = get_contract()
    entry_hash, timestamp, anchored_by = contract.functions.getAnchor(ledger_entry_id).call()
    if timestamp == 0:
        return None

    return {
        "entry_hash": entry_hash.hex(),
        "timestamp": timestamp,
        "anchored_by": anchored_by,
    }
