import json
from web3 import Web3
from django.conf import settings
from web3.middleware import ExtraDataToPOAMiddleware

def get_contract_abi():
    try:
        with open(settings.CONTRACT_ABI_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ABI file not found at {settings.CONTRACT_ABI_PATH}. Returning empty list.")
        return [] 
    except json.JSONDecodeError:
        print(f"Error decoding ABI JSON from {settings.CONTRACT_ABI_PATH}. Returning empty list.")
        return []

def get_web3_instance():
    w3 = Web3(Web3.HTTPProvider(settings.BLOCKCHAIN_URL))
    if settings.APPLY_POA_MIDDLEWARE: 
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3

def get_contract_instance(w3=None):
    if not w3:
        w3 = get_web3_instance()
    
    abi = get_contract_abi()
    contract_address_from_settings = settings.CONTRACT_ADDRESS

    if not contract_address_from_settings or not abi:
        print("Contract address or ABI not configured properly.")
        return None 

    checksum_contract_address = Web3.to_checksum_address(contract_address_from_settings)

    return w3.eth.contract(address=checksum_contract_address, abi=abi)


def register_document_on_chain(document_hash_bytes):
    w3 = get_web3_instance()
    contract = get_contract_instance(w3)
    if not contract:
        raise Exception("Contract instance could not be loaded.")

    account = w3.eth.account.from_key(settings.BACKEND_WALLET_PRIVATE_KEY)
    nonce = w3.eth.get_transaction_count(account.address)

    tx_params = {
        'from': account.address,
        'nonce': nonce,
        'gas': 2000000,
        'gasPrice': w3.eth.gas_price 
    }

    if len(document_hash_bytes) != 32:
        raise ValueError("Document hash must be 32 bytes long.")

    transaction = contract.functions.registerDocument(document_hash_bytes).build_transaction(tx_params)
    signed_tx = w3.eth.account.sign_transaction(transaction, private_key=settings.BACKEND_WALLET_PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def record_signature_on_chain(document_hash_bytes, signer_address):
    w3 = get_web3_instance()
    contract = get_contract_instance(w3)
    if not contract:
        raise Exception("Contract instance could not be loaded.")

    checksum_signer_address = Web3.to_checksum_address(signer_address)

    account = w3.eth.account.from_key(settings.BACKEND_WALLET_PRIVATE_KEY)
    nonce = w3.eth.get_transaction_count(account.address)

    tx_params = {
        'from': Web3.to_checksum_address(account.address), 
        'nonce': nonce,
        'gas': 2000000, 
        'gasPrice': w3.eth.gas_price
    }

    if len(document_hash_bytes) != 32:
        raise ValueError("Document hash must be 32 bytes long.")

    transaction = contract.functions.signDocument(document_hash_bytes, checksum_signer_address).build_transaction(tx_params)
    signed_tx = w3.eth.account.sign_transaction(transaction, private_key=settings.BACKEND_WALLET_PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt

def check_if_deal_is_on_chain(document_hash_bytes, signer_address):
    w3 = get_web3_instance()
    contract = get_contract_instance(w3)
    if not contract:
        print("Contract instance could not be loaded for checking deal status.")
        return False 
    
    checksum_signer_address = Web3.to_checksum_address(signer_address)
    return contract.functions.hasSigned(document_hash_bytes, checksum_signer_address).call()
