import os
import sys
import json
import base58
import bip39
import hdwallet
import binascii
from hdwallet import HDWallet
from hdwallet.bip39 import Bip39MnemonicGenerator
from hdwallet.bip32 import HDKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def keccak256(data):
    digest = hashes.Hash(hashes.Keccak_256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def private_key_to_tron_address(private_key):
    key = HDKey.from_private_key(bytes.fromhex(private_key))
    public_key = key.public_key()
    public_key_hex = public_key.to_hex()
    address_hash = keccak256(bytes.fromhex(public_key_hex))[12:]
    address_hex = '41' + address_hash.hex()
    address_bytes = bytes.fromhex(address_hex)
    tron_address = base58.b58encode_check(address_bytes).decode('utf-8')
    return tron_address

def generate_wallet():
    mnemonic = Bip39MnemonicGenerator().generate()
    seed = bip39.mnemonic_to_seed(mnemonic)
    hd_wallet = HDWallet.from_seed(seed)
    hd_wallet.from_path("m/44'/195'/0'/0/0")
    private_key = hd_wallet.private_key().hex()
    address = private_key_to_tron_address(private_key)
    return {
        "mnemonic": mnemonic,
        "private_key": private_key,
        "address": address,
    }

def save_wallets(wallets, file_format):
    if file_format == 'csv':
        import csv
        with open('wallets.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Mnemonic", "PrivateKey", "WalletAddress"])
            for wallet in wallets:
                writer.writerow([wallet["mnemonic"], wallet["private_key"], wallet["address"]])
    else:
        with open('wallets.json', mode='w') as file:
            json.dump(wallets, file, indent=4)

def main():
    if len(sys.argv) < 2:
        print("⛔️ Error: Please provide the number of wallets to generate!")
        sys.exit(1)
    
    number_of_wallets = int(sys.argv[1])
    if number_of_wallets < 1:
        print("⛔️ Error: Number of wallets must be at least 1!")
        sys.exit(1)

    file_format = 'csv' if len(sys.argv) < 3 else sys.argv[2].lower()
    if file_format not in ["csv", "json"]:
        print('⛔️ Error: Format must be either "csv" or "json"!')
        sys.exit(1)

    wallets = []
    print(f"✨ Generating {number_of_wallets} wallet(s) in {file_format} format...")
    for i in range(number_of_wallets):
        wallet = generate_wallet()
        print(f"Wallet #{i + 1}")
        print("📄 Mnemonic:", wallet["mnemonic"])
        print("🔑 Private Key:", wallet["private_key"])
        print("👛 Wallet Address:", wallet["address"])
        print("-----------------------------------")
        wallets.append(wallet)

    save_wallets(wallets, file_format)
    print(f"✨ Generated and saved {number_of_wallets} wallet(s) in {file_format} format.")

if __name__ == "__main__":
    main()
