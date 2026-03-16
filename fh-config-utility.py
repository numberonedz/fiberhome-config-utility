#!/usr/bin/env python3

#Fiberhome configuration file unpacker
#
#Tested with HG6145F1 ONT Firmware RP4423
#By Adel/NumberOneDZ   |   https://github.com/numberonedz/
#
#Input file(s) are not checked if valid before encryption/decryption

import argparse
import os
import sys
import gzip
import tarfile
import io
import random
import binascii
from Crypto.Cipher import AES

key: int = 0x2537
stringkey = b"ABCDEFGHIJKLMNOP"

def xor_transform(data: bytes, key: int) -> bytes:
    size = len(data)
    out = bytearray(size)
    
    size_div_key = size // key
    
    for i, b in enumerate(data):
        transform_val = (size + key + i) - size_div_key
        out[i] = b ^ (transform_val & 0xFF)
        
    return bytes(out)


def decompress_if_needed(data: bytes) -> bytes:
    if data.startswith(b"\x1F\x8B"):
        return gzip.decompress(data)

    return data


def is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


def extract_tar(data: bytes, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        # Check if the 'filter' parameter is supported (Python 3.12+)
        if hasattr(tarfile, 'data_filter'):
            tar.extractall(out_dir, filter='data')
        else:
            # Fallback for Python < 3.12
            tar.extractall(out_dir)


def fh_config_decrypt(src_path: str, out_path: str):
    with open(src_path, "rb") as f:
        encrypted = f.read()

    # XOR decrypt
    data = xor_transform(encrypted, key)

    # Decompress (if present)
    data = decompress_if_needed(data)

    # TAR extraction (if needed)
    if is_tar(data):
        extract_dir = out_path + "_extracted"
        extract_tar(data, extract_dir)
        print(f"\n[+] Archive extracted to: {os.path.abspath(extract_dir)}")
    else:
        out_path = out_path + "_decrypted"
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"\n[+] Output written to: {os.path.abspath(out_path)}")
        
        
def fh_config_encrypt(src_path: str):
    mandatory_file = "usrconfig_conf"
    optional_file = "voice_digitmap_conf"
    
    files_to_add = []
    
    m_path = os.path.join(src_path, mandatory_file)
    if os.path.exists(m_path):
        files_to_add.append(m_path)
    else:
        print(f"Mandatory file '{mandatory_file}' not found in {src_path}")
        sys.exit(1)

    o_path = os.path.join(src_path, optional_file)
    if os.path.exists(o_path):
        files_to_add.append(o_path)

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for f_path in files_to_add:
            tar.add(f_path, arcname=os.path.basename(f_path))
    
    compressed_data = buffer.getvalue()

    encrypted_data = xor_transform(compressed_data, key)

    random_id = random.randint(10000, 99999)
    filename = f"usrconfig_fh-{random_id}"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, filename)
    
    with open(out_path, "wb") as f:
        f.write(encrypted_data)
        
    print(f"[+] Encryption complete. Output saved to: {os.path.abspath(out_path)}")        
        

def fh_encrypt_string(plaintext: str) -> str:
    cipher = AES.new(stringkey, AES.MODE_ECB)
    block_size = AES.block_size

    data = plaintext.encode("utf-8")
    
    padding = block_size - (len(data) % block_size)
    if padding != block_size:
        data += b"\x00" * padding

    ciphertext = cipher.encrypt(data)
    
    return binascii.hexlify(ciphertext).decode().upper()


def fh_decrypt_string(cipher_hex: str) -> str:
    cipher = AES.new(stringkey, AES.MODE_ECB)

    try:
        ciphertext = bytes.fromhex(cipher_hex)
    except ValueError as e:
        print(f"Invalid input: {e}")
        sys.exit(1)
        
    try:        
        plaintext = cipher.decrypt(ciphertext)
    except ValueError as e:
        print(f"Decrypting error: {e}")
        sys.exit(1)
        
    return plaintext.rstrip(b"\x00").decode("UTF-8")
    
def handle_d(file_path):
    if not os.path.isfile(file_path):
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)

    fh_config_decrypt(os.path.abspath(file_path), os.path.basename(file_path))
	

def handle_e(folder_path):
    if not os.path.isdir(folder_path):
        print(f"[ERROR] Folder not found: {folder_path}")
        sys.exit(1)

    fh_config_encrypt(folder_path)
    
    
def main():
    print("Fiberhome Config Utility by Adel/NumberOneDZ\n")
    
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()

    group.add_argument("-d", metavar="FILE", help="Config file to decrypt")
    group.add_argument("-e", metavar="FOLDER", help="Config file encryption - Enter path that contains usrconfig_conf (mandatory) and voice_digitmap_conf (optional)")
    group.add_argument("-ds", metavar="STRING", help="String decryption")
    group.add_argument("-es", metavar="STRING", help="String encryption")

    # print help if no arguments were passed
    if len(sys.argv) == 1:
        print("This tool allows you to decrypt and re-encrypt configuration files downloaded from the ONT's web interface.\n")
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.d:
        handle_d(args.d)
    elif args.e:
        handle_e(args.e)
    elif args.ds:
        encrypted=fh_decrypt_string(args.ds)
        print(f"Decrypted value: {encrypted}")
    elif args.es:
        encrypted = fh_encrypt_string(args.es)
        print(f"Encrypted value: {encrypted}")


if __name__ == "__main__":
    main()