import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from shamir_mnemonic import generate_mnemonics, combine_mnemonics

AES_KEY_SIZE = 32  # 256-bit key
RSA_KEY_SIZE = 4096  # 4096-bit RSA key
FAILED_ATTEMPTS_LIMIT = 5
FAILED_ATTEMPTS = 0

def generate_rsa_keys():
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

from typing import List, Tuple

def encrypt_file(file_path, public_key):
    aes_key = os.urandom(AES_KEY_SIZE)
    cipher = AES.new(aes_key, AES.MODE_EAX)
    with open(file_path, "rb") as f:
        data = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(data)
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    enc_file_path = file_path + ".enc"
    with open(enc_file_path, "wb") as f:
        f.write(encrypted_aes_key + cipher.nonce + tag + ciphertext)
    mnemonics = generate_mnemonics(
        group_threshold=1,
        groups=[(3, 5)],
        master_secret=aes_key
    )

    messagebox.showinfo("Encryption", f"File Encrypted Successfully!\nSecret Shares:\n{mnemonics}")
    return mnemonics


def decrypt_file(file_path, private_key, secret_shares):
    global FAILED_ATTEMPTS

    if FAILED_ATTEMPTS >= FAILED_ATTEMPTS_LIMIT:
        messagebox.showerror("Security Alert", "Too many failed attempts! File deleted.")
        os.remove(file_path)
        return

    try:
        with open(file_path, "rb") as f:
            encrypted_aes_key = f.read(RSA_KEY_SIZE // 8)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        recovered_key = combine_mnemonics(secret_shares[:3])  # Use 3 shares to reconstruct
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        dec_file_path = file_path.replace(".enc", ".dec")
        with open(dec_file_path, "wb") as f:
            f.write(data)

        messagebox.showinfo("Decryption", f"File Decrypted Successfully!\nSaved as: {dec_file_path}")

    except Exception as e:
        FAILED_ATTEMPTS += 1
        messagebox.showerror("Error", f"Decryption Failed! Attempts Left: {FAILED_ATTEMPTS_LIMIT - FAILED_ATTEMPTS}")

def open_file():
    return filedialog.askopenfilename()

def encrypt_action():
    file_path = open_file()
    if file_path:
        shares = encrypt_file(file_path, public_key)
        messagebox.showinfo("Secret Shares", f"Keep these safe:\n{shares}")

def decrypt_action():
    file_path = open_file()
    if file_path:
        shares_input = simpledialog.askstring("Secret Shares", "Enter at least 3 shares, separated by commas:")
        if shares_input:
            shares_list = shares_input.split(",")  # No need for `bytes.fromhex()`
            decrypt_file(file_path, private_key, shares_list)

private_key, public_key = generate_rsa_keys()
root = tk.Tk()
root.title("Secure File System")

encrypt_btn = tk.Button(root, text="Encrypt File", command=encrypt_action)
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(root, text="Decrypt File", command=decrypt_action)
decrypt_btn.pack(pady=10)

root.mainloop()
