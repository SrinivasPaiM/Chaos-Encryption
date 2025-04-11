import numpy as np
from scipy.integrate import odeint
from hashlib import sha256
import tkinter as tk
from tkinter import messagebox, scrolledtext
import base64


def lorenz_system(state, t, sigma, rho, beta):
    x, y, z = state
    dxdt = sigma * (y - x)
    dydt = x * (rho - z) - y
    dzdt = x * y - beta * z
    return [dxdt, dydt, dzdt]


def generate_chaos_key(key: str, steps: int):
    """ Generate a chaotic key using the Lorenz system and SHA-256 hashing for randomness """
    hash_key = sha256(key.encode('utf-8')).hexdigest()

    x0 = int(hash_key[:8], 16) % 20 - 10
    y0 = int(hash_key[8:16], 16) % 20 - 10
    z0 = int(hash_key[16:24], 16) % 20 - 10
    sigma = 10 + int(hash_key[24:32], 16) % 10  # Ensure non-repeating
    rho = 28 + int(hash_key[32:40], 16) % 20
    beta = 2.667 + (int(hash_key[40:48], 16) % 500) / 1000  # Add more decimal precision

    initial_state = [x0, y0, z0]
    t = np.linspace(0, 50, steps * 2)  # Increase time resolution

    solution = odeint(lorenz_system, initial_state, t, args=(sigma, rho, beta))

    chaotic_bytes = ((solution - solution.min()) / (solution.max() - solution.min()) * 255).astype(np.uint8)

    # Strengthen randomness using SHA-256 mixing
    chaos_key = bytearray()
    for value in chaotic_bytes.flatten()[:steps]:
        mixed = sha256(bytes([value])).digest()[:1]  # Take first byte after hashing
        chaos_key.extend(mixed)

    return bytes(chaos_key[:steps])


def encrypt(message: str, key: str, salt: str):
    combined_key = key + salt
    message_bytes = message.encode('utf-8')
    chaos_key = generate_chaos_key(combined_key, len(message_bytes))

    encrypted_bytes = bytes([mb ^ ck for mb, ck in zip(message_bytes, chaos_key)])

    # Encode to base64 for better storage & display
    return base64.b64encode(encrypted_bytes).decode('utf-8')


def decrypt(encrypted_message: str, key: str, salt: str):
    combined_key = key + salt
    encrypted_bytes = base64.b64decode(encrypted_message)
    chaos_key = generate_chaos_key(combined_key, len(encrypted_bytes))

    decrypted_bytes = bytes([eb ^ ck for eb, ck in zip(encrypted_bytes, chaos_key)])
    return decrypted_bytes.decode('utf-8', errors='ignore')


def on_encrypt():
    message = message_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    salt = salt_entry.get().strip()

    if not message or not key or not salt:
        messagebox.showerror("Error", "All fields must be filled.")
        return

    encrypted_message = encrypt(message, key, salt)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted_message)


def on_decrypt():
    try:
        encrypted_message = output_text.get("1.0", tk.END).strip()
        key = key_entry.get().strip()
        salt = salt_entry.get().strip()

        if not encrypted_message or not key or not salt:
            messagebox.showerror("Error", "All fields must be filled.")
            return

        decrypted_message = decrypt(encrypted_message, key, salt)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt. Error: {str(e)}")


root = tk.Tk()
root.title("Lorenz Attractor Encryptor")
root.geometry("500x600")

# Message input
message_label = tk.Label(root, text="Message:")
message_label.pack()
message_entry = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=5)
message_entry.pack(padx=10, pady=5)

# Key input
key_label = tk.Label(root, text="Encryption Key:")
key_label.pack()
key_entry = tk.Entry(root, show="*", width=50)
key_entry.pack(padx=10, pady=5)

# Salt input
salt_label = tk.Label(root, text="Salt:")
salt_label.pack()
salt_entry = tk.Entry(root, width=50)
salt_entry.pack(padx=10, pady=5)

# Encrypt button
encrypt_button = tk.Button(root, text="Encrypt", command=on_encrypt)
encrypt_button.pack(pady=10)

# Decrypt button
decrypt_button = tk.Button(root, text="Decrypt", command=on_decrypt)
decrypt_button.pack(pady=5)

# Output area
output_label = tk.Label(root, text="Output (Encrypted/Decrypted Message):")
output_label.pack()
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=10)
output_text.pack(padx=10, pady=5)

root.mainloop()
