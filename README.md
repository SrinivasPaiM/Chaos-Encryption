# 🔐 Lorenz Attractor Chaos Encryptor

A unique message encryption and decryption app based on **chaos theory**. This Python desktop application uses the **Lorenz attractor** to generate highly unpredictable, non-repeating encryption keys from user input — making every message encoded with beautiful math and secure randomness.

<p align="center">
  <img src="https://upload.wikimedia.org/wikipedia/commons/2/22/Lorenz_system_r28_s10_b2-6666.png" alt="Lorenz Attractor" width="400"/>
</p>

## 🚀 Features

- 🔁 **Encrypt & Decrypt** messages using chaos-based keys  
- 🧠 **Lorenz System** dynamics used to generate deterministic chaos  
- 🔐 Combines user **key + salt** to create unique encryption streams  
- 🎨 Intuitive **Tkinter GUI** for ease of use  
- 🔢 Internally converts chaotic points into usable byte sequences  
- 🔄 XOR-based encryption with **SHA-256 entropy enhancement**  
- 💾 **Base64 encoding** for easy sharing & storage of encrypted text

## 🧪 How It Works

1. You enter a message, a key, and a salt.  
2. The program hashes the key to get Lorenz system parameters (`σ`, `ρ`, `β`, `x0`, `y0`, `z0`).  
3. It simulates the **Lorenz attractor** using `scipy.integrate.odeint`.  
4. The resulting chaotic values are normalized and passed through `SHA-256` to create a **chaotic byte stream**.  
5. Your message is XORed with the chaotic bytes and encoded in Base64.

## 🖥️ UI Preview

> 📷 *Add your screenshot here if you want – simply paste an image in the repo!*

## 🔧 Installation

Install dependencies with:

`pip install numpy scipy`

This script runs directly as a desktop app using Tkinter, which comes pre-installed with Python.

## 📝 Example Usage

**Encryption Input:**  
- Message: `The cake is a lie`  
- Key: `portal`  
- Salt: `42`

**Encrypted Output:**  
`a3BJNFwbpOhILB0IYziK0tg=`

**Decrypting with same Key + Salt gives you the original.**

## 📚 Dependencies

- `numpy`  
- `scipy`  
- `tkinter` (built-in)  
- `hashlib` (built-in)  
- `base64` (built-in)

## 🧠 Why Chaos?

The Lorenz system is highly sensitive to initial conditions — even the tiniest change leads to completely different outputs. This makes it a powerful tool for cryptography, especially for generating pseudo-random sequences in a deterministic yet non-repeating way.

## ⚠️ Disclaimer

This is a fun and educational experiment to understand more about chaos-based encryption. While it offers strong randomness, it's not meant to replace industry-grade cryptographic libraries like `cryptography`, `PyNaCl`, or OpenSSL in production systems.

