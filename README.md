# 🔐 Secure Communication System (RSA + Feistel + SHA-256)

A **complete educational implementation of secure communication** between a client and a server, demonstrating **how cryptographic systems work step by step** using **RSA for key exchange**, a **Feistel-based symmetric cipher for message encryption**, and **SHA-256 for integrity verification**.

This project focuses on **understanding**, not just using, cryptography.

---

## 📌 Project Overview

This system establishes a **secure, two-way encrypted communication channel** over an **insecure network**.  
It mirrors how modern protocols (like TLS) work internally:

- **RSA** → Securely exchange a secret key  
- **Symmetric encryption (Feistel)** → Encrypt messages efficiently  
- **SHA-256** → Detect message tampering  

All cryptographic steps are **explicitly implemented and explained**, not hidden behind libraries.

---

## 🧠 Cryptographic Architecture

RSA (Asymmetric) → Secure key exchange
Feistel Cipher → Fast message encryption
SHA-256 → Message integrity verification


---

## ⚙️ Technologies Used

- Python 3
- Sockets (TCP)
- RSA (manual implementation)
- Custom Feistel Cipher
- SHA-256 hashing
- GUI-based Client & Server

---

## 🚀 How It Works

- Server starts → Generates RSA key pair
- Client connects → Receives public key
- Client generates symmetric key
- Client encrypts symmetric key using RSA
- Server decrypts symmetric key using RSA private key
- Secure channel established
- Messages encrypted with Feistel
- Integrity verified with SHA-256
- Two-way secure communication


---

## 🧩 Detailed Phases

### PHASE 1: Server Startup & RSA Key Generation
- Server generates two large primes `p` and `q`
- Computes:
  - `n = p × q`
  - `φ(n) = (p − 1)(q − 1)`
- Chooses public exponent `e = 65537`
- Computes private exponent `d`
- Keeps **private key secret**, shares **public key**

---

### PHASE 2: Client Connection
- Client connects to server via TCP
- At this stage:
  - Connection exists
  - **No encryption yet**
  - Network is vulnerable

---

### PHASE 3: Secure Key Exchange (RSA)
- Server sends **public key (e, n)** to client
- Client generates a **symmetric key**
- Client encrypts the symmetric key using:


c = m^e mod n

- Server decrypts it using:


m = c^d mod n

- Result: **Both now share the same secret key**, securely

---

### PHASE 4: Secure Messaging
- Messages are encrypted using a **Feistel cipher**
- Characteristics:
- 16 rounds
- Block-based
- XOR, substitutions, rotations
- RSA is NOT used for messages (too slow)

---

### PHASE 5: Integrity Protection (SHA-256)
- Before sending:
- Encrypted message is hashed using SHA-256
- Server verifies:
- If hash matches → message is authentic
- If hash differs → message rejected
- Protects against:
- Tampering
- Man-in-the-middle modification

---

### PHASE 6: Two-Way Secure Chat
- Server replies using the same process:
- Encrypt → Hash → Send
- Client verifies hash and decrypts
- Secure communication continues indefinitely

---

## 📊 Security Properties

### ✔ Confidentiality
- Messages are unreadable without the symmetric key

### ✔ Integrity
- Any modification is detected via SHA-256

### ✔ Secure Key Exchange
- RSA prevents secret leakage during key sharing

### ✔ Resistance to Attacks
- Eavesdropping → useless encrypted data
- Message tampering → detected and rejected
- Brute force → computationally infeasible

---


## ✅ Key Takeaways

- **RSA** solves the key distribution problem
- **Symmetric encryption** is used for performance
- **SHA-256** guarantees integrity
- Combining them creates a **secure communication system**

## Secure Chat Application

A Python-based secure messaging application featuring RSA key exchange, Feistel cipher encryption, and SHA-256 integrity verification.

## 🚀 How to Run

### 1. Start the Server

```bash
python gui_server.py
```

- Click "🚀 Start Server" in the GUI
- Server will generate RSA keys automatically

### 2. Start the Client

```bash
python gui_client.py
```

- Click "Connect"
- Client receives the public key and sends encrypted symmetric key

### 3. Start Secure Messaging

After key exchange, both client and server can:

- Send messages encrypted with the Feistel cipher
- Verify integrity with SHA-256
- Chat securely in real time
