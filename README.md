# VPN Tunnel
A lightweight and secure **VPN Tunnel** for client and server architecture. It automatically creates virtual network adapters on Windows and Linux servers, encrypts outbound traffic, and forwards it to the server. Connection establishment is fast and secure, utilizing a custom **2-steps handshake**.


## Features
* **WireGuard-inspired Handshake:** Uses HKDF (HMAC-based Extract-and-Expand Key Derivation Function) for a secure, 2-steps handshake.
* **Robust Encryption:** Protects data in transit using the authenticated ChaCha20-Poly1305 encryption algorithm.
* **Cross-Platform Virtual Adapters:** Automatically provisions and configures virtual network interfaces on both Windows and Linux. 


## Stack
* **CFFI:** C Foreign Function Interface for low-level interaction with system C libraries.
* **Cryptography:** Implements high-grade cryptographic primitives, including **ChaCha20-Poly1305** for data encryption and **X25519** for key exchange.
* **Asyncio:** Handles asynchronous network I/O operations and manages internal threading.


## Quick Start

### 1. Environment Setup
Clone the repository, locate the `.env.example` files, create a copy named `.env`, and fill in the required environment variables:
```bash
cp .env.example .env
```

### 2. Generate and Key Management
Generate your asymmetric keys using the provided utility script and place them into their respective directories:
```bash
python script.py
```
* **Client keys location:** `app/keys_X25519/`
* **Server keys location:** `server/keys_X25519/`

### 3. Launching the Application

#### Client Deployment
Run the client application using `uv`. The `--active` flag ensures the project uses the currently active virtual environment:
```bash
uv run --active main.py
```
#### Server Deployment
Build and run the server using Docker. Note that **privileged mode** is required to allow the container to manage virtual network interfaces.

1. **Build the image:**
   ```bash
   docker build -t vpn-server .
   ```
2. **Run the container:**
   ```bash
   docker run --privileged -it vpn-server -a <SERVER_IP> -b "" -p <SERVER_PORT>
   ```
   * `-b` — Server IP address to bind to.
   * `-p` — Server port.