[![Video Explanation](https://img.youtube.com/vi/NflyI_Wr0Vc/maxresdefault.jpg)](https://youtu.be/NflyI_Wr0Vc)

> **Click the image above to watch the full video explanation and demonstration.**

---

# Secure Telemetry Link with Authenticated Diffie–Hellman

## Overview

This project implements a mutually authenticated Diffie–Hellman key exchange and a secure communication channel that simulates the encrypted link between an on-board flight controller and a ground station in aerospace, defence, or satellite systems - where the protection of mission-critical telemetry is crucial. It utilises elliptic curves to achieve strong security with efficient keys suitable for resource-constrained flight controllers. The secure link is demonstrated here between:

- **Bob (Aircraft Flight Computer)** — generates or ingests ADS-C telemetry and transmits it securely.
- **Alice (Ground Control Station)** — receives encrypted telemetry and decrypts it after the authenticated handshake.

The focus is on demonstrating confidentiality, integrity, and authentication using modern cryptographic primitives, as required by the brief.

Telemetry is included only as a realistic payload to show encrypted data transfer after the key exchange.

---

## Cryptographic Features

- **Key Exchange:** X25519 ephemeral Diffie–Hellman  
- **Authentication:** Ed25519 digital signatures  
- **Key Derivation:** HKDF-SHA256  
- **Encryption:** AES-256-GCM (AEAD)  
- **Replay Protection:** Sequence numbers in AEAD additional authenticated data  
- **Forward Secrecy:** Fresh ephemeral keys for every session  
- **Key Confirmation:** HMAC over transcript hash using derived confirmation key  

---

## Requirements

### Python Version
- Python **3.8+**

### Libraries
Install dependencies using:

```bash
pip install -r requirements.txt
```

The required packages are:

- `cryptography`
- `pandas` (only required when using real ADS-C telemetry)

---

## Repository Organisation

- `README.md` - This file
- `future_enhancements.md` - Brief description of future enhancements for real world applications.
- `ITO5163-A2-Report-35619694.pdf` - Report that documents the project (PDF version) - Also includes YouTube link to demo video
- `ITO5163-A2-Report-35619694.docx` - Report that documents the project (Word document) - Also includes YouTube link to demo video
- `ITO5163-A2-Video-Demonstration-35619694.mp4` - Video demonstration of the system

**Project root:** `dh-secure/`
- `requirements.txt` - Python dependencies
- `alice.py` - Ground station
- `bob.py` - Aircraft
- `attacker.py` - MITM attack demonstration
- `handshake.py` - Authenticated DH protocol
- `crypto_suite.py` - Crypto primitives
- `secure_channel.py` - AES-GCM secure channel
- `telemetry_stream.py` - Simulated & real telemetry sources
- `adsc_sample.csv` - Preprocessed real telemetry data
- `keys/` - Directory for generated Ed25519 key pairs (created by setup script)
- `demo_scripts/` - Helper scripts for quick execution
- `raw_data/` - Raw telemetry data from OpenSky Network
  - `adsc_decoded.txt` - Raw telemetry data file (≈5 million lines)
  - `adsc_parser.py` - Parser for converting raw telemetry data to CSV format
- `venv/` - Python virtual environment

---

## Setup Instructions

**Note:** All commands should be run from the `dh-secure/` directory (project root).

The project includes ready-to-use demo scripts so the system can be executed without manually entering long command lines. These scripts ensure that all paths, ports, and arguments are correct.

Before running the system, you need to set up the environment on both machines and exchange public keys.

### 0. Initial Deployment to Raspberry Pi

**STEP A - Copy project to Pi**

From Windows PowerShell on your laptop, navigate to the directory containing the `dh-secure` folder and use SCP to copy it:

```powershell
cd path\to\project\parent
scp -r dh-secure user@pi-ip-address:/home/user/
```

**STEP B - Fix permissions and line endings**

SSH into the Pi and navigate to the project:

```bash
ssh user@pi-ip-address
cd ~/dh-secure
```

Fix ownership and permissions:

```bash
chmod -R u+rwX .
```

Fix Windows CRLF line endings in scripts:

```bash
sed -i 's/\r$//' demo_scripts/*.sh
```

Make scripts executable:

```bash
chmod +x demo_scripts/*.sh
```

### 1. Windows Laptop (Alice) Setup

**STEP A - Navigate to your project**

Open PowerShell and run:

```powershell
cd path\to\project\dh-secure
```

**STEP B - Create the virtual environment**

```powershell
python -m venv venv
```

**STEP C - Activate it**

```powershell
.\venv\Scripts\activate
```

Your terminal should show:

```
(venv)
```

**STEP D - Install requirements**

```powershell
pip install -r requirements.txt
```

### 2. Raspberry Pi (Bob) Setup

**STEP A - Navigate to your project**

Assuming you cloned/copied the directory to `/home/pi`:

```bash
cd ~/dh-secure
```

**STEP B - Update system and install Python venv**

```bash
sudo apt update
sudo apt install python3-venv -y
```

**STEP C - Create virtual environment**

```bash
python3 -m venv venv
```

**STEP D - Activate it**

```bash
source venv/bin/activate
```

**STEP E - Install requirements**

```bash
pip install -r requirements.txt
```

### 3. Generate Keys

**On the laptop (Alice machine)**

Inside the `dh-secure` directory:

```bash
bash demo_scripts/01_generate_keys.sh alice
```

This creates:
- `keys/alice_ed25519_priv.pem`
- `keys/alice_ed25519_pub.pem`

**On the Raspberry Pi**

Inside the Pi's `dh-secure` directory:

```bash
bash demo_scripts/01_generate_keys.sh bob
```

This creates:
- `keys/bob_ed25519_priv.pem`
- `keys/bob_ed25519_pub.pem`

### 4. Exchange ONLY the Public Keys

**Important:** Each party needs the other's **public** key for authentication. Private keys must never be shared.

In real aerospace systems, public keys would be pre-provisioned onto both devices using USB or other secure physical means during aircraft commissioning. For simplicity in this demonstration, we use SCP (Secure Copy Protocol).

**Option A - Manual Transfer:**

Copy Alice's public key to Pi (from Windows PowerShell):

```powershell
scp path\to\dh-secure\keys\alice_ed25519_pub.pem user@pi-ip-address:/home/user/dh-secure/keys/
```

Copy Bob's public key from Pi to laptop (navigate to keys folder first):

```powershell
cd path\to\dh-secure\keys
scp user@pi-ip-address:/home/user/dh-secure/keys/bob_ed25519_pub.pem .
```

**Final key state:**

Laptop (Alice):
```
keys/
  alice_ed25519_priv.pem
  alice_ed25519_pub.pem
  bob_ed25519_pub.pem
```

Pi (Bob):
```
keys/
  bob_ed25519_priv.pem
  bob_ed25519_pub.pem
  alice_ed25519_pub.pem
```

**Option B - Use the sync script:**

The project includes `demo_scripts/01_sync_keys.sh` to automate this. Configure the Pi's connection parameters at the top of the script, then run:

```bash
chmod +x demo_scripts/01_sync_keys.sh
bash demo_scripts/01_sync_keys.sh
```

This script will:
- Copy Alice's public key to the Pi
- Verify Bob's public key exists on the Pi
- Copy Bob's public key back to the laptop

See the comment block at the bottom of `01_sync_keys.sh` for more details.

---

## Running the System

### 1. Start Alice (Ground Control Station)

```bash
bash demo_scripts/02_run_alice.sh
```

Alice will:
- listen on the correct port,
- wait for aircraft to connect,
- perform the authenticated handshake,
- decrypt and log telemetry.

### 2. Start Bob (Aircraft Flight Computer) — Simulated Telemetry

```bash
bash demo_scripts/03_run_bob.sh
```

Bob will:
- load aircraft keys,
- connect to Alice,
- complete the authenticated handshake,
- begin sending encrypted simulated ADS-C telemetry.

### 3. Run Attacker Demo — MITM Attempt

#### Quick Demo (Using Script)

```bash
bash demo_scripts/04_run_attacker.sh
```

This shows:
- how an interceptor cannot modify handshake messages,
- how modified ciphertext fails authentication,
- how integrity + signatures protect the channel.

#### Full MITM Scenario (Manual Setup)

To demonstrate a full man-in-the-middle attack where the attacker sits between Bob and Alice, you'll need three terminals:

**Terminal 1 - Alice (Laptop)**

Open Command Prompt, activate venv, and start Alice listening on port 9000:

```bash
cd path\to\dh-secure
venv\Scripts\activate.bat
python alice.py --host 0.0.0.0 --port 9000
```

**Terminal 2 - Attacker (Laptop)**

In a separate terminal on the same laptop (with venv activated), run the attacker:

```bash
python attacker.py --alice-port 9001 --bob-host <pi-ip-address> --bob-port 9000
```

The attacker listens on port 9001 for Bob's connection and proxies traffic to Alice on port 9000.

**Terminal 3 - Bob (Raspberry Pi)**

SSH into the Pi and run Bob, but **point him at the attacker** (laptop IP, port 9001) instead of directly to Alice:

```bash
ssh user@pi-ip-address
cd ~/dh-secure
source venv/bin/activate
python3 bob.py --host <laptop-ip-address> --port 9001
```

**Why Bob connects to the attacker:** In this scenario, Bob believes he's connecting to Alice but is actually connecting to the attacker's proxy on port 9001. The attacker then forwards traffic to the real Alice on port 9000, attempting to intercept or modify messages. The authentication and integrity mechanisms will detect and reject the attacker's tampering.

### 4. Using Real ADS-C Telemetry

Instead of simulated telemetry, there is an option to use the prerecorded data generated in the parsed `adsc_sample.csv` by running:

```bash
bash demo_scripts/05_run_bob_real.sh
```

instead of Bob. This streams real decoded ADS-C telemetry through the secure channel.

---

## Manual Execution (Optional)

If preferred, the system can also be run directly via Python:

```bash
python alice.py --host 0.0.0.0 --port 9000
python bob.py --host 127.0.0.1 --port 9000 --telemetry-mode simulated
```

But the demo scripts are the recommended way.

---

## Security Features

### MITM Protection via Key Pinning

The system implements **key pinning** to provide genuine MITM (Man-in-the-Middle) resistance:

- Alice loads Bob's expected static public key from `keys/bob_ed25519_pub.pem`
- Bob loads Alice's expected static public key from `keys/alice_ed25519_pub.pem`
- During the handshake, each party verifies that the received static public key matches the expected one
- If keys don't match, the handshake fails immediately with a clear error message

This creates a trusted binding between public keys and identities, preventing an attacker from substituting their own keys.

### Trust Model

Key pinning assumes out-of-band distribution of public keys:
- Public keys are exchanged through a secure channel before runtime (e.g., during aircraft commissioning)
- Each party maintains a trusted reference to the other's public key
- This is standard practice in aerospace/defense systems where configuration is controlled

---

## Additional Notes

- Telemetry is only a payload demonstrating encryption: the cryptography is the actual subject.
- TCP is used as the transport for simplicity; in real avionics this would be replaced by an RF or satellite link.
- The system demonstrates the complete post-handshake encrypted channel with correct use of AEAD and sequence numbers
- Port 9000 is arbitrary for demonstration; real aerospace systems use protocol-specific ports or direct radio/satellite links. Ports are configurable via `--port` argument.
  - This system is transport-agnostic at the cryptographic layer and would sit above any physical/data-link layer required.
