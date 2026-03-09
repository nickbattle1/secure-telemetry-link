#!/usr/bin/env python3
# ITO5163 Assessment 2
# Student ID: 35619694
# Student Name: Nicholas Battle

"""
Attacker (Man-in-the-Middle Proxy)

Demonstrates security properties by attempting to intercept and tamper with
the communication between Alice and Bob. This script shows that:
- Signature verification prevents impersonation
- Authentication tags prevent message tampering
- Key confirmation detects MITM attacks

Usage:
    python attacker.py --alice-port <port> --bob-host <host> --bob-port <port>
"""

import socket
import json
import argparse
import sys
import threading


class Attacker:
    """
    Man-in-the-middle proxy that attempts to intercept and tamper with traffic.
    """
    
    def __init__(self, alice_port, bob_host, bob_port):
        """
        Initialize attacker proxy.
        
        Args:
            alice_port: Port to listen for Alice's connection
            bob_host: Bob's real hostname/IP
            bob_port: Bob's real port
        """
        self.alice_port = alice_port
        self.bob_host = bob_host
        self.bob_port = bob_port
        self.alice_socket = None
        self.bob_socket = None
        self.server_socket = None
    
    def start_proxy(self):
        """
        Start listening for Alice's connection.
        """
        try:
            # Set up TCP server to intercept Alice
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.alice_port))
            self.server_socket.listen(1)
            
            print(f"[Attacker] Listening on port {self.alice_port} (pretending to be Bob)")
            print(f"[Attacker] Will forward to real Bob at {self.bob_host}:{self.bob_port}")
            print("[Attacker] Waiting for Alice to connect...")
            
        except Exception as e:
            print(f"[Attacker] Error starting proxy: {e}")
            sys.exit(1)
    
    def accept_alice(self):
        """
        Accept connection from Alice.
        """
        try:
            self.alice_socket, client_address = self.server_socket.accept()
            print(f"[Attacker] Alice connected from {client_address[0]}:{client_address[1]}")
            
        except Exception as e:
            print(f"[Attacker] Error accepting Alice: {e}")
            raise
    
    def connect_to_bob(self):
        """
        Connect to the real Bob.
        """
        try:
            # Establish connection to Legitimate Bob
            print(f"[Attacker] Connecting to real Bob at {self.bob_host}:{self.bob_port}...")
            self.bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.bob_socket.connect((self.bob_host, self.bob_port))
            print("[Attacker] Connected to Bob")
            
        except Exception as e:
            print(f"[Attacker] Error connecting to Bob: {e}")
            raise
    
    def recv_json(self, sock):
        """
        Receive JSON message from socket.
        
        Args:
            sock: Socket to receive from
            
        Returns:
            dict: Parsed JSON message
        """
        buffer = b''
        while b'\n' not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            buffer += chunk
        
        message = buffer.split(b'\n')[0]
        return json.loads(message.decode())
    
    def send_json(self, sock, data):
        """
        Send JSON message over socket.
        
        Args:
            sock: Socket to send to
            data: Dictionary to send as JSON
        """
        message = json.dumps(data).encode() + b'\n'
        sock.sendall(message)
    
    def tamper_with_message(self, message, direction):
        """
        Attempt to tamper with a message.
        
        Args:
            message: dict containing the message
            direction: "alice->bob" or "bob->alice"
            
        Returns:
            dict: Modified message
        """
        msg_type = message.get("type", "unknown")
        
        print(f"\n[Attacker] Intercepted {direction}: {msg_type}")
        
        # Demonstrate various cryptographic attack attempts (all should fail)
        
        # Try different attacks based on message type
        if msg_type == "client_hello":
            # Attack 1: Replace ephemeral key (will fail signature check)
            print("[Attacker] Attempting to replace Alice's ephemeral public key...")
            original = message["ephemeral_public_key"]
            message["ephemeral_public_key"] = "00" * 32
            print(f"[Attacker] Original key: {original[:32]}...")
            print(f"[Attacker] Replaced with: {message['ephemeral_public_key'][:32]}...")
            
        elif msg_type == "server_response":
            # Attack 2: Forge signature (will fail Ed25519 verification)
            print("[Attacker] Attempting to tamper with Bob's signature...")
            original = message["signature"]
            message["signature"] = "ff" * 64  # Invalid signature
            print(f"[Attacker] Original sig: {original[:32]}...")
            print(f"[Attacker] Replaced with: {message['signature'][:32]}...")
            
        elif msg_type == "client_auth":
            # Attack 3: Modify authentication (will fail signature verification)
            print("[Attacker] Attempting to modify client authentication...")
            # This will fail signature verification
            original = message["signature"]
            message["signature"] = "aa" * 64  # Invalid signature
            print(f"[Attacker] Original sig: {original[:32]}...")
            print(f"[Attacker] Replaced with: {message['signature'][:32]}...")
            
        elif msg_type == "key_confirm":
            # Attack 4: Alter HMAC (will fail key confirmation)
            print("[Attacker] Attempting to modify key confirmation tag...")
            original = message["tag"]
            message["tag"] = "bb" * 32  # invalid HMAC
            print(f"[Attacker] Original tag: {original[:32]}...")
            print(f"[Attacker] Replaced with: {message['tag'][:32]}...")
            
        elif msg_type == "data":
            # Attack 5: Tamper with encrypted data (will fail GCM auth)
            print("[Attacker] Attempting to modify encrypted telemetry...")
            ciphertext = message["ciphertext"]
            # Flip some bits in the ciphertext
            modified = "ff" * 16 + ciphertext[32:]
            message["ciphertext"] = modified
            print(f"[Attacker] Original data: {ciphertext[:32]}...")
            print(f"[Attacker] Modified data: {modified[:32]}...")
        
        return message
    
    def proxy_handshake(self):
        """
        Proxy the handshake while attempting to tamper.
        """
        print("\n[Attacker] Proxying handshake (with tampering attempts)...")
        
        try:
            # Intercept and tamper with each handshake message
            msg = self.recv_json(self.alice_socket)
            tampered = self.tamper_with_message(msg, "alice->bob")
            self.send_json(self.bob_socket, tampered)
            
            # Server response: Bob -> Alice
            msg = self.recv_json(self.bob_socket)
            tampered = self.tamper_with_message(msg, "bob->alice")
            self.send_json(self.alice_socket, tampered)
            
            # Client auth: Alice -> Bob
            msg = self.recv_json(self.alice_socket)
            tampered = self.tamper_with_message(msg, "alice->bob")
            self.send_json(self.bob_socket, tampered)
            
            # Key confirm from Alice: Alice -> Bob
            msg = self.recv_json(self.alice_socket)
            tampered = self.tamper_with_message(msg, "alice->bob")
            self.send_json(self.bob_socket, tampered)
            
            # Key confirm from Bob: Bob -> Alice
            msg = self.recv_json(self.bob_socket)
            tampered = self.tamper_with_message(msg, "bob->alice")
            self.send_json(self.alice_socket, tampered)
            
            print("\n[Attacker] Handshake proxying complete")
            print("[Attacker] If Alice and Bob continue, the attack FAILED")
            print("[Attacker] If they disconnect, the attack was DETECTED")
            
        except Exception as e:
            print(f"\n[Attacker] Error during handshake: {e}")
            print("[Attacker] Attack likely detected by cryptographic verification")
    
    def proxy_data(self):
        """
        Proxy data messages while attempting to tamper.
        """
        print("\n[Attacker] Proxying data messages...")
        
        count = 0
        try:
            while count < 5:  # Tamper with first 5 messages
                msg = self.recv_json(self.alice_socket)
                tampered = self.tamper_with_message(msg, "alice->bob")
                self.send_json(self.bob_socket, tampered)
                count += 1
            
            print("\n[Attacker] Attempted to tamper with 5 messages")
            print("[Attacker] Monitoring for detection...")
            
            # Continue proxying without tampering
            while True:
                msg = self.recv_json(self.alice_socket)
                self.send_json(self.bob_socket, msg)
                
        except ConnectionError:
            print("\n[Attacker] Connection closed")
        except Exception as e:
            print(f"\n[Attacker] Error: {e}")
    
    def run(self):
        """
        Main execution flow for the attacker proxy.
        """
        try:
            self.start_proxy()
            self.accept_alice()
            self.connect_to_bob()
            
            self.proxy_handshake()
            
            # If we get here, check if connection is still alive
            print("\n[Attacker] Checking if attack was detected...")
            self.alice_socket.settimeout(2)
            
            try:
                # Try to receive next message
                self.proxy_data()
            except socket.timeout:
                print("[Attacker] No more data - Alice likely detected the attack and disconnected")
            
        except KeyboardInterrupt:
            print("\n[Attacker] Interrupted by user")
        except Exception as e:
            print(f"\n[Attacker] Error: {e}")
        finally:
            self.close()
    
    def close(self):
        """
        Close all sockets.
        """
        print("\n[Attacker] Closing connections...")
        
        if self.alice_socket:
            self.alice_socket.close()
        
        if self.bob_socket:
            self.bob_socket.close()
        
        if self.server_socket:
            self.server_socket.close()
        
        print("[Attacker] Proxy stopped")


def main():
    """
    Parse arguments and run attacker proxy.
    """
    parser = argparse.ArgumentParser(
        description="Attacker - Man-in-the-Middle Proxy for Security Testing"
    )
    parser.add_argument(
        "--alice-port",
        type=int,
        default=9001,
        help="Port to listen for Alice (default: 9001)"
    )
    parser.add_argument(
        "--bob-host",
        default="127.0.0.1",
        help="Real Bob's hostname/IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--bob-port",
        type=int,
        default=9000,
        help="Real Bob's port (default: 9000)"
    )
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("Attacker - Man-in-the-Middle Proxy")
    print("=" * 80)
    print("\nThis proxy demonstrates security properties by attempting to:")
    print("  1. Replace ephemeral keys (will fail signature verification)")
    print("  2. Forge signatures (will fail Ed25519 verification)")
    print("  3. Modify encrypted data (will fail GCM authentication)")
    print("  4. Alter key confirmation (will fail HMAC verification)")
    print("\nAll attacks should be detected and the connection terminated.")
    print("=" * 80 + "\n")
    
    attacker = Attacker(args.alice_port, args.bob_host, args.bob_port)
    attacker.run()


if __name__ == "__main__":
    main()