#!/usr/bin/env python3
# ITO5163 Assessment 2
# Student ID: 35619694
# Student Name: Nicholas Battle

"""
Alice (Ground Control Station)

Listens for connections from Bob (aircraft) and receives encrypted telemetry.
Performs authenticated key exchange and decrypts ADS-C telemetry data from
the aircraft's flight computer.

Acts as server using HandshakeServer - waits for aircraft to connect and
authenticate before receiving telemetry data.

Usage:
    python alice.py --host <listen_ip> --port <port>
"""

import socket
import json
import argparse
import sys
from pathlib import Path

from crypto_suite import CryptoSuite
from handshake import HandshakeServer
from secure_channel import SecureChannel
from telemetry_stream import TelemetryLogger


def recv_json_from_socket(sock, recv_buf):
    """
    Read one newline-terminated JSON message from socket with persistent buffer.
    This prevents losing bytes when multiple messages arrive together.
    
    Args:
        sock: Socket to read from
        recv_buf: Bytearray maintained between calls
        
    Returns:
        tuple: (message_dict, remaining_recv_buf)
    """
    while b'\n' not in recv_buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        recv_buf.extend(chunk)
    
    # Find first newline
    idx = recv_buf.index(b'\n')
    raw = bytes(recv_buf[:idx])
    
    # Remove consumed bytes from buffer
    del recv_buf[:idx + 1]
    
    return json.loads(raw.decode()), recv_buf


class Alice:
    """
    Ground control station for receiving secure telemetry from aircraft.
    
    Server role - uses HandshakeServer to authenticate connecting aircraft.
    Listens on a TCP port and waits for Bob (aircraft) to connect.
    """
    
    HANDSHAKE_TIMEOUT = 30
    MAX_AUTH_FAILS = 5
    
    def __init__(self, host, port, keys_dir="keys"):
        """
        Initialize Alice ground control station.
        
        Args:
            host: IP address to bind (0.0.0.0 for all interfaces)
            port: TCP port to listen on
            keys_dir: Directory containing Ed25519 key files
        """
        self.host = host
        self.port = port
        self.keys_dir = Path(keys_dir)
        self.server_socket = None
        self.client_socket = None
        self.recv_buf = bytearray()  # Persistent buffer prevents data loss between messages
        self.handshake = None
        self.secure_channel = None
        self.telemetry_logger = TelemetryLogger()
        self.failed_auth_count = 0  # DoS protection: track consecutive auth failures
        
        # Load static identity keys
        self.load_keys()
    
    def load_keys(self):
        """
        Load Ed25519 static keys from files.
        Also loads Bob's expected public key for key pinning (MITM protection).
        """
        try:
            #paths to identity key files
            alice_priv_path = self.keys_dir / "alice_ed25519_priv.pem"
            alice_pub_path = self.keys_dir / "alice_ed25519_pub.pem"
            bob_pub_path = self.keys_dir / "bob_ed25519_pub.pem"
            
            # Load Alices signing keys
            self.static_private_key = CryptoSuite.load_ed25519_private_key(alice_priv_path)
            self.static_public_key = CryptoSuite.load_ed25519_public_key(alice_pub_path)
            # Load Bobs public key for key pinning (MITM prevention)
            self.expected_bob_public_key = CryptoSuite.load_ed25519_public_key(bob_pub_path)
            
            print(f"[Alice] Loaded identity keys from {self.keys_dir}")
            print(f"[Alice] Loaded Bob's expected public key for key pinning")
            
        except FileNotFoundError as e:
            print(f"[Alice] Error: Key files not found in {self.keys_dir}")
            print("[Alice] Run 'bash demo_scripts/01_generate_keys.sh' to create keys")
            sys.exit(1)
        except Exception as e:
            print(f"[Alice] Error loading keys: {e}")
            sys.exit(1)
    
    def start_listening(self):
        """
        Start listening for incoming connections from aircraft.
        """
        try:
            # Create TCP Socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow address reuse to prevent "address already in use" errors
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            # accept only one client connection at a time
            self.server_socket.listen(1)
            
            print(f"[Alice] Ground control listening on {self.host}:{self.port}")
            print("[Alice] Waiting for aircraft (Bob) to connect...")
            
        except Exception as e:
            print(f"[Alice] Error starting server: {e}")
            sys.exit(1)
    
    def accept_connection(self):
        """
        Accept incoming connection from aircraft (Bob).
        """
        try:
            # Wait for and accept incoming connection
            self.client_socket, client_address = self.server_socket.accept()
            #timeout to prevent hanging during handshake
            self.client_socket.settimeout(self.HANDSHAKE_TIMEOUT)
            
            print(f"[Alice] Aircraft connected from {client_address[0]}:{client_address[1]}")
            
        except Exception as e:
            print(f"[Alice] Error accepting connection: {e}")
            raise
    
    def send_json(self, data):
        """
        Send JSON message over socket.
        
        Args:
            data: Dictionary to send as JSON
        """
        # Serialise to JSON and append newline as message delimiter
        message = json.dumps(data).encode() + b'\n'
        self.client_socket.sendall(message)
    
    def recv_json(self):
        """
        Receive JSON message from socket using persistent buffer.
        
        Returns:
            dict: Parsed JSON message
        """
        msg, self.recv_buf = recv_json_from_socket(self.client_socket, self.recv_buf)
        return msg
    
    def perform_handshake(self):
        """
        Perform authenticated key exchange with aircraft (Bob).
        
        Returns:
            bool: True if handshake succeeded
        """
        print("\n[Alice] Starting authenticated handshake...")
        
        # create handshake handler with Alice's keys and expected Bob's key
        self.handshake = HandshakeServer(
            self.static_private_key, 
            self.static_public_key,
            self.expected_bob_public_key
        )
        
        # Step 1: Receive and validate client HELLO from Bob
        print("[Alice] Waiting for aircraft hello...")
        hello = self.recv_json()
        
        # verify hello contains required fields and valid ephemeral key
        if not self.handshake.process_client_hello(hello):
            # NOTE: In production systems, error messages would be less specific
            # to avoid leaking oracle-like side-channel information.
            print("[Alice] ERROR: Invalid aircraft hello!")
            return False
        
        print("[Alice] Received aircraft hello")
        
        # Step 2: Send server response with signature
        print("[Alice] Sending ground station authentication...")
        response = self.handshake.create_response()
        self.send_json(response)
        
        # Step 3: Verify Bobs signature and check key pinning
        print("[Alice] Waiting for aircraft authentication...")
        auth = self.recv_json()
        
        # Validate signature and ensure Bob's key matches expected value
        if not self.handshake.process_client_auth(auth):
            print("[Alice] ERROR: Aircraft authentication failed!")
            return False
        
        print("[Alice] Aircraft authenticated successfully")
        
        # Step 4: Derive session keys
        print("[Alice] Deriving session keys...")
        session_keys = self.handshake.derive_keys()
        
        # Step 5: Key confirmation
        print("[Alice] Performing key confirmation...")
        client_confirm = self.recv_json()
        
        # Check Bob's HMAC to ensure key agreement succeeded
        if not self.handshake.verify_client_confirmation(client_confirm):
            print("[Alice] ERROR: Aircraft key confirmation failed!")
            return False
        
        # Send server confirmation
        server_confirm = self.handshake.create_key_confirmation()
        self.send_json(server_confirm)
        
        print("[Alice] Key confirmation successful")
        print("[Alice] Secure channel established!\n")
        
        # initialise secure channel with direction specific keys
        # Alice receives from Bob using k_app_bob_to_alice
        # Alice would send to Bob using k_app_alice_to_bob (for future bi directional comms)
        self.secure_channel = SecureChannel(
            k_send=session_keys["k_app_alice_to_bob"],
            k_recv=session_keys["k_app_bob_to_alice"],
            is_client=False
        )
        
        # Reset socket timeout after handshake completes
        self.client_socket.settimeout(None)
        
        return True
    
    def receive_telemetry(self):
        """
        Receive and decrypt telemetry data from aircraft (Bob).
        """
        print("[Alice] Ready to receive telemetry from aircraft...")
        print("-" * 80)
        
        frame_count = 0
        
        try:
            # Continuously receive and process telemetry frames
            while True:
                # Receive encrypted message from Bob
                encrypted_msg = self.recv_json()
                
                # Decrypt and authenticate message
                frame = self.secure_channel.decrypt_json(encrypted_msg)
                
                # Auth failure indicates tampering or replay attack
                if frame is None:
                    self.failed_auth_count += 1
                    print(f"[Alice] WARNING: Failed to decrypt message (attempt {self.failed_auth_count}/{self.MAX_AUTH_FAILS}) - possible tampering!")
                    
                    # DoS protection: close connection after too many failures
                    if self.failed_auth_count > self.MAX_AUTH_FAILS:
                        print("[Alice] ERROR: Too many authentication failures - closing connection")
                        break
                    
                    continue
                
                # Reset failure count on success
                self.failed_auth_count = 0
                frame_count += 1
                
                # Log telemetry
                self.telemetry_logger.log_frame(frame)
                
        except ConnectionError:
            print("\n[Alice] Connection closed by aircraft")
        except KeyboardInterrupt:
            print("\n[Alice] Reception interrupted by user")
        except Exception as e:
            print(f"\n[Alice] Reception error: {e}")
        
        print("-" * 80)
        print(f"[Alice] Received {frame_count} telemetry frames from aircraft")
        
        # Get statistics
        stats = self.secure_channel.get_statistics()
        print(f"[Alice] Channel statistics: {stats}")
    
    def close(self):
        """
        Close all sockets.
        """
        print("\n[Alice] Closing connections...")
        
        if self.client_socket:
            self.client_socket.close()
        
        if self.server_socket:
            self.server_socket.close()
        
        print("[Alice] Ground station stopped")
    
    def run(self):
        """
        Main execution flow: listen, accept, handshake, receive, close.
        """
        try:
            # Start server and wait for Bob to connect
            self.start_listening()
            self.accept_connection()
            
            # Perform mutual authentication and key exchange
            if not self.perform_handshake():
                print("[Alice] Handshake failed - closing connection")
                return
            
            # Begin receiving encrypted telemetry
            self.receive_telemetry()
            
        except KeyboardInterrupt:
            print("\n[Alice] Ground station interrupted by user")
        finally:
            self.close()


def main():
    """
    Parse arguments and run Alice ground control station.
    """
    parser = argparse.ArgumentParser(
        description="Alice (Ground Control Station) - Secure Telemetry Receiver"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="IP address to bind (default: 0.0.0.0 for all interfaces)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="TCP port to listen on (default: 9000)"
    )
    parser.add_argument(
        "--keys-dir",
        default="keys",
        help="Directory containing key files (default: keys)"
    )
    
    args = parser.parse_args()
    
    # Display banner to improve visual appearance and separate from data text
    print("=" * 80)
    print("Alice (Ground Control Station) - Secure Aerospace Telemetry System")
    print("=" * 80)
    
    #Initialise and run ground control station
    alice = Alice(args.host, args.port, args.keys_dir)
    alice.run()


if __name__ == "__main__":
    main()