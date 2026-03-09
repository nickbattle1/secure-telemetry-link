#!/usr/bin/env python3
# ITO5163 Assessment 2
# Student ID: 35619694
# Student Name: Nicholas Battle

"""
Bob (Aircraft Flight Computer)

Connects to Alice (ground control) and transmits encrypted telemetry.
Generates ADS-C telemetry data and performs authenticated key exchange before
secure transmission.

Acts as client using HandshakeClient - initiates connection to ground control
and transmits encrypted telemetry after authentication.

Usage:
    python bob.py --host <alice_ip> --port <port>
"""

import socket
import json
import argparse
import time
import sys
from pathlib import Path

from crypto_suite import CryptoSuite
from handshake import HandshakeClient
from secure_channel import SecureChannel
from telemetry_stream import TelemetryStream, RealTelemetryStream


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


class Bob:
    """
    Aircraft flight computer for transmitting secure telemetry to ground control.
    
    Client role - uses HandshakeClient to connect to and authenticate with Alice.
    Generates telemetry and transmits it over encrypted channel.
    """
    
    HANDSHAKE_TIMEOUT = 30
    # Send telemetry every 0.5 seconds (for demonstration purposes)
    MESSAGE_INTERVAL = 0.5 # This would be more like 300+ sec (5-15 minutes) in a real system
    
    def __init__(self, host, port, keys_dir="keys", telemetry_mode="simulated", telemetry_file=None):
        """
        Initialize Bob aircraft flight computer.
        
        Args:
            host: Alice's IP address or hostname (ground control)
            port: Alice's TCP port
            keys_dir: Directory containing Ed25519 key files
            telemetry_mode: "simulated" or "real"
            telemetry_file: Path to CSV file (required if mode is "real")
        """
        self.host = host
        self.port = port
        self.keys_dir = Path(keys_dir)
        self.telemetry_mode = telemetry_mode
        self.telemetry_file = telemetry_file
        self.socket = None
        self.recv_buf = bytearray()  # Persistent buffer prevents data loss between messages
        self.handshake = None
        self.secure_channel = None
        self.telemetry_stream = None
        
        # Load static identity keys
        self.load_keys()
    
    def load_keys(self):
        """
        Load Ed25519 static keys from files.
        Also loads Alice's expected public key for key pinning (MITM protection).
        """
        try:
            # Construct paths to identity key files
            bob_priv_path = self.keys_dir / "bob_ed25519_priv.pem"
            bob_pub_path = self.keys_dir / "bob_ed25519_pub.pem"
            alice_pub_path = self.keys_dir / "alice_ed25519_pub.pem"
            
            # Load Bob's signing keys
            self.static_private_key = CryptoSuite.load_ed25519_private_key(bob_priv_path)
            self.static_public_key = CryptoSuite.load_ed25519_public_key(bob_pub_path)
            # Load Alices public key for key pinning (MITM prevention)
            self.expected_alice_public_key = CryptoSuite.load_ed25519_public_key(alice_pub_path)
            
            print(f"[Bob] Loaded identity keys from {self.keys_dir}")
            print(f"[Bob] Loaded Alice's expected public key for key pinning")
            
        except FileNotFoundError as e:
            print(f"[Bob] Error: Key files not found in {self.keys_dir}")
            print("[Bob] Run 'bash demo_scripts/01_generate_keys.sh' to create keys")
            sys.exit(1)
        except Exception as e:
            print(f"[Bob] Error loading keys: {e}")
            sys.exit(1)
    
    def connect(self):
        """
        Establish TCP connection to Alice (ground control).
        """
        try:
            print(f"[Bob] Aircraft connecting to ground control at {self.host}:{self.port}...")
            # Create TCP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set timeout to prevent hanging if Alice is unreachable
            self.socket.settimeout(self.HANDSHAKE_TIMEOUT)
            # Initiate connection to Alice
            self.socket.connect((self.host, self.port))
            print("[Bob] Connected to ground control successfully")
            
        except socket.timeout:
            print(f"[Bob] Connection timeout - is ground control running at {self.host}:{self.port}?")
            sys.exit(1)
        except ConnectionRefusedError:
            print(f"[Bob] Connection refused - is ground control running at {self.host}:{self.port}?")
            sys.exit(1)
        except Exception as e:
            print(f"[Bob] Connection error: {e}")
            sys.exit(1)
    
    def send_json(self, data):
        """
        Send JSON message over socket.
        
        Args:
            data: Dictionary to send as JSON
        """
        # Serialise to JSON + append new line as message delimiter
        message = json.dumps(data).encode() + b'\n'
        self.socket.sendall(message)
    
    def recv_json(self):
        """
        Receive JSON message from socket using persistent buffer.
        
        Returns:
            dict: Parsed JSON message
        """
        msg, self.recv_buf = recv_json_from_socket(self.socket, self.recv_buf)
        return msg
    
    def perform_handshake(self):
        """
        Perform authenticated key exchange with ground control (Alice).
        
        Returns:
            bool: True if handshake succeeded
        """
        print("\n[Bob] Starting authenticated handshake...")
        
        # Create handshake handler with Bob's keys and expected Alice's key
        self.handshake = HandshakeClient(
            self.static_private_key, 
            self.static_public_key,
            self.expected_alice_public_key
        )
        
        # Step 1: Send client hello
        print("[Bob] Sending aircraft hello with ephemeral public key...")
        hello = self.handshake.create_hello()
        self.send_json(hello)
        
        # Step 2: Verify Alice's signature and check key pinning
        print("[Bob] Waiting for ground control response...")
        response = self.recv_json()
        
        if not self.handshake.process_server_response(response):
            # NOTE: In production systems, error messages would be less specific
            # to avoid leaking oracle-like side-channel information.
            print("[Bob] ERROR: Ground control authentication failed!")
            return False
        
        print("[Bob] Ground control authenticated successfully")
        
        # Step 3: Send aircraft authentication
        print("[Bob] Sending aircraft authentication...")
        auth = self.handshake.create_client_auth()
        self.send_json(auth)
        
        # Step 4: Derive session keys
        print("[Bob] Deriving session keys...")
        session_keys = self.handshake.derive_keys()
        
        # Step 5: Key confirmation
        print("[Bob] Performing key confirmation...")
        confirm = self.handshake.create_key_confirmation()
        self.send_json(confirm)
        
        # Receive ground control confirmation
        server_confirm = self.recv_json()
        if not self.handshake.verify_server_confirmation(server_confirm):
            print("[Bob] ERROR: Ground control key confirmation failed!")
            return False
        
        print("[Bob] Key confirmation successful")
        print("[Bob] Secure channel established!\n")
        
        # Initialize secure channel with direction-specific keys
        # Bob sends to Alice using k_app_bob_to_alice
        # Bob would receive from Alice using k_app_alice_to_bob (for future bidirectional comms)
        self.secure_channel = SecureChannel(
            k_send=session_keys["k_app_bob_to_alice"],
            k_recv=session_keys["k_app_alice_to_bob"],
            is_client=True
        )
        
        return True
    
    def transmit_telemetry(self, duration=60):
        """
        Transmit encrypted telemetry data to ground control (Alice).
        
        Args:
            duration: How many seconds to transmit (0 for infinite)
        """
        print(f"[Bob] Starting telemetry transmission...")
        print(f"[Bob] Mode: {self.telemetry_mode}")
        print(f"[Bob] Sending data every {self.MESSAGE_INTERVAL} seconds")
        print("-" * 80)
        
        # Choose between real ADS-C data or simulated telemetry
        if self.telemetry_mode == "real":
            if not self.telemetry_file:
                print("[Bob] ERROR: Real mode requires --telemetry-file")
                return
            
            # Load real telemetry from CSV file
            try:
                self.telemetry_stream = RealTelemetryStream(self.telemetry_file)
                print(f"[Bob] Loaded {self.telemetry_stream.get_total_frames()} real ADS-C frames")
            except Exception as e:
                print(f"[Bob] ERROR loading real telemetry: {e}")
                return
        else:
            # Generate simulated aircraft telemetry
            self.telemetry_stream = TelemetryStream.create_predefined_stream("transatlantic")
            print(f"[Bob] Using simulated telemetry")
        
        start_time = time.time()
        frame_count = 0
        
        try:
            # Main telemetry transmission loop
            while True:
                # Check duration limit
                if duration > 0 and (time.time() - start_time) >= duration:
                    break
                
                # Get next telemetry frame from stream
                frame = self.telemetry_stream.get_next_frame()
                frame_count += 1
                
                # encrypt and send
                encrypted_msg = self.secure_channel.encrypt_json(frame)
                self.send_json(encrypted_msg)
                
                # Show transmission confirmation (minimal because resource constrained controller)
                print(f"[{time.strftime('%H:%M:%S')}] Bob TX frame #{frame_count} ({frame['Registration']}) → Ground Control")
                
                # Wait before next transmission
                time.sleep(self.MESSAGE_INTERVAL)
                
        except KeyboardInterrupt:
            print("\n[Bob] Transmission interrupted by user")
        except Exception as e:
            print(f"\n[Bob] Transmission error: {e}")
        
        print("-" * 80)
        print(f"[Bob] Transmitted {frame_count} telemetry frames")
        
        # Get statistics
        stats = self.secure_channel.get_statistics()
        print(f"[Bob] Channel statistics: {stats}")
    
    def close(self):
        """
        Close connection to ground control.
        """
        if self.socket:
            print("\n[Bob] Closing connection...")
            self.socket.close()
            print("[Bob] Disconnected from ground control")
    
    def run(self, duration=60):
        """
        Main execution flow: connect, handshake, transmit, disconnect.
        
        Args:
            duration: How many seconds to transmit telemetry
        """
        try:
            # Connect to ground control station
            self.connect()
            
            # Perform mutual authentication and key exchange
            if not self.perform_handshake():
                print("[Bob] Handshake failed - aborting")
                return
            
            # begin transmitting encrypted telemetry
            self.transmit_telemetry(duration)
            
        finally:
            self.close()


def main():
    """
    Parse arguments and run Bob aircraft flight computer.
    """
    parser = argparse.ArgumentParser(
        description="Bob (Aircraft Flight Computer) - Secure Telemetry Transmitter"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Alice's IP address or hostname (ground control) (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Alice's TCP port (default: 9000)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Transmission duration in seconds (default: 60, 0 for infinite)"
    )
    parser.add_argument(
        "--keys-dir",
        default="keys",
        help="Directory containing key files (default: keys)"
    )
    parser.add_argument(
        "--telemetry-mode",
        choices=["simulated", "real"],
        default="simulated",
        help="Telemetry source: simulated or real ADS-C data (default: simulated)"
    )
    parser.add_argument(
        "--telemetry-file",
        help="CSV file with real ADS-C data (required if mode is 'real')"
    )
    
    args = parser.parse_args()
    
    # Validate telemetry mode
    if args.telemetry_mode == "real" and not args.telemetry_file:
        parser.error("--telemetry-file is required when using --telemetry-mode real")
    
    # Display banner
    print("=" * 80)
    print("Bob (Aircraft Flight Computer) - Secure Aerospace Telemetry System")
    print("=" * 80)
    
    # Initialise and run aircraft flight computer
    bob = Bob(args.host, args.port, args.keys_dir, args.telemetry_mode, args.telemetry_file)
    bob.run(args.duration)


if __name__ == "__main__":
    main()