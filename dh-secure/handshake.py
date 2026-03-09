# ITO5163 Assessment 2
# Student ID: 35619694
# Student Name: Nicholas Battle

"""
Authenticated Handshake Protocol

Implements a mutually authenticated Diffie-Hellman key exchange using:
- X25519 for ephemeral key agreement
- Ed25519 signatures to prevent man-in-the-middle attacks
- HKDF to derive session keys
- HMAC-based key confirmation

Handshake flow:
1. Client sends ephemeral public key
2. Server sends ephemeral public key + signature + static public key
3. Client sends signature + static public key
4. Both derive shared secret and session keys
5. Both perform key confirmation with HMAC
"""

import json
from crypto_suite import CryptoSuite


class HandshakeClient:
    """
    Client-side authenticated handshake implementation.
    """
    
    def __init__(self, static_private_key, static_public_key, expected_peer_static_public_key):
        """
        Initialize client handshake.
        
        Args:
            static_private_key: Ed25519PrivateKey for signing
            static_public_key: bytes of Ed25519 public key
            expected_peer_static_public_key: bytes of expected server's Ed25519 public key (for key pinning)
        """
        self.static_private_key = static_private_key
        self.static_public_key = static_public_key
        self.expected_peer_static_public_key = expected_peer_static_public_key
        self.ephemeral_private_key = None
        self.ephemeral_public_key = None
        self.peer_ephemeral_public_key = None
        self.peer_static_public_key = None
        self.shared_secret = None
        self.transcript = []
        self.session_keys = None
        
    def create_hello(self):
        """
        Create client hello message with ephemeral public key.
        
        Returns:
            dict: Hello message to send to server
        """
        # Generate fresh ephemeral key pair for this session
        self.ephemeral_private_key, self.ephemeral_public_key = CryptoSuite.generate_x25519_keypair()
        
        # Construct hello message with supported algorithms
        hello = {
            "type": "client_hello",
            "version": "1.0",
            "algorithms": ["X25519", "Ed25519", "AES-256-GCM"],
            "ephemeral_public_key": self.ephemeral_public_key.hex()
        }
        
        # record message in transcript for key confirmation
        self.transcript.append(json.dumps(hello, sort_keys=True))
        return hello
    
    def process_server_response(self, response):
        """
        Process server response and verify signature.
        
        Args:
            response: dict containing server's ephemeral key, signature, and static public key
            
        Returns:
            bool: True if server authentication succeeded
        """
        if response.get("type") != "server_response":
            return False
        
        self.transcript.append(json.dumps(response, sort_keys=True))
        
        try:
            # Extract servers keys and signature
            self.peer_ephemeral_public_key = bytes.fromhex(response["ephemeral_public_key"])
            server_signature = bytes.fromhex(response["signature"])
            self.peer_static_public_key = bytes.fromhex(response["static_public_key"])
            
            # KEY PINNING: Verify that server's static public key matches expected key
            if self.peer_static_public_key != self.expected_peer_static_public_key:
                # NOTE: In production systems, error messages would be less specific
                # to avoid leaking oracle-like side-channel information.
                print("[HandshakeClient] ERROR: Server static key does not match expected key!")
                print(f"[HandshakeClient] Received: {self.peer_static_public_key.hex()}")
                print(f"[HandshakeClient] Expected: {self.expected_peer_static_public_key.hex()}")
                return False
            
            # Verify server signed both ephemeral keys (prevents replay attacks)
            message_to_verify = (
                self.peer_ephemeral_public_key +
                self.ephemeral_public_key +
                b"secure-telemetry-server"
            )
            
            # Check Ed25519 signature is valid
            if not CryptoSuite.ed25519_verify(self.peer_static_public_key, server_signature, message_to_verify):
                return False
            
            return True
            
        except Exception as e:
            print(f"Error processing server response: {e}")
            return False
    
    def create_client_auth(self):
        """
        Create client authentication message with signature.
        
        Returns:
            dict: Authentication message to send to server
        """
        # Sign both ephemeral keys to prove possession of private key
        message_to_sign = (
            self.ephemeral_public_key +
            self.peer_ephemeral_public_key +
            b"secure-telemetry-client"
        )
        
        # Create Ed25519 signature
        signature = CryptoSuite.ed25519_sign(self.static_private_key, message_to_sign)
        
        auth = {
            "type": "client_auth",
            "signature": signature.hex(),
            "static_public_key": self.static_public_key.hex()
        }
        
        self.transcript.append(json.dumps(auth, sort_keys=True))
        return auth
    
    def derive_keys(self):
        """
        Derive session keys from shared secret and transcript hash.
        
        Returns:
            dict: Session keys with direction-specific application keys
                 {k_app_bob_to_alice, k_app_alice_to_bob, k_confirm}
        """
        # Compute shared secret
        self.shared_secret = CryptoSuite.x25519_exchange(
            self.ephemeral_private_key,
            self.peer_ephemeral_public_key
        )
        
        # Hash entire handshake transcript for key confirmation
        transcript_data = "".join(self.transcript).encode()
        transcript_hash = CryptoSuite.sha256(transcript_data)
        
        # Derive keys using HKDF (96 bytes = 3 keys of 32 bytes each)
        key_material = CryptoSuite.hkdf_derive_keys(self.shared_secret, transcript_hash, 96)
        
        # Separate keys per direction prevents key reuse between sender/receiver
        self.session_keys = {
            "k_app_bob_to_alice": key_material[0:32],
            "k_app_alice_to_bob": key_material[32:64],
            "k_confirm": key_material[64:96],
            "transcript_hash": transcript_hash
        }
        
        return self.session_keys
    
    def create_key_confirmation(self):
        """
        Create key confirmation message using HMAC.
        
        Returns:
            dict: Key confirmation message
        """
        if not self.session_keys:
            raise ValueError("Keys not derived yet")
        
        # Create HMAC over transcript to prove key derivation succeeded
        confirm_message = self.session_keys["transcript_hash"] + b"client"
        confirm_tag = CryptoSuite.hmac_sha256(self.session_keys["k_confirm"], confirm_message)
        
        return {
            "type": "key_confirm",
            "tag": confirm_tag.hex()
        }
    
    def verify_server_confirmation(self, confirmation):
        """
        Verify server's key confirmation.
        
        Args:
            confirmation: dict with server's confirmation tag
            
        Returns:
            bool: True if confirmation is valid
        """
        if confirmation.get("type") != "key_confirm":
            return False
        
        try:
            server_tag = bytes.fromhex(confirmation["tag"])
            
            # Compute expected HMAC for server
            confirm_message = self.session_keys["transcript_hash"] + b"server"
            
            # Verify servers HMAC matches (constant-time comparison)
            return CryptoSuite.hmac_verify(self.session_keys["k_confirm"], confirm_message, server_tag)
            
        except Exception as e:
            print(f"Error verifying server confirmation: {e}")
            return False


class HandshakeServer:
    """
    Server-side authenticated handshake implementation.
    """
    
    def __init__(self, static_private_key, static_public_key, expected_peer_static_public_key):
        """
        Initialize server handshake.
        
        Args:
            static_private_key: Ed25519PrivateKey for signing
            static_public_key: bytes of Ed25519 public key
            expected_peer_static_public_key: bytes of expected client's Ed25519 public key (for key pinning)
        """
        self.static_private_key = static_private_key
        self.static_public_key = static_public_key
        self.expected_peer_static_public_key = expected_peer_static_public_key
        self.ephemeral_private_key = None
        self.ephemeral_public_key = None
        self.peer_ephemeral_public_key = None
        self.peer_static_public_key = None
        self.shared_secret = None
        self.transcript = []
        self.session_keys = None
    
    def process_client_hello(self, hello):
        """
        Process client hello message.
        
        Args:
            hello: dict with client's ephemeral public key
            
        Returns:
            bool: True if hello is valid
        """
        if hello.get("type") != "client_hello":
            return False
        
        self.transcript.append(json.dumps(hello, sort_keys=True))
        
        try:
            self.peer_ephemeral_public_key = bytes.fromhex(hello["ephemeral_public_key"])
            return True
        except Exception as e:
            print(f"Error processing client hello: {e}")
            return False
    
    def create_response(self):
        """
        Create server response with ephemeral key and signature.
        
        Returns:
            dict: Response message to send to client
        """
        # Generate ephemeral key pair
        self.ephemeral_private_key, self.ephemeral_public_key = CryptoSuite.generate_x25519_keypair()
        
        # Sign both ephemeral keys to prove possession of private key
        message_to_sign = (
            self.ephemeral_public_key +
            self.peer_ephemeral_public_key +
            b"secure-telemetry-server"
        )
        
        # Create Ed25519 signature
        signature = CryptoSuite.ed25519_sign(self.static_private_key, message_to_sign)
        
        response = {
            "type": "server_response",
            "ephemeral_public_key": self.ephemeral_public_key.hex(),
            "signature": signature.hex(),
            "static_public_key": self.static_public_key.hex()
        }
        
        self.transcript.append(json.dumps(response, sort_keys=True))
        return response
    
    def process_client_auth(self, auth):
        """
        Process client authentication and verify signature.
        
        Args:
            auth: dict with client's signature and static public key
            
        Returns:
            bool: True if client authentication succeeded
        """
        if auth.get("type") != "client_auth":
            return False
        
        self.transcript.append(json.dumps(auth, sort_keys=True))
        
        try:
            # Extract client's signature and public key
            client_signature = bytes.fromhex(auth["signature"])
            self.peer_static_public_key = bytes.fromhex(auth["static_public_key"])
            
            # KEY PINNING: Prevent MITM by checking client's identity
            if self.peer_static_public_key != self.expected_peer_static_public_key:
                # NOTE: In production systems, error messages would be less specific
                # to avoid leaking oracle-like side-channel information.
                print("[HandshakeServer] ERROR: Client static key does not match expected key!")
                print(f"[HandshakeServer] Received: {self.peer_static_public_key.hex()}")
                print(f"[HandshakeServer] Expected: {self.expected_peer_static_public_key.hex()}")
                return False
            
            # Verify client signed both ephemeral keys (prevents replay attacks)
            message_to_verify = (
                self.peer_ephemeral_public_key +
                self.ephemeral_public_key +
                b"secure-telemetry-client"
            )
            
            # Check ed25519 signature is valid
            if not CryptoSuite.ed25519_verify(self.peer_static_public_key, client_signature, message_to_verify):
                return False
            
            return True
            
        except Exception as e:
            print(f"Error processing client auth: {e}")
            return False
    
    def derive_keys(self):
        """
        Derive session keys from shared secret and transcript hash.
        
        Returns:
            dict: Session keys with direction-specific application keys
                 {k_app_bob_to_alice, k_app_alice_to_bob, k_confirm}
        """
        # Compute shared secret
        self.shared_secret = CryptoSuite.x25519_exchange(
            self.ephemeral_private_key,
            self.peer_ephemeral_public_key
        )
        
        # hash entire handshake transcript for key confirmation
        transcript_data = "".join(self.transcript).encode()
        transcript_hash = CryptoSuite.sha256(transcript_data)
        
        # Derive keys using HKDF (96 bytes = 3 keys of 32 bytes each)
        key_material = CryptoSuite.hkdf_derive_keys(self.shared_secret, transcript_hash, 96)
        
        # Separate keys per direction prevents key reuse between sender/receiver
        self.session_keys = {
            "k_app_bob_to_alice": key_material[0:32],
            "k_app_alice_to_bob": key_material[32:64],
            "k_confirm": key_material[64:96],
            "transcript_hash": transcript_hash
        }
        
        return self.session_keys
    
    def verify_client_confirmation(self, confirmation):
        """
        Verify client's key confirmation.
        
        Args:
            confirmation: dict with client's confirmation tag
            
        Returns:
            bool: True if confirmation is valid
        """
        if confirmation.get("type") != "key_confirm":
            return False
        
        try:
            client_tag = bytes.fromhex(confirmation["tag"])
            
            # HMAC(k_confirm, transcript_hash || "client")
            confirm_message = self.session_keys["transcript_hash"] + b"client"
            
            return CryptoSuite.hmac_verify(self.session_keys["k_confirm"], confirm_message, client_tag)
            
        except Exception as e:
            print(f"Error verifying client confirmation: {e}")
            return False
    
    def create_key_confirmation(self):
        """
        Create key confirmation message using HMAC.
        
        Returns:
            dict: Key confirmation message
        """
        if not self.session_keys:
            raise ValueError("Keys not derived yet")
        
        # HMAC(k_confirm, transcript_hash || "server")
        confirm_message = self.session_keys["transcript_hash"] + b"server"
        confirm_tag = CryptoSuite.hmac_sha256(self.session_keys["k_confirm"], confirm_message)
        
        return {
            "type": "key_confirm",
            "tag": confirm_tag.hex()
        }