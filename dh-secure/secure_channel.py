# ITO5163 Assessment 2
# Student ID: 35619694
# Student Name: Nicholas Battle

"""
Secure Channel Implementation

Provides encrypted message transmission with:
- AES-256-GCM authenticated encryption
- Sequence number-based replay protection
- Message integrity through AEAD
- Automatic nonce management

Each message includes a sequence number in the AAD to prevent
replay and reordering attacks.
"""

import json
import struct
from crypto_suite import CryptoSuite


class SecureChannel:
    """
    Manages encrypted bidirectional communication channel.
    """
    
    MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB limit
    
    def __init__(self, k_send, k_recv, is_client=True):
        """
        Initialize secure channel with direction-specific session keys.
        
        Args:
            k_send: 32-byte AES-256 key for sending messages
            k_recv: 32-byte AES-256 key for receiving messages
            is_client: True if this is the client side
        """
        self.k_send = k_send
        self.k_recv = k_recv
        self.is_client = is_client
        self.send_sequence = 0
        self.recv_sequence = 0
    
    def _generate_nonce(self, sequence_number):
        """
        Generate 12-byte nonce from sequence number.
        
        Nonce format: 4 bytes of zeros || 8 bytes sequence number (big-endian)
        
        Args:
            sequence_number: 64-bit integer
            
        Returns:
            bytes: 12-byte nonce
        """
        return b'\x00\x00\x00\x00' + struct.pack('>Q', sequence_number)
    
    def encrypt_message(self, plaintext_data):
        """
        Encrypt a message with AES-256-GCM and sequence number binding.
        
        Args:
            plaintext_data: dict or bytes to encrypt
            
        Returns:
            dict: Encrypted message with metadata
        """
        # Convert to bytes if dict
        if isinstance(plaintext_data, dict):
            plaintext = json.dumps(plaintext_data).encode()
        else:
            plaintext = plaintext_data
        
        # Check size limit
        if len(plaintext) > self.MAX_MESSAGE_SIZE:
            raise ValueError(f"Message exceeds maximum size of {self.MAX_MESSAGE_SIZE} bytes")
        
        # Generate unique nonce from sequence number
        nonce = self._generate_nonce(self.send_sequence)
        
        # Include sequence number in AAD for replay protection
        aad = f"seq|{self.send_sequence}".encode()
        
        # Encrypt plaintext and generate authentication tag
        ciphertext_with_tag = CryptoSuite.aes_gcm_encrypt(
            self.k_send,
            nonce,
            plaintext,
            aad
        )
        
        # GCM appends 16-byte authentication tag to ciphertext
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        # Package encrypted data with metadata for transmission
        message = {
            "type": "data",
            "seq": self.send_sequence,
            "nonce": nonce.hex(),
            "aad": aad.decode(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex()
        }
        
        # Increment sequence number for next message
        self.send_sequence += 1
        return message
    
    def decrypt_message(self, encrypted_message):
        """
        Decrypt and verify a message.
        
        Args:
            encrypted_message: dict with encrypted message fields
            
        Returns:
            bytes: Decrypted plaintext, or None if verification fails
        """
        try:
            # Extract fields
            seq = encrypted_message["seq"]
            nonce = bytes.fromhex(encrypted_message["nonce"])
            aad = encrypted_message["aad"].encode()
            ciphertext = bytes.fromhex(encrypted_message["ciphertext"])
            tag = bytes.fromhex(encrypted_message["tag"])
            
            # Replay protection: strictly enforce sequential message ordering
            if seq != self.recv_sequence:
                # NOTE: In production systems, error messages would be less specific
                # to avoid leaking oracle-like side-channel information.
                print(f"Sequence number mismatch: expected {self.recv_sequence}, got {seq}")
                return None
            
            # Verify AAD format that it hasn't been modified
            expected_aad = f"seq|{seq}".encode()
            if aad != expected_aad:
                print("AAD verification failed")
                return None
            
            # Verify authentication tag and decrypt in one operation
            ciphertext_with_tag = ciphertext + tag
            plaintext = CryptoSuite.aes_gcm_decrypt(
                self.k_recv,
                nonce,
                ciphertext_with_tag,
                aad
            )
            
            # None indicates authentication failure
            if plaintext is None:
                print("Decryption failed - authentication tag invalid")
                return None
            
            # Increment sequence for next expected massage
            self.recv_sequence += 1
            return plaintext
            
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return None
    
    def encrypt_json(self, data_dict):
        """
        Convenience method to encrypt a JSON-serializable dict.
        
        Args:
            data_dict: Dictionary to encrypt
            
        Returns:
            dict: Encrypted message
        """
        return self.encrypt_message(data_dict)
    
    def decrypt_json(self, encrypted_message):
        """
        Convenience method to decrypt and parse JSON.
        
        Args:
            encrypted_message: dict with encrypted message
            
        Returns:
            dict: Decrypted and parsed JSON, or None on failure
        """
        plaintext = self.decrypt_message(encrypted_message)
        if plaintext is None:
            return None
        
        try:
            return json.loads(plaintext.decode())
        except Exception as e:
            print(f"Error parsing JSON: {e}")
            return None
    
    def reset_sequences(self):
        """
        Reset sequence numbers (use with caution, only for testing).
        """
        self.send_sequence = 0
        self.recv_sequence = 0
    
    def get_statistics(self):
        """
        Get channel statistics.
        
        Returns:
            dict: Statistics about messages sent/received
        """
        return {
            "messages_sent": self.send_sequence,
            "messages_received": self.recv_sequence
        }