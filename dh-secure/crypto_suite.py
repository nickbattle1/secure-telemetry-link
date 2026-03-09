# ITO5163 Assessment 2
# Student ID: 35619694
# Student Name: Nicholas Battle

"""
Cryptographic Suite for Secure Telemetry System

This module provides all cryptographic primitives needed for the authenticated
key exchange and secure channel:
- X25519 for ECDH key agreement
- Ed25519 for digital signatures
- AES-256-GCM for authenticated encryption
- HKDF-SHA256 for key derivation
- HMAC-SHA256 for key confirmation
"""

import os
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CryptoSuite:
    """
    Provides cryptographic operations for the secure telemetry system.
    """
    
    @staticmethod
    def generate_x25519_keypair():
        """
        Generate an ephemeral X25519 key pair for ECDH.
        
        Returns:
            tuple: (private_key, public_key_bytes)
        """
        # Generate random private key
        private_key = X25519PrivateKey.generate()
        # Extract public key in raw 32-byte format
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return private_key, public_key_bytes
    
    @staticmethod
    def x25519_exchange(private_key, peer_public_bytes):
        """
        Perform X25519 ECDH key exchange.
        
        Args:
            private_key: X25519PrivateKey object
            peer_public_bytes: 32-byte public key from peer
            
        Returns:
            bytes: 32-byte shared secret
        """
        # Reconstruct peerss public key from raw bytes
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
        # Compute Diffie-Hellman shared secret
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret
    
    @staticmethod
    def generate_ed25519_keypair():
        """
        Generate a static Ed25519 signing key pair for authentication.
        
        Returns:
            tuple: (private_key, public_key_bytes)
        """
        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return private_key, public_key_bytes
    
    @staticmethod
    def save_ed25519_private_key(private_key, filepath):
        """
        Save Ed25519 private key to PEM file.
        
        Args:
            private_key: Ed25519PrivateKey object
            filepath: Path to save the PEM file
        """
        # Serialise private key to PEM format (unencrypted for demo purposes)
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Write to file
        with open(filepath, 'wb') as f:
            f.write(pem_bytes)
    
    @staticmethod
    def save_ed25519_public_key(public_key_bytes, filepath):
        """
        Save Ed25519 public key to PEM file.
        
        Args:
            public_key_bytes: 32-byte raw public key
            filepath: Path to save the PEM file
        """
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filepath, 'wb') as f:
            f.write(pem_bytes)
    
    @staticmethod
    def load_ed25519_private_key(filepath):
        """
        Load Ed25519 private key from PEM file.
        
        Args:
            filepath: Path to the PEM file
            
        Returns:
            Ed25519PrivateKey: Loaded private key
        """
        with open(filepath, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    
    @staticmethod
    def load_ed25519_public_key(filepath):
        """
        Load Ed25519 public key from PEM file.
        
        Args:
            filepath: Path to the PEM file
            
        Returns:
            bytes: 32-byte raw public key
        """
        with open(filepath, 'rb') as f:
            # Load PEM encoded public key
            public_key = serialization.load_pem_public_key(f.read())
            # convert to raw 32-byte format for easier handling
            return public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
    
    @staticmethod
    def ed25519_sign(private_key, message):
        """
        Sign a message with Ed25519 private key.
        
        Args:
            private_key: Ed25519PrivateKey object
            message: bytes to sign
            
        Returns:
            bytes: 64-byte signature
        """
        return private_key.sign(message)
    
    @staticmethod
    def ed25519_verify(public_key_bytes, signature, message):
        """
        Verify an Ed25519 signature.
        
        Args:
            public_key_bytes: 32-byte public key
            signature: 64-byte signature
            message: bytes that were signed
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Reconstruct public key from raw bytes
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            # Verify signature (raises exception if invalid)
            public_key.verify(signature, message)
            return True
        except Exception:
            # Invalid signature or malformed data
            return False
    
    @staticmethod
    def sha256(data):
        """
        Compute SHA-256 hash of data.
        
        Args:
            data: bytes to hash
            
        Returns:
            bytes: 32-byte hash
        """
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def hkdf_derive_keys(shared_secret, transcript_hash, key_length=96):
        """
        Derive symmetric keys from shared secret using HKDF-SHA256.
        
        Uses standard HKDF with IKM = shared_secret || transcript_hash.
        This provides three 32-byte keys with direction separation:
        - k_app_bob_to_alice (0:32) for Bob→Alice encryption
        - k_app_alice_to_bob (32:64) for Alice→Bob encryption  
        - k_confirm (64:96) for HMAC key confirmation
        
        Args:
            shared_secret: bytes from ECDH
            transcript_hash: SHA-256 hash of handshake transcript
            key_length: total bytes to derive (default 96 for three 32-byte keys)
            
        Returns:
            bytes: Derived key material
        """
        # Combine ECDH secret with transcript to bind keys to this specific handshake
        ikm = shared_secret + transcript_hash
        
        # HKDF expands shared secret into multiple keys
        # No salt needed: X25519 output has sufficient entropy
        # Configure HKDF with SHA-256
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=b'secure-telemetry-v1',  # Domain separation for protocol version
        )
        # Derive key material from IKM
        key_material = hkdf.derive(ikm)
        
        return key_material
    
    @staticmethod
    def hmac_sha256(key, message):
        """
        Compute HMAC-SHA256 of message with key.
        
        Args:
            key: bytes for HMAC key
            message: bytes to authenticate
            
        Returns:
            bytes: 32-byte HMAC tag
        """
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        return h.finalize()
    
    @staticmethod
    def hmac_verify(key, message, tag):
        """
        Verify HMAC-SHA256 tag.
        
        Args:
            key: bytes for HMAC key
            message: bytes that were authenticated
            tag: expected HMAC tag
            
        Returns:
            bool: True if tag is valid, False otherwise
        """
        try:
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(message)
            h.verify(tag)
            return True
        except Exception:
            return False
    
    @staticmethod
    def aes_gcm_encrypt(key, nonce, plaintext, aad):
        """
        Encrypt plaintext with AES-256-GCM.
        
        Args:
            key: 32-byte encryption key
            nonce: 12-byte nonce (must be unique per key)
            plaintext: bytes to encrypt
            aad: additional authenticated data (not encrypted)
            
        Returns:
            bytes: ciphertext with authentication tag appended
        """
        # Initialise AES-GCM with the encryption key
        aesgcm = AESGCM(key)
        # Encrypt and authenticate (returns ciphertext + 16-byte tag)
        return aesgcm.encrypt(nonce, plaintext, aad)
    
    @staticmethod
    def aes_gcm_decrypt(key, nonce, ciphertext_with_tag, aad):
        """
        Decrypt ciphertext with AES-256-GCM.
        
        Args:
            key: 32-byte encryption key
            nonce: 12-byte nonce
            ciphertext_with_tag: encrypted data with 16-byte tag appended
            aad: additional authenticated data
            
        Returns:
            bytes: decrypted plaintext, or None if authentication fails
        """
        try:
            # Initialise AES-GCM with the decryption key
            aesgcm = AESGCM(key)
            # decrypt and verify tag (raises exception if tag invalid)
            return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except Exception:
            return None # auth failed