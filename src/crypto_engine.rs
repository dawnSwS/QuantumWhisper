use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key as AesKey, Nonce as AesNonce,
};
use argon2::Argon2;
use chacha20poly1305::{Key as XKey, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use ml_dsa::{signature::Verifier, MlDsa87, VerifyingKey as MlDsa87VerifyingKey};
use ml_kem::{
    kem::Decapsulate,
    DecapsulationKey1024, EncapsulationKey1024, MlKem1024,
};

use crate::protocol::*;

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidSignature,
    KeyExchangeFailed(&'static str),
    EncryptionFailed(&'static str),
    KeyDerivationFailed(&'static str),
    StateError(String),
    SerializationError(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for CryptoError {}

pub struct PeerSession {
    pub pending_kem_sk: Option<Vec<u8>>,
    pub session_key: Option<[u8; 32]>,
    pub is_authenticated: bool,
}

impl PeerSession {
    pub fn new() -> Self {
        Self {
            pending_kem_sk: None,
            session_key: None,
            is_authenticated: false,
        }
    }
}

impl Default for PeerSession {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CryptoEngine {
    server_dsa_pk: Option<Vec<u8>>,
    pending_transport_sk: Option<Vec<u8>>,
    transport_key: Option<[u8; 32]>,
    peers: HashMap<String, PeerSession>,
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self {
            server_dsa_pk: None,
            pending_transport_sk: None,
            transport_key: None,
            peers: HashMap::new(),
        }
    }

    pub fn verify_server_hello(&mut self, server_pk: &[u8]) -> Result<(), CryptoError> {
        let _ = MlDsa87VerifyingKey::try_from(server_pk)
            .map_err(|_| CryptoError::InvalidSignature)?;

        self.server_dsa_pk = Some(server_pk.to_vec());
        Ok(())
    }

    pub fn generate_client_key_exchange(&mut self) -> Result<Vec<u8>, CryptoError> {
        let (dk, ek) = MlKem1024::generate_keypair();
        self.pending_transport_sk = Some(dk.as_ref().to_vec());
        Ok(ek.as_ref().to_vec())
    }

    pub fn establish_transport_key(
        &mut self,
        ciphertext: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let pk_bytes = self
            .server_dsa_pk
            .as_ref()
            .ok_or_else(|| CryptoError::StateError("Server ML-DSA-87 PK not set".into()))?;

        let server_pk = MlDsa87VerifyingKey::try_from(pk_bytes.as_slice())
            .map_err(|_| CryptoError::InvalidSignature)?;

        let sig = ml_dsa::Signature::<MlDsa87>::try_from(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;

        server_pk
            .verify(ciphertext, &sig)
            .map_err(|_| CryptoError::InvalidSignature)?;

        let mut sk_bytes = self
            .pending_transport_sk
            .take()
            .ok_or_else(|| CryptoError::StateError("Missing pending transport KEM SK".into()))?;

        let dk = DecapsulationKey1024::try_from(sk_bytes.as_slice())
            .map_err(|_| CryptoError::KeyExchangeFailed("Invalid transport SK format"))?;

        let ct = ciphertext.try_into()
            .map_err(|_| CryptoError::KeyExchangeFailed("Invalid transport CT format"))?;

        let shared_secret = dk
            .decapsulate(&ct)
            .map_err(|_| CryptoError::KeyExchangeFailed("Transport decapsulation failed"))?;

        sk_bytes.zeroize();

        let hk = Hkdf::<Sha512>::new(None, shared_secret.as_ref());
        let mut transport_key = [0u8; 32];
        hk.expand(b"c2s_flow", &mut transport_key)
            .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expand failed"))?;

        self.transport_key = Some(transport_key);
        Ok(())
    }

    pub fn encrypt_server_message(&self, message: &ServerMessage) -> Result<ServerEnvelope, CryptoError> {
        let key_bytes = self
            .transport_key
            .as_ref()
            .ok_or_else(|| CryptoError::StateError("Transport key not established".into()))?;

        let plain_bytes = bincode::serialize(message)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        let cipher = Aes256Gcm::new(AesKey::from_slice(key_bytes));

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let ciphertext = cipher
            .encrypt(AesNonce::from_slice(&nonce_bytes), plain_bytes.as_ref())
            .map_err(|_| CryptoError::EncryptionFailed("AES-GCM encryption failed"))?;

        Ok(ServerEnvelope {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    pub fn decrypt_server_message(
        &self,
        envelope: &ServerEnvelope,
    ) -> Result<ServerMessage, CryptoError> {
        let key_bytes = self
            .transport_key
            .as_ref()
            .ok_or_else(|| CryptoError::StateError("Transport key not established".into()))?;

        let cipher = Aes256Gcm::new(AesKey::from_slice(key_bytes));

        let plain_bytes = cipher
            .decrypt(
                AesNonce::from_slice(&envelope.nonce),
                envelope.ciphertext.as_ref(),
            )
            .map_err(|_| {
                CryptoError::EncryptionFailed(
                    "AES-GCM MAC validation failed (Data Tampered!)",
                )
            })?;

        bincode::deserialize(&plain_bytes)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    pub fn initiate_peer_key_exchange(
        &mut self,
        target_client_id: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let (dk, ek) = MlKem1024::generate_keypair();

        let peer = self
            .peers
            .entry(target_client_id.to_string())
            .or_insert_with(PeerSession::new);
        peer.pending_kem_sk = Some(dk.as_ref().to_vec());

        Ok(ek.as_ref().to_vec())
    }

    pub fn accept_peer_key_exchange(
        &self,
        client_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let ek = EncapsulationKey1024::try_from(client_pk)
            .map_err(|_| CryptoError::KeyExchangeFailed("Invalid Peer PK format"))?;

        let (ct, shared_secret) = ek.encapsulate();

        Ok((ct.as_ref().to_vec(), shared_secret.as_ref().to_vec()))
    }

    pub fn finish_peer_key_exchange(
        &mut self,
        target_client_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let peer = self
            .peers
            .get_mut(target_client_id)
            .ok_or_else(|| CryptoError::StateError("Target peer not found".into()))?;

        let mut sk_bytes = peer
            .pending_kem_sk
            .take()
            .ok_or_else(|| CryptoError::StateError("Missing pending Peer KEM SK".into()))?;

        let dk = DecapsulationKey1024::try_from(sk_bytes.as_slice())
            .map_err(|_| CryptoError::KeyExchangeFailed("Invalid Peer SK format"))?;

        let ct = ciphertext.try_into()
            .map_err(|_| CryptoError::KeyExchangeFailed("Invalid Peer CT format"))?;

        let shared_secret = dk
            .decapsulate(&ct)
            .map_err(|_| CryptoError::KeyExchangeFailed("Peer Decapsulation failed"))?;

        sk_bytes.zeroize();

        Ok(shared_secret.as_ref().to_vec())
    }

    pub fn derive_peer_session_key(
        &mut self,
        target_client_id: &str,
        shared_secret: &[u8],
        password: &str,
        salt: &[u8],
    ) -> Result<(), CryptoError> {
        let mut password_hash = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut password_hash)
            .map_err(|_| CryptoError::KeyDerivationFailed("Argon2id hashing failed"))?;

        let hk = Hkdf::<Sha512>::new(Some(&password_hash), shared_secret);
        let mut session_key = [0u8; 32];
        hk.expand(b"c2c_session_key", &mut session_key)
            .map_err(|_| {
                CryptoError::KeyDerivationFailed("HKDF peer session key expand failed")
            })?;

        let peer = self
            .peers
            .entry(target_client_id.to_string())
            .or_insert_with(PeerSession::new);
        peer.session_key = Some(session_key);
        peer.is_authenticated = false;

        password_hash.zeroize();
        Ok(())
    }

    pub fn compute_auth_mac(
        &self,
        peer_id: &str,
        sender_id: &str,
        receiver_id: &str,
        sender_username: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let peer = self
            .peers
            .get(peer_id)
            .ok_or_else(|| CryptoError::StateError("Peer not found".into()))?;
        let session_key = peer
            .session_key
            .as_ref()
            .ok_or_else(|| CryptoError::StateError("Session key missing".into()))?;

        let mut mac = Hmac::<Sha256>::new_from_slice(session_key)
            .map_err(|_| CryptoError::StateError("HMAC init failed".into()))?;
        mac.update(sender_username.as_bytes());
        mac.update(sender_id.as_bytes());
        mac.update(receiver_id.as_bytes());
        mac.update(b"peer_auth_proof");

        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn verify_auth_mac(
        &self,
        peer_id: &str,
        sender_id: &str,
        receiver_id: &str,
        sender_username: &str,
        received_mac: &[u8],
    ) -> Result<bool, CryptoError> {
        let expected_mac = self.compute_auth_mac(peer_id, sender_id, receiver_id, sender_username)?;
        if expected_mac.len() != received_mac.len() {
            return Ok(false);
        }
        Ok(bool::from(expected_mac.as_slice().ct_eq(received_mac)))
    }

    pub fn set_peer_authenticated(&mut self, peer_id: &str) -> Result<(), CryptoError> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| CryptoError::StateError("Peer not found".into()))?;
        peer.is_authenticated = true;
        Ok(())
    }

    pub fn is_peer_authenticated(&self, peer_id: &str) -> bool {
        self.peers.get(peer_id).map(|p| p.is_authenticated).unwrap_or(false)
    }

    pub fn encrypt_peer_message(
        &self,
        target_client_id: &str,
        message: &PeerMessage,
    ) -> Result<PeerEnvelope, CryptoError> {
        let peer = self
            .peers
            .get(target_client_id)
            .ok_or_else(|| CryptoError::StateError("Peer not found".into()))?;

        if !peer.is_authenticated {
            match message {
                PeerMessage::AuthRequest { .. } | PeerMessage::AuthResponse { .. } => {},
                _ => return Err(CryptoError::StateError("Cannot encrypt message for unauthenticated peer".into())),
            }
        }

        let key_bytes = peer
            .session_key
            .as_ref()
            .ok_or_else(|| CryptoError::StateError("Session key missing".into()))?;

        let plain_bytes = bincode::serialize(message)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = XChaCha20Poly1305::new(XKey::from_slice(key_bytes));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce_bytes), plain_bytes.as_ref())
            .map_err(|_| CryptoError::EncryptionFailed("XChaCha20 encryption failed"))?;

        Ok(PeerEnvelope {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    pub fn decrypt_peer_message(
        &self,
        sender_client_id: &str,
        envelope: &PeerEnvelope,
    ) -> Result<PeerMessage, CryptoError> {
        let peer = self
            .peers
            .get(sender_client_id)
            .ok_or_else(|| CryptoError::StateError("Peer not found".into()))?;

        let key_bytes = peer
            .session_key
            .as_ref()
            .ok_or_else(|| CryptoError::StateError("Session key missing".into()))?;

        let cipher = XChaCha20Poly1305::new(XKey::from_slice(key_bytes));

        let plain_bytes = cipher
            .decrypt(
                XNonce::from_slice(&envelope.nonce),
                envelope.ciphertext.as_ref(),
            )
            .map_err(|_| {
                CryptoError::EncryptionFailed(
                    "XChaCha20 MAC verification failed (Data Tampered!)",
                )
            })?;

        bincode::deserialize(&plain_bytes)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::SigningKey;
    use signature::Signer;

    #[test]
    fn test_server_packing_unpacking() {
        let mut engine = CryptoEngine::new();
        engine.transport_key = Some([7u8; 32]);

        let msg = ServerMessage::JoinRoom {
            room_id: "test_room".to_string(),
        };

        let envelope = engine.encrypt_server_message(&msg).unwrap();
        let decrypted = engine.decrypt_server_message(&envelope).unwrap();

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_peer_kem_flow() {
        let mut client_a = CryptoEngine::new();
        let client_b = CryptoEngine::new();

        let target_id = "client_b";

        let pk_a = client_a.initiate_peer_key_exchange(target_id).unwrap();

        let (ct_b, secret_b) = client_b
            .accept_peer_key_exchange(&pk_a)
            .unwrap();

        let secret_a = client_a
            .finish_peer_key_exchange(target_id, &ct_b)
            .unwrap();

        assert_eq!(secret_a, secret_b);
    }

    #[test]
    fn test_peer_packing_unpacking() {
        let mut client_a = CryptoEngine::new();
        let mut client_b = CryptoEngine::new();
        let target_id = "client_b";
        let sender_id = "client_a";

        client_a.peers.insert(
            target_id.to_string(),
            PeerSession {
                pending_kem_sk: None,
                session_key: Some([5u8; 32]),
                is_authenticated: true,
            },
        );

        client_b.peers.insert(
            sender_id.to_string(),
            PeerSession {
                pending_kem_sk: None,
                session_key: Some([5u8; 32]),
                is_authenticated: true,
            },
        );

        let msg = PeerMessage::ChatMessage {
            timestamp: 100,
            content: "Secret Message".to_string(),
        };

        let envelope = client_a.encrypt_peer_message(target_id, &msg).unwrap();
        let decrypted = client_b
            .decrypt_peer_message(sender_id, &envelope)
            .unwrap();

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_server_kem_flow() {
        let mut client_engine = CryptoEngine::new();

        let mut rng = OsRng;
        let server_sk = SigningKey::<MlDsa87>::generate(&mut rng);
        let server_pk = server_sk.verifying_key().to_bytes().to_vec();

        client_engine.verify_server_hello(&server_pk).unwrap();

        let client_pk = client_engine.generate_client_key_exchange().unwrap();

        let ek = EncapsulationKey1024::try_from(client_pk.as_slice()).unwrap();
        let (ct, shared_secret_server) = ek.encapsulate();

        let signature = server_sk.sign(ct.as_ref());

        client_engine
            .establish_transport_key(ct.as_ref(), signature.as_bytes())
            .unwrap();

        let hk = Hkdf::<Sha512>::new(None, shared_secret_server.as_ref());
        let mut transport_key = [0u8; 32];
        hk.expand(b"c2s_flow", &mut transport_key).unwrap();

        assert_eq!(client_engine.transport_key.unwrap(), transport_key);
    }
}