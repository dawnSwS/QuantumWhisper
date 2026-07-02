use crate::crypto_engine::{CryptoEngine, CryptoError};
use crate::protocol::{NetworkMessage, PeerMessage, ServerMessage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientState {
    Disconnected,
    WaitingForServerKey,
    Connected,
    RoomJoined,
}

pub struct ChatClient {
    pub client_id: String,
    pub username: String,
    pub room_id: String,
    pub room_password: String,

    pub state: ClientState,
    pub crypto: CryptoEngine,

    pub chat_inbox: Vec<(String, u64, String)>,
}

impl ChatClient {
    pub fn new(
        client_id: String,
        username: String,
        room_id: String,
        room_password: String,
    ) -> Self {
        Self {
            client_id,
            username,
            room_id,
            room_password,
            state: ClientState::Disconnected,
            crypto: CryptoEngine::new(),
            chat_inbox: Vec::new(),
        }
    }

    fn get_room_salt(&self) -> Vec<u8> {
        let mut salt = self.room_id.as_bytes().to_vec();
        if salt.len() < 16 {
            salt.resize(16, 0);
        }
        salt
    }

    pub fn process_network_message(
        &mut self,
        msg: NetworkMessage,
    ) -> Result<Vec<NetworkMessage>, CryptoError> {
        let mut responses = Vec::new();

        match msg {
            NetworkMessage::ServerHello { server_pk } => {
                if self.state != ClientState::Disconnected {
                    return Err(CryptoError::StateError(
                        "Unexpected ServerHello in current state".into(),
                    ));
                }

                self.crypto.verify_server_hello(&server_pk)?;
                let client_pk = self.crypto.generate_client_key_exchange()?;

                self.state = ClientState::WaitingForServerKey;
                responses.push(NetworkMessage::ClientKeyExchange {
                    client_pk,
                });
            }

            NetworkMessage::ServerKeyExchange {
                ciphertext,
                signature,
            } => {
                if self.state != ClientState::WaitingForServerKey {
                    return Err(CryptoError::StateError(
                        "Unexpected ServerKeyExchange in current state".into(),
                    ));
                }

                self.crypto
                    .establish_transport_key(&ciphertext, &signature)?;
                self.state = ClientState::Connected;

                let join_req = ServerMessage::JoinRoom {
                    room_id: self.room_id.clone(),
                };
                let env = self.crypto.encrypt_server_message(&join_req)?;
                responses.push(NetworkMessage::EncryptedPayload(env));
            }

            NetworkMessage::ClientKeyExchange { .. } => {
                return Err(CryptoError::StateError(
                    "Client should not receive ClientKeyExchange".into(),
                ));
            }

            NetworkMessage::EncryptedPayload(env) => {
                if self.state == ClientState::Disconnected || self.state == ClientState::WaitingForServerKey
                {
                    return Err(CryptoError::StateError(
                        "Transport layer not secured yet".into(),
                    ));
                }

                let server_msg = self.crypto.decrypt_server_message(&env)?;

                let mut trans_responses = self.handle_server_message(server_msg)?;
                responses.append(&mut trans_responses);
            }
        }

        Ok(responses)
    }

    fn handle_server_message(
        &mut self,
        msg: ServerMessage,
    ) -> Result<Vec<NetworkMessage>, CryptoError> {
        let mut responses = Vec::new();

        match msg {
            ServerMessage::RoomMembers { members } => {
                self.state = ClientState::RoomJoined;

                for member_id in members {
                    if member_id == self.client_id {
                        continue;
                    }
                    let client_pk = self.crypto.initiate_peer_key_exchange(&member_id)?;
                    let init_msg = ServerMessage::PeerExchangeInit {
                        target_client_id: member_id.clone(),
                        sender_client_id: self.client_id.clone(),
                        client_pk,
                    };
                    let env = self.crypto.encrypt_server_message(&init_msg)?;
                    responses.push(NetworkMessage::EncryptedPayload(env));
                }
            }

            ServerMessage::PeerExchangeInit {
                target_client_id,
                sender_client_id,
                client_pk,
            } => {
                if target_client_id != self.client_id {
                    return Ok(responses);
                }

                let (ciphertext, shared_secret) = self
                    .crypto
                    .accept_peer_key_exchange(&client_pk)?;
                let salt = self.get_room_salt();

                self.crypto.derive_peer_session_key(
                    &sender_client_id,
                    &shared_secret,
                    &self.room_password,
                    &salt,
                )?;

                let resp_msg = ServerMessage::PeerExchangeResponse {
                    target_client_id: sender_client_id.clone(),
                    sender_client_id: self.client_id.clone(),
                    ciphertext,
                };
                let env = self.crypto.encrypt_server_message(&resp_msg)?;
                responses.push(NetworkMessage::EncryptedPayload(env));
            }

            ServerMessage::PeerExchangeResponse {
                target_client_id,
                sender_client_id,
                ciphertext,
            } => {
                if target_client_id != self.client_id {
                    return Ok(responses);
                }

                let shared_secret = self
                    .crypto
                    .finish_peer_key_exchange(&sender_client_id, &ciphertext)?;
                let salt = self.get_room_salt();

                self.crypto.derive_peer_session_key(
                    &sender_client_id,
                    &shared_secret,
                    &self.room_password,
                    &salt,
                )?;

                let auth_mac = self.crypto.compute_auth_mac(
                    &sender_client_id,
                    &self.client_id,
                    &sender_client_id,
                    &self.username,
                )?;

                let auth_req = PeerMessage::AuthRequest {
                    username: self.username.clone(),
                    auth_mac,
                };

                let ws_msg = self.encapsulate_peer_message(&sender_client_id, &auth_req)?;
                responses.push(ws_msg);
            }

            ServerMessage::RelayPeerMessage {
                target_client_id,
                sender_client_id,
                peer_envelope,
            } => {
                if target_client_id != self.client_id {
                    return Ok(responses);
                }

                let peer_msg = self
                    .crypto
                    .decrypt_peer_message(&sender_client_id, &peer_envelope)?;

                match peer_msg {
                    PeerMessage::AuthRequest {
                        username,
                        auth_mac,
                    } => {
                        let is_valid = self.crypto.verify_auth_mac(
                            &sender_client_id,
                            &sender_client_id,
                            &self.client_id,
                            &username,
                            &auth_mac,
                        )?;

                        if !is_valid {
                            return Err(CryptoError::StateError(
                                "Peer authentication failed".into(),
                            ));
                        }

                        self.crypto.set_peer_authenticated(&sender_client_id)?;

                        let my_mac = self.crypto.compute_auth_mac(
                            &sender_client_id,
                            &self.client_id,
                            &sender_client_id,
                            &self.username,
                        )?;

                        let auth_resp = PeerMessage::AuthResponse {
                            username: self.username.clone(),
                            auth_mac: my_mac,
                        };

                        let ws_msg = self.encapsulate_peer_message(&sender_client_id, &auth_resp)?;
                        responses.push(ws_msg);
                    }
                    PeerMessage::AuthResponse {
                        username,
                        auth_mac,
                    } => {
                        let is_valid = self.crypto.verify_auth_mac(
                            &sender_client_id,
                            &sender_client_id,
                            &self.client_id,
                            &username,
                            &auth_mac,
                        )?;

                        if !is_valid {
                            return Err(CryptoError::StateError(
                                "Peer authentication failed".into(),
                            ));
                        }

                        self.crypto.set_peer_authenticated(&sender_client_id)?;
                    }
                    PeerMessage::ChatMessage { timestamp, content } => {
                        if !self.crypto.is_peer_authenticated(&sender_client_id) {
                            return Err(CryptoError::StateError(
                                "Received chat message from unauthenticated peer".into(),
                            ));
                        }
                        self.chat_inbox.push((sender_client_id, timestamp, content));
                    }
                }
            }

            ServerMessage::JoinRoom { .. } => {}
        }

        Ok(responses)
    }

    fn encapsulate_peer_message(
        &self,
        target_client_id: &str,
        msg: &PeerMessage,
    ) -> Result<NetworkMessage, CryptoError> {
        let peer_envelope = self.crypto.encrypt_peer_message(target_client_id, msg)?;
        let server_msg = ServerMessage::RelayPeerMessage {
            target_client_id: target_client_id.to_string(),
            sender_client_id: self.client_id.clone(),
            peer_envelope,
        };
        Ok(NetworkMessage::EncryptedPayload(
            self.crypto.encrypt_server_message(&server_msg)?,
        ))
    }

    pub fn send_chat_message(
        &self,
        target_client_id: &str,
        content: String,
    ) -> Result<NetworkMessage, CryptoError> {
        if self.state != ClientState::RoomJoined {
            return Err(CryptoError::StateError(
                "Cannot send chat before joining a room".into(),
            ));
        }

        if !self.crypto.is_peer_authenticated(target_client_id) {
            return Err(CryptoError::StateError(
                "Cannot send chat to unauthenticated peer".into(),
            ));
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        let msg = PeerMessage::ChatMessage { timestamp, content };

        self.encapsulate_peer_message(target_client_id, &msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::SigningKey;
    use ml_kem::EncapsulationKey1024;
    use rand::rngs::OsRng;
    use signature::Signer;

    #[test]
    fn test_client_state_machine_init() {
        let mut client = ChatClient::new(
            "client1".to_string(),
            "user1".to_string(),
            "room1".to_string(),
            "pass1".to_string(),
        );

        assert_eq!(client.state, ClientState::Disconnected);

        let mut rng = OsRng;
        let server_sk = SigningKey::<ml_dsa::MlDsa87>::generate(&mut rng);
        let server_pk = server_sk.verifying_key().to_bytes().to_vec();

        let responses = client
            .process_network_message(NetworkMessage::ServerHello { server_pk })
            .unwrap();

        assert_eq!(client.state, ClientState::WaitingForServerKey);
        assert_eq!(responses.len(), 1);

        if let NetworkMessage::ClientKeyExchange { client_pk } = &responses[0] {
            let ek = EncapsulationKey1024::try_from(client_pk.as_slice()).unwrap();
            let (ct, _) = ek.encapsulate();
            let sig = server_sk.sign(ct.as_ref());

            let responses2 = client
                .process_network_message(NetworkMessage::ServerKeyExchange {
                    ciphertext: ct.as_ref().to_vec(),
                    signature: sig.as_bytes().to_vec(),
                })
                .unwrap();

            assert_eq!(client.state, ClientState::Connected);
            assert_eq!(responses2.len(), 1);
        } else {
            panic!("Expected ClientKeyExchange");
        }
    }

    #[test]
    fn test_send_chat_message_requires_room_joined() {
        let client = ChatClient::new(
            "client1".to_string(),
            "user1".to_string(),
            "room1".to_string(),
            "pass1".to_string(),
        );

        let result = client.send_chat_message("client2", "hello".to_string());
        assert!(result.is_err());
    }
}