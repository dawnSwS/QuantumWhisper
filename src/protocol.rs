use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum NetworkMessage {
    ServerHello {
        #[serde(with = "serde_bytes")]
        server_pk: Vec<u8>,
    },
    ClientKeyExchange {
        #[serde(with = "serde_bytes")]
        client_pk: Vec<u8>,
    },
    ServerKeyExchange {
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
    EncryptedPayload(ServerEnvelope),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerEnvelope {
    pub nonce: [u8; 12],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ServerMessage {
    JoinRoom {
        room_id: String,
    },
    RoomMembers {
        members: Vec<String>,
    },
    PeerExchangeInit {
        target_client_id: String,
        sender_client_id: String,
        #[serde(with = "serde_bytes")]
        client_pk: Vec<u8>,
    },
    PeerExchangeResponse {
        target_client_id: String,
        sender_client_id: String,
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
    },
    RelayPeerMessage {
        target_client_id: String,
        sender_client_id: String,
        peer_envelope: PeerEnvelope,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PeerEnvelope {
    pub nonce: [u8; 24],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum PeerMessage {
    AuthRequest {
        username: String,
        #[serde(with = "serde_bytes")]
        auth_mac: Vec<u8>,
    },
    AuthResponse {
        username: String,
        #[serde(with = "serde_bytes")]
        auth_mac: Vec<u8>,
    },
    ChatMessage {
        timestamp: u64,
        content: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_message_serialization() {
        let msg = NetworkMessage::ServerHello {
            server_pk: vec![1, 2, 3, 4],
        };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: NetworkMessage = bincode::deserialize(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_server_message_serialization() {
        let msg = ServerMessage::JoinRoom {
            room_id: "room_123".to_string(),
        };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: ServerMessage = bincode::deserialize(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_peer_message_serialization() {
        let msg = PeerMessage::ChatMessage {
            timestamp: 1670000000,
            content: "Hello PQC".to_string(),
        };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: PeerMessage = bincode::deserialize(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }
}
