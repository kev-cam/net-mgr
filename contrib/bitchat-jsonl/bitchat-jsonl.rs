// bitchat-jsonl — a headless BitChat receiver that prints one JSON object
// per received message on stdout. Other delegate events go to stderr (so the
// supervising process can log them).
//
// Designed for the net-bitchat-bridge (Perl) supervisor: each line on stdout
// is a complete JSON object the supervisor decodes and posts via OBSERVE
// kind=chat_msg.
//
// Env:
//   BITCHAT_NICK    nickname this client advertises (default: bigsony-bridge)

use anyhow::Result;
use async_trait::async_trait;
use bitchat_rust::mesh::{BluetoothMeshDelegate, BluetoothMeshService};
use bitchat_rust::model::BitchatMessage;
use bitchat_rust::protocol::Packet;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

struct JsonDelegate {
    nickname: RwLock<String>,
    peer_id: RwLock<String>,
    // Set after BluetoothMeshService::new returns — breaks the Arc cycle.
    // The five `should_*` callbacks below dispatch back through this handle
    // so Noise handshakes actually progress (without it, the mesh service
    // keeps asking "should I initiate?" and the delegate just shrugs, which
    // is exactly what blocked tier-0 from receiving user-typed messages).
    mesh: RwLock<Option<Arc<BluetoothMeshService>>>,
}

impl JsonDelegate {
    fn new(nickname: String) -> Self {
        let mut id_bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut id_bytes);
        let peer_id = hex::encode(id_bytes);
        Self {
            nickname: RwLock::new(nickname),
            peer_id: RwLock::new(peer_id),
            mesh: RwLock::new(None),
        }
    }
    async fn set_mesh(&self, mesh: Arc<BluetoothMeshService>) {
        *self.mesh.write().await = Some(mesh);
    }
    async fn with_mesh<F, Fut>(&self, scope: &str, f: F)
    where
        F: FnOnce(Arc<BluetoothMeshService>) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        let guard = self.mesh.read().await;
        let Some(mesh) = guard.clone() else {
            log(scope, "(mesh not set yet)");
            return;
        };
        drop(guard);
        if let Err(e) = f(mesh).await {
            log(scope, &format!("error: {}", e));
        }
    }
}

fn emit(value: serde_json::Value) {
    if let Ok(s) = serde_json::to_string(&value) {
        println!("{}", s);
    }
}

fn log(scope: &str, detail: &str) {
    eprintln!("[{}] {}", scope, detail);
}

#[async_trait]
impl BluetoothMeshDelegate for JsonDelegate {
    async fn did_receive_message(&self, message: BitchatMessage) {
        // None = the default Mesh broadcast surface; Some(s) is a geohash
        // channel (Block/Neighborhood/City/...) which would have arrived via
        // Nostr. The earlier label "public" was wrong — there is no public
        // channel in BitChat, only Mesh + geohash tiers + DMs.
        let channel = message
            .channel
            .clone()
            .unwrap_or_else(|| "mesh".to_string());
        emit(json!({
            "type":    "msg",
            "sender":  message.sender,
            "body":    message.content,
            "ts":      message.timestamp.timestamp(),
            "channel": channel,
            "is_dm":   message.is_private,
            "id":      message.id,
        }));
    }

    async fn did_connect_to_peer(&self, peer_id: String) {
        log("connect", &peer_id);
    }
    async fn did_disconnect_from_peer(&self, peer_id: String) {
        log("disconnect", &peer_id);
    }
    async fn did_update_peer_list(&self, peers: Vec<String>) {
        log("peers", &format!("{} active", peers.len()));
    }
    async fn did_receive_noise_handshake_init(&self, peer_id: String, _p: Packet) {
        log("noise/init", &peer_id);
    }
    async fn did_receive_noise_handshake_response(&self, peer_id: String, _p: Packet) {
        log("noise/resp", &peer_id);
    }
    async fn did_receive_noise_identity_announce(&self, peer_id: String, _p: Packet) {
        log("noise/announce", &peer_id);
    }
    async fn did_complete_noise_handshake(&self, peer_id: String) {
        log("noise/ok", &peer_id);
    }
    async fn did_fail_noise_handshake(&self, peer_id: String, error: String) {
        log("noise/fail", &format!("{} {}", peer_id, error));
    }
    async fn did_receive_noise_encrypted(&self, peer_id: String, _p: Packet) {
        log("noise/enc", &peer_id);
    }
    async fn did_receive_system_validation(&self, peer_id: String, _p: Packet) {
        log("sysvalid", &peer_id);
    }

    async fn should_connect_to_peer(&self, peer_address: String) {
        log("connect?", &peer_address);
    }
    async fn did_receive_delivery_ack(&self, message_id: String, from_peer: String) {
        log("ack/deliver", &format!("{} from {}", message_id, from_peer));
    }
    async fn did_receive_read_receipt(&self, message_id: String, from_peer: String) {
        log("ack/read", &format!("{} from {}", message_id, from_peer));
    }
    async fn did_receive_typing_indicator(&self, peer_id: String, is_typing: bool) {
        log(
            "typing",
            &format!("{} {}", peer_id, if is_typing { "on" } else { "off" }),
        );
    }
    async fn did_receive_key_verify_request(&self, peer_id: String, _key_hash: Vec<u8>) {
        log("keyverify?", &peer_id);
    }
    async fn did_receive_key_verify_response(&self, peer_id: String, verified: bool) {
        log("keyverify", &format!("{} {}", peer_id, verified));
    }
    async fn did_receive_password_update(
        &self,
        channel: String,
        _password_hash: Vec<u8>,
        from_peer: String,
    ) {
        log("passwd", &format!("{} from {}", channel, from_peer));
    }
    async fn did_receive_channel_metadata(
        &self,
        channel: String,
        _metadata: Vec<u8>,
        from_peer: String,
    ) {
        log("chanmeta", &format!("{} from {}", channel, from_peer));
    }
    async fn should_send_version_ack(&self, peer_id: String, peer_version: u8) {
        log("verack?", &format!("{} v{}", peer_id, peer_version));
    }
    async fn did_complete_version_negotiation(&self, peer_id: String, agreed_version: u8) {
        log("vernego", &format!("{} v{}", peer_id, agreed_version));
    }
    async fn should_initiate_noise_handshake(&self, peer_id: String) {
        log("noise/init?", &peer_id);
        let pid = peer_id.clone();
        self.with_mesh("noise/init", |mesh| async move {
            // Skip if a Noise session already exists — same guard the TUI uses.
            let nser = mesh.get_encryption_service().get_noise_service();
            if nser.has_session(&pid).await {
                log("noise/init", &format!("{} already has session", pid));
                return Ok(());
            }
            mesh.initiate_noise_handshake(pid).await.map_err(|e| anyhow::anyhow!(e))
        })
        .await;
    }
    async fn should_send_handshake_request(&self, target_peer_id: String) {
        log("handshake?", &target_peer_id);
        let tid = target_peer_id.clone();
        self.with_mesh("handshake", |mesh| async move {
            mesh.send_handshake_request(tid).await.map_err(|e| anyhow::anyhow!(e))
        })
        .await;
    }
    async fn should_send_noise_identity_announcement(&self) {
        log("announce?", "self");
        self.with_mesh("announce", |mesh| async move {
            mesh.send_noise_identity_announcement().await.map_err(|e| anyhow::anyhow!(e))
        })
        .await;
    }
    async fn should_send_targeted_noise_identity_announcement(&self, target_peer_id: String) {
        log("announce?", &target_peer_id);
        let tid = target_peer_id.clone();
        self.with_mesh("announce", |mesh| async move {
            mesh.send_noise_identity_announcement_to(Some(tid)).await.map_err(|e| anyhow::anyhow!(e))
        })
        .await;
    }
    async fn get_my_peer_id(&self) -> String {
        self.peer_id.read().await.clone()
    }
    async fn get_my_nickname(&self) -> String {
        self.nickname.read().await.clone()
    }
    async fn should_send_announce(&self) {
        log("announce?", "broadcast");
        self.with_mesh("announce", |mesh| async move {
            mesh.send_announce().await.map_err(|e| anyhow::anyhow!(e))
        })
        .await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // env_logger emits to stderr — keeps our stdout JSON-clean.
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Stderr)
        .init();

    let nickname = std::env::var("BITCHAT_NICK").unwrap_or_else(|_| "bigsony-bridge".to_string());
    eprintln!("[startup] nickname={}", nickname);

    let delegate = Arc::new(JsonDelegate::new(nickname));
    let mesh = Arc::new(BluetoothMeshService::new(delegate.clone()).await?);
    // Plug the mesh handle back into the delegate so the should_* callbacks
    // can drive Noise handshakes. Without this the mesh service never
    // completes a handshake and the bridge only sees System announcements.
    delegate.set_mesh(mesh.clone()).await;
    mesh.start().await?;
    eprintln!("[startup] mesh service started; awaiting messages");

    // Run until interrupted. Helper exit lets the Perl supervisor respawn.
    tokio::signal::ctrl_c().await?;
    eprintln!("[shutdown] ctrl-c received");
    Ok(())
}
