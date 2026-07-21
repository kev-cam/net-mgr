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
use tokio::io::{AsyncBufReadExt, BufReader};

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
        // Sync our peer_id to whatever the mesh derived (SHA256(noise_pk)[:8]).
        // packet_processor uses delegate.get_my_peer_id() for "is this packet
        // from me?" checks — if it disagrees with the mesh's own peer_id our
        // packets get treated as "not self" and echoed back, and mainline sees
        // sender_id ≠ SHA256(noise_pk)[:8] and rejects us at Announce preflight.
        let mesh_peer_id = mesh.get_peer_id_hex();
        *self.peer_id.write().await = mesh_peer_id;
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
    // Cross-site mesh relay: emit every raw wire packet the helper receives
    // from BLE, BEFORE decode. The supervisor forwards these to peer bridge
    // sites over IP; peer helpers inject them via inject_packet cmd. from
    // is either a BLE MAC ("6A:44:FC:CE:A4:B5") or "relay:<peer_bridge>" for
    // IP-injected packets — so a peer bridge can distinguish and NOT relay
    // packets it received from another relay (breaks amplification loops).
    async fn did_receive_raw_packet(&self, bytes: Vec<u8>, from_address: String) {
        emit(json!({
            "type": "packet_rx",
            "hex":  hex::encode(&bytes),
            "from": from_address,
            "len":  bytes.len(),
        }));
    }

    async fn did_receive_message(&self, message: BitchatMessage) {
        // None = the default Mesh broadcast surface; Some(s) is a geohash
        // channel (Block/Neighborhood/City/...) which would have arrived via
        // Nostr. The earlier label "public" was wrong — there is no public
        // channel in BitChat, only Mesh + geohash tiers + DMs.
        let channel = message
            .channel
            .clone()
            .unwrap_or_else(|| "mesh".to_string());
        // Include the sender's 16-hex peer_id so the supervisor can route
        // an automated DM back to just that peer (e.g. the WiFi-onramp
        // "WiFi?" auto-response). BitchatMessage carries it as
        // Option<String>; empty string when absent so downstream JSON parsers
        // don't have to distinguish null vs missing.
        emit(json!({
            "type":           "msg",
            "sender":         message.sender,
            "sender_peer_id": message.sender_peer_id.clone().unwrap_or_default(),
            "body":           message.content,
            "ts":             message.timestamp.timestamp(),
            "channel":        channel,
            "is_dm":          message.is_private,
            "id":             message.id,
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
    async fn did_receive_noise_handshake_init(&self, peer_id: String, p: Packet) {
        // The stock stub just logged and swallowed the packet — no
        // responder ever ran, so foreign initiators (our Java Android
        // client, third-party ports) got radio silence. Wire the
        // mesh service's responder here, matching how main.rs bridges
        // the same delegate event into `mesh_service.handle_noise_
        // handshake_init(...)` via an AppEvent hop.
        log("noise/init", &peer_id);
        let pid = peer_id.clone();
        let pkt = p.clone();
        self.with_mesh("noise/init", |mesh| async move {
            mesh.handle_noise_handshake_init(pid, pkt).await
                .map_err(|e| anyhow::anyhow!(e))
        })
        .await;
    }
    async fn did_receive_noise_handshake_response(&self, peer_id: String, p: Packet) {
        // Same fix as the init handler: forward to the mesh service so
        // (a) as initiator we produce msg 3, (b) as responder we consume
        // msg 3 and promote to transport. handle_noise_handshake_response
        // dispatches internally on session state.
        log("noise/resp", &peer_id);
        let pid = peer_id.clone();
        let pkt = p.clone();
        self.with_mesh("noise/resp", |mesh| async move {
            mesh.handle_noise_handshake_response(pid, pkt).await
                .map_err(|e| anyhow::anyhow!(e))
        })
        .await;
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

    let delegate = Arc::new(JsonDelegate::new(nickname.clone()));
    let mesh = Arc::new(BluetoothMeshService::new(delegate.clone()).await?);
    // Plug the mesh handle back into the delegate so the should_* callbacks
    // can drive Noise handshakes. Without this the mesh service never
    // completes a handshake and the bridge only sees System announcements.
    delegate.set_mesh(mesh.clone()).await;
    mesh.start().await?;
    eprintln!("[startup] mesh service started; awaiting messages");

    // Command reader: one JSON object per stdin line drives outbound mesh
    // ops. Kept minimal — the Perl supervisor's job is to source these
    // from net-chat subscriptions and pipe them in. Supported:
    //   {"cmd":"peers"}                                — dump known peers
    //   {"cmd":"send","body":"..."}                    — broadcast on mesh
    //   {"cmd":"send","body":"...","to":"nickname"}    — private to a peer
    // Results go to stdout as JSON lines (same channel as inbound msg
    // events) tagged {"type":"cmd_reply","cmd":..., ...}. Errors are
    // reported inline as {"type":"cmd_reply","ok":false,"err":"..."}.
    let mesh_stdin = mesh.clone();
    let my_nick = nickname.clone();
    tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue }
                    let ev: serde_json::Value = match serde_json::from_str(line) {
                        Ok(v)  => v,
                        Err(e) => {
                            println!("{}", json!({
                                "type": "cmd_reply",
                                "ok":   false,
                                "err":  format!("bad json: {}", e),
                            }));
                            continue;
                        }
                    };
                    let cmd = ev.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
                    match cmd {
                        "peers" => {
                            let peers = mesh_stdin.get_peer_manager().get_all_peers().await;
                            let out: Vec<_> = peers.iter().map(|p| json!({
                                "nickname":   p.nickname.clone().unwrap_or_default(),
                                "peer_id":    p.id,
                                "connected":  p.is_connected,
                                "last_seen":  p.last_seen.to_rfc3339(),
                            })).collect();
                            println!("{}", json!({
                                "type":  "cmd_reply",
                                "cmd":   "peers",
                                "ok":    true,
                                "count": out.len(),
                                "peers": out,
                            }));
                        }
                        "send" => {
                            let body = ev.get("body").and_then(|v| v.as_str())
                                        .unwrap_or("").to_string();
                            let to      = ev.get("to").and_then(|v| v.as_str())
                                            .map(String::from);
                            let to_peer = ev.get("to_peer").and_then(|v| v.as_str())
                                            .map(String::from);
                            if body.is_empty() {
                                println!("{}", json!({
                                    "type": "cmd_reply", "cmd": "send",
                                    "ok": false, "err": "empty body",
                                }));
                                continue;
                            }
                            let msg = BitchatMessage::new(
                                my_nick.clone(), body.clone(), chrono::Utc::now(),
                            );
                            // Spawned + bounded: bluer's connect/write paths
                            // have no timeout of their own, and awaiting them
                            // inline froze this whole loop when a peripheral
                            // hung (rotating-MAC Android peers) — peers polls
                            // went unanswered and the supervisor's watchdog
                            // killed us. The reader loop must stay live no
                            // matter what one send does.
                            let mesh_send = mesh_stdin.clone();
                            tokio::spawn(async move {
                                // Priority: explicit hex peer_id > nickname > broadcast.
                                // to_peer is 16 hex chars = 8 bytes. Useful when a
                                // peer's stored nickname is garbled (old-format
                                // announce senders) but we know the peer id.
                                let fut = async {
                                    if let Some(hex_id) = to_peer.as_deref() {
                                        match hex::decode(hex_id) {
                                            Ok(bytes) if bytes.len() == 8 => {
                                                let mut rid = [0u8; 8];
                                                rid.copy_from_slice(&bytes);
                                                match mesh_send.send_private_message(msg, rid).await {
                                                    Ok(_)  => (true,  String::new(), format!("private:{}", hex_id)),
                                                    Err(e) => (false, format!("{}", e), format!("private:{}", hex_id)),
                                                }
                                            }
                                            Ok(_)  => (false, "to_peer must decode to 8 bytes".into(), format!("private:{}", hex_id)),
                                            Err(e) => (false, format!("bad hex: {}", e), format!("private:{}", hex_id)),
                                        }
                                    } else if let Some(nick) = to.as_deref() {
                                        match mesh_send.send_private_message_by_nickname(
                                            msg, nick.to_string()).await
                                        {
                                            Ok(_)  => (true,  String::new(), format!("private:{}", nick)),
                                            Err(e) => (false, format!("{}", e), format!("private:{}", nick)),
                                        }
                                    } else {
                                        match mesh_send.send_message(msg).await {
                                            Ok(_)  => (true,  String::new(), "broadcast".to_string()),
                                            Err(e) => (false, format!("{}", e), "broadcast".to_string()),
                                        }
                                    }
                                };
                                let (ok, err, path) = match tokio::time::timeout(
                                    std::time::Duration::from_secs(30), fut).await
                                {
                                    Ok(r)  => r,
                                    Err(_) => (false, "send timed out after 30s (BLE stack hung)".to_string(),
                                               "timeout".to_string()),
                                };
                                println!("{}", json!({
                                    "type": "cmd_reply", "cmd": "send",
                                    "ok":   ok,
                                    "path": path,
                                    "err":  err,
                                }));
                            });
                        }
                        "inject_packet" => {
                            // Cross-site mesh relay: replay raw wire bytes
                            // that another bridge site captured via BLE and
                            // forwarded to us over IP. hex = hex-encoded
                            // full BitChat wire packet (padded, sig+all).
                            // from = synthetic label like "relay:zmc1" — the
                            // helper's packet_processor / bloom filter treats
                            // it exactly like a BLE-received packet.
                            let hex_str = ev.get("hex").and_then(|v| v.as_str())
                                            .unwrap_or("");
                            let from = ev.get("from").and_then(|v| v.as_str())
                                         .unwrap_or("relay:unknown").to_string();
                            match hex::decode(hex_str) {
                                Ok(bytes) => {
                                    // Spawned + bounded for the same reason as
                                    // "send": the local rebroadcast side of an
                                    // injected packet can hang in bluer and
                                    // must not freeze the reader loop.
                                    let n = bytes.len();
                                    let mesh_inj = mesh_stdin.clone();
                                    tokio::spawn(async move {
                                        let (ok, err) = match tokio::time::timeout(
                                            std::time::Duration::from_secs(30),
                                            mesh_inj.inject_raw_packet(bytes, from)).await
                                        {
                                            Ok(_)  => (true, String::new()),
                                            Err(_) => (false, "inject timed out after 30s (BLE stack hung)".to_string()),
                                        };
                                        println!("{}", json!({
                                            "type": "cmd_reply", "cmd": "inject_packet",
                                            "ok":   ok, "len":  n, "err":  err,
                                        }));
                                    });
                                }
                                Err(e) => {
                                    println!("{}", json!({
                                        "type": "cmd_reply", "cmd": "inject_packet",
                                        "ok":   false, "len": 0,
                                        "err":  format!("bad hex: {}", e),
                                    }));
                                }
                            }
                        }
                        other => {
                            println!("{}", json!({
                                "type": "cmd_reply",
                                "ok":   false,
                                "err":  format!("unknown cmd '{}'", other),
                            }));
                        }
                    }
                }
                Ok(None)  => break,   // EOF — supervisor closed stdin
                Err(e)    => { eprintln!("[stdin] read error: {}", e); break }
            }
        }
        eprintln!("[stdin] reader exited");
    });

    // Run until interrupted. Helper exit lets the Perl supervisor respawn.
    tokio::signal::ctrl_c().await?;
    eprintln!("[shutdown] ctrl-c received");
    Ok(())
}
