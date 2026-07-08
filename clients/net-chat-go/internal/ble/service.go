// Package ble — cross-platform BLE surface for the bitchat mesh.
//
// The interface deliberately hides both the BLE role split (Central
// scanning + Peripheral advertising happen together for mesh peers)
// and the transport chunking (packets bigger than the GATT MTU get
// fragmented — the caller doesn't need to care). All the mesh layer
// sees is "peer discovered, peer lost, bytes arrived".
package ble

import "context"

// BitchatServiceUUID is the 128-bit UUID we advertise so other bitchat
// peers can find us in the noise. Wire-compatible with iOS/Android/
// bitchat-rust — see mesh/bluetooth_connection_manager.rs.
const BitchatServiceUUID = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"

// BitchatCharacteristicUUID is the read/write/notify GATT
// characteristic that carries wire packets both directions.
const BitchatCharacteristicUUID = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"

// Service is the platform-BLE-facing side of the bitchat mesh. The
// caller (the mesh service) writes Send() to reach a specific peer
// and reads Events() to receive peer roster changes + inbound bytes.
//
// Implementations MUST be safe for concurrent use. Start returns
// after the adapter is initialised — if BLE hardware isn't
// available (desktop with no adapter, phone with BT off) it
// returns an error and Events() stays closed.
type Service interface {
	// Start powers up the adapter, begins scanning + advertising,
	// and stands the GATT server up. localID is our 8-byte peer id
	// (the same one that goes in Packet.SenderID); nickname is
	// broadcast in Announce TLVs and is optional. Cancelling ctx
	// tears everything down.
	Start(ctx context.Context, localID [8]byte, nickname string) error

	// Send delivers one wire packet to a specific peer. Blocks until
	// the write is queued (not until the peer acks). Returns an
	// error if the peer isn't currently reachable or the transport
	// backpressures.
	Send(peerID [8]byte, data []byte) error

	// Broadcast delivers to every currently-connected peer. Used
	// for Announce / public Message packets. Errors on individual
	// peer writes are logged, not returned — a broadcast is
	// best-effort by design.
	Broadcast(data []byte)

	// Events returns a receive-only channel of BLE events. Never
	// nil; closed when Close is called or ctx is cancelled.
	Events() <-chan Event

	// Close tears down scanning, advertising, and any live GATT
	// connections. Safe to call multiple times.
	Close() error
}

// Event is the sum-type BLE surfaces to the mesh layer. Consumers
// switch on the concrete type.
type Event interface{ isBLEEvent() }

// PeerFound signals a peer joined the mesh — the payload can be
// used to send them targeted packets. Address is opaque; the mesh
// layer only tracks by PeerID.
type PeerFound struct {
	PeerID  [8]byte
	Address string
}

// PeerLost signals a peer became unreachable — the GATT link
// dropped, they stopped advertising, they moved out of range.
type PeerLost struct {
	PeerID [8]byte
}

// DataReceived is one inbound wire packet from a peer.
type DataReceived struct {
	PeerID [8]byte
	Data   []byte
}

// AdapterStateChanged reflects the OS's Bluetooth adapter power
// state. Callers surface this to the UI so an operator with BT off
// knows what's wrong.
type AdapterStateChanged struct {
	PoweredOn bool
	Reason    string // optional human-readable
}

func (PeerFound) isBLEEvent()           {}
func (PeerLost) isBLEEvent()            {}
func (DataReceived) isBLEEvent()        {}
func (AdapterStateChanged) isBLEEvent() {}
