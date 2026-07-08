// Package protocol — Go port of bitchat-rust's src/protocol/*.rs.
//
// Wire-compatible with mainline permissionlesstech/bitchat (iOS + Android)
// and the bigsony fork. Kept pure — no BLE, no allocation beyond what the
// packet itself needs, no external deps beyond golang.org/x/crypto for the
// crypto layer above.
package protocol

import "fmt"

// MessageType is the 1-byte type tag in a packet header. Numeric values
// are mainline-compatible — see message_type.rs comment on 0x02 vs 0x04.
type MessageType uint8

const (
	MTAnnounce                 MessageType = 0x01
	MTMessage                  MessageType = 0x02
	MTLeave                    MessageType = 0x03
	MTFragmentStart            MessageType = 0x05
	MTFragmentContinue         MessageType = 0x06
	MTFragmentEnd              MessageType = 0x07
	MTChannelAnnounce          MessageType = 0x08
	MTChannelRetention         MessageType = 0x09
	MTDeliveryAck              MessageType = 0x0A
	MTDeliveryStatusRequest    MessageType = 0x0B
	MTReadReceipt              MessageType = 0x0C
	MTNoiseHandshakeInit       MessageType = 0x10
	MTNoiseHandshakeResp       MessageType = 0x11
	MTNoiseEncrypted           MessageType = 0x12
	MTNoiseIdentityAnnounce    MessageType = 0x13
	MTChannelKeyVerifyRequest  MessageType = 0x14
	MTChannelKeyVerifyResponse MessageType = 0x15
	MTChannelPasswordUpdate    MessageType = 0x16
	MTChannelMetadata          MessageType = 0x17
	MTNoiseHandshakeFinal      MessageType = 0x18
	MTVersionHello             MessageType = 0x20
	MTVersionAck               MessageType = 0x21
	MTProtocolAck              MessageType = 0x22
	MTProtocolNack             MessageType = 0x23
	MTSystemValidation         MessageType = 0x24
	MTHandshakeRequest         MessageType = 0x25
	MTFavorited                MessageType = 0x30
	MTUnfavorited              MessageType = 0x31
)

// MessageTypeFromByte parses a wire byte. Legacy 0x04 aliases to
// MTMessage — mirrors message_type.rs's rolling-upgrade tolerance.
func MessageTypeFromByte(b byte) (MessageType, error) {
	switch b {
	case 0x01:
		return MTAnnounce, nil
	case 0x02, 0x04:
		return MTMessage, nil
	case 0x03:
		return MTLeave, nil
	case 0x05:
		return MTFragmentStart, nil
	case 0x06:
		return MTFragmentContinue, nil
	case 0x07:
		return MTFragmentEnd, nil
	case 0x08:
		return MTChannelAnnounce, nil
	case 0x09:
		return MTChannelRetention, nil
	case 0x0A:
		return MTDeliveryAck, nil
	case 0x0B:
		return MTDeliveryStatusRequest, nil
	case 0x0C:
		return MTReadReceipt, nil
	case 0x10:
		return MTNoiseHandshakeInit, nil
	case 0x11:
		return MTNoiseHandshakeResp, nil
	case 0x12:
		return MTNoiseEncrypted, nil
	case 0x13:
		return MTNoiseIdentityAnnounce, nil
	case 0x14:
		return MTChannelKeyVerifyRequest, nil
	case 0x15:
		return MTChannelKeyVerifyResponse, nil
	case 0x16:
		return MTChannelPasswordUpdate, nil
	case 0x17:
		return MTChannelMetadata, nil
	case 0x18:
		return MTNoiseHandshakeFinal, nil
	case 0x20:
		return MTVersionHello, nil
	case 0x21:
		return MTVersionAck, nil
	case 0x22:
		return MTProtocolAck, nil
	case 0x23:
		return MTProtocolNack, nil
	case 0x24:
		return MTSystemValidation, nil
	case 0x25:
		return MTHandshakeRequest, nil
	case 0x30:
		return MTFavorited, nil
	case 0x31:
		return MTUnfavorited, nil
	}
	return 0, fmt.Errorf("unknown message type 0x%02x", b)
}
