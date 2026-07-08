package protocol

// BroadcastRecipient is the all-0xFF 8-byte recipient id for public
// (broadcast) messages. iOS/Android/fork all agree.
var BroadcastRecipient = [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
