package protocol

// Padding blocks that iOS + Android + the Rust fork all agree on. Any
// change here breaks Announce signature verification against mainline
// clients — the signed bytes MUST reproduce byte-for-byte.
var padBlocks = [...]int{256, 512, 1024, 2048}

// OptimalBlockSize picks the smallest block from padBlocks that fits
// data. For over-2K messages we skip padding (return the original
// size), matching Rust MessagePadding::optimal_block_size.
func OptimalBlockSize(dataSize int) int {
	for _, b := range padBlocks {
		if dataSize <= b {
			return b
		}
	}
	return dataSize
}

// Pad appends PKCS#7 padding up to targetSize. If the padding would
// need to be more than 255 bytes (PKCS#7's byte-count limit) or the
// data is already at/over targetSize, returns data unchanged (matches
// padding.rs including the "return original" fallback comment).
func Pad(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		out := make([]byte, len(data))
		copy(out, data)
		return out
	}
	need := targetSize - len(data)
	if need > 255 {
		out := make([]byte, len(data))
		copy(out, data)
		return out
	}
	out := make([]byte, targetSize)
	copy(out, data)
	for i := len(data); i < targetSize; i++ {
		out[i] = byte(need)
	}
	return out
}

// Unpad reverses PKCS#7 padding. Invalid padding (zero or > len) is
// tolerated by returning data unchanged, matching padding.rs.
func Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	n := int(data[len(data)-1])
	if n == 0 || n > len(data) {
		return data
	}
	return data[:len(data)-n]
}
