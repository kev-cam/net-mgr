package protocol

import (
	"bytes"
	"compress/flate"
	"io"
)

// compressionThreshold matches Rust CompressionUtil::COMPRESSION_THRESHOLD.
const compressionThreshold = 100

// ShouldCompress is currently a hard "no" — matches the Rust code's
// TODO comment about iOS compression compatibility. Left as a hook
// so we can flip it on when the mainline clients agree.
func ShouldCompress(_ []byte) bool { return false }

// Compress runs deflate over data. Returns (nil, nil) when the input
// is under the threshold or the compressed form isn't smaller —
// mirrors the Rust CompressionUtil::compress return contract.
func Compress(data []byte) ([]byte, error) {
	if len(data) < compressionThreshold {
		return nil, nil
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if buf.Len() == 0 || buf.Len() >= len(data) {
		return nil, nil
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

// Decompress reverses Compress. originalSize hints the output length
// so the buffer doesn't grow repeatedly.
func Decompress(compressed []byte, originalSize int) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	out := bytes.NewBuffer(make([]byte, 0, originalSize))
	if _, err := io.Copy(out, r); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
