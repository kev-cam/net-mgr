package crypto

import "golang.org/x/crypto/curve25519"

// Wire the x25519Base indirect declared in identity.go to
// curve25519.X25519 with the fixed base point.
func init() {
	x25519Base = func(priv [32]byte) ([32]byte, error) {
		out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
		if err != nil {
			return [32]byte{}, err
		}
		var arr [32]byte
		copy(arr[:], out)
		return arr, nil
	}
}
