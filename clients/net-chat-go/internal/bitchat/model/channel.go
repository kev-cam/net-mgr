package model

// Channel is a named chat room. When a password is set, iOS/Android
// derive a symmetric key from it and encrypt channel messages
// end-to-end.
type Channel struct {
	Name        string
	Password    string // "" ⇒ not password-protected
	IsEncrypted bool
	UnreadCount int
}

// NewChannel builds a plain channel with no password.
func NewChannel(name string) *Channel { return &Channel{Name: name} }

// NewEncryptedChannel builds a channel with a password + IsEncrypted set.
func NewEncryptedChannel(name, password string) *Channel {
	return &Channel{Name: name, Password: password, IsEncrypted: true}
}
