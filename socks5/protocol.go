package socks5

// Protocol Version
const (
	Version = 0x05
)

// Authentication Methods
const (
	MethodNoAuth       = 0x00
	MethodGSSAPI       = 0x01
	MethodUserPass     = 0x02
	MethodNoAcceptable = 0xFF
)

// Commands
const (
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03
)

// Address Types
const (
	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04
)

// Replies
const (
	ReplySucceeded               = 0x00
	ReplyGeneralFailure          = 0x01
	ReplyConnectionNotAllowed    = 0x02
	ReplyNetworkUnreachable      = 0x03
	ReplyHostUnreachable         = 0x04
	ReplyConnectionRefused       = 0x05
	ReplyTTLExpired              = 0x06
	ReplyCommandNotSupported     = 0x07
	ReplyAddressTypeNotSupported = 0x08
)

// User/Password Auth Protocol Version
const (
	UserPassAuthVersion = 0x01
	AuthSuccess         = 0x00
	AuthFailure         = 0x01
)

// Auth represents SOCKS5 username/password authentication credentials
type Auth struct {
	User     string
	Password string
}
