package u2ftoken

// A RegisterRequest is a message used for token registration.
type RegisterRequest struct {
	// Challenge is the 32-byte SHA-256 hash of the Client Data JSON prepared by
	// the client.
	Challenge []byte

	// Application is the 32-byte SHA-256 hash of the application identity of
	// the relying party requesting registration.
	Application []byte
}

// An AuthenticateRequires is a message used for authenticating to a relying party
type AuthenticateRequest struct {
	// Challenge is the 32-byte SHA-256 hash of the Client Data JSON prepared by
	// the client.
	Challenge []byte

	// Application is the 32-byte SHA-256 hash of the application identity of
	// the relying party requesting authentication.
	Application []byte

	// KeyHandle is the opaque key handle that was provided to the relying party
	// during registration.
	KeyHandle []byte
}

// An AuthenticateResponse is a message returned in response to a successful
// authentication request.
type AuthenticateResponse struct {
	// Counter is the value of the counter that is incremented by the token
	// every time it performs an authentication operation.
	Counter uint32

	// Signature is the P-256 ECDSA signature over the authentication data.
	Signature []byte

	// RawResponse is the raw response bytes from the U2F token.
	RawResponse []byte
}

// A Request is a low-level request to the token.
type Request struct {
	Command uint8
	Param1  uint8
	Param2  uint8
	Data    []byte
}

// A Response is a low-level response from the token.
type Response struct {
	Data   []byte
	Status uint16
}
