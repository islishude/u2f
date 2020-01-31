// Package u2ftoken implements the FIDO U2F raw message protocol used to
// communicate with U2F tokens.
package u2ftoken

import (
	"encoding/binary"
	"fmt"
)

// Device implements a message transport to a concrete U2F device. It is
// implemented in package u2fhid.
type Device interface {
	// Message sends a message to the device and returns the response.
	Message(data []byte) ([]byte, error)
}

// NewToken returns a token that will use Device to communicate with the device.
func NewToken(d Device) *Token {
	return &Token{d: d}
}

// A Token implements the FIDO U2F hardware token messages as defined in the Raw
// Message Formats specification.
type Token struct {
	d Device
}

// Register registers an application with the token and returns the raw
// registration response message to be passed to the relying party. It returns
// ErrPresenceRequired if the call should be retried after proof of user
// presence is provided to the token.
func (t *Token) Register(req RegisterRequest) ([]byte, error) {
	if len(req.Challenge) != 32 {
		return nil, fmt.Errorf("u2ftoken: Challenge must be exactly 32 bytes")
	}
	if len(req.Application) != 32 {
		return nil, fmt.Errorf("u2ftoken: Application must be exactly 32 bytes")
	}

	res, err := t.Message(Request{
		Param1: authEnforce, Command: CmdRegister,
		Data: append(req.Challenge, req.Application...),
	})
	if err != nil {
		return nil, err
	}

	switch res.Status {
	case StatusNoError:
		return res.Data, nil
	case StatusConditionsNotSatisfied:
		return nil, ErrPresenceRequired
	default:
		return nil, fmt.Errorf("u2ftoken: unexpected error %d during registration", res.Status)
	}
}

func encodeAuthenticateRequest(req AuthenticateRequest) ([]byte, error) {
	if len(req.Challenge) != 32 {
		return nil, fmt.Errorf("u2ftoken: Challenge must be exactly 32 bytes")
	}
	if len(req.Application) != 32 {
		return nil, fmt.Errorf("u2ftoken: Application must be exactly 32 bytes")
	}
	if len(req.KeyHandle) > 256 {
		return nil, fmt.Errorf("u2ftoken: KeyHandle is too long")
	}

	buf := make([]byte, 0, len(req.Challenge)+len(req.Application)+1+len(req.KeyHandle))
	buf = append(buf, req.Challenge...)
	buf = append(buf, req.Application...)
	buf = append(buf, byte(len(req.KeyHandle)))
	buf = append(buf, req.KeyHandle...)

	return buf, nil
}

// Authenticate peforms an authentication operation and returns the response to
// provide to the relying party. It returns ErrPresenceRequired if the call
// should be retried after proof of user presence is provided to the token and
// ErrUnknownKeyHandle if the key handle is unknown to the token.
func (t *Token) Authenticate(req AuthenticateRequest) (*AuthenticateResponse, error) {
	buf, err := encodeAuthenticateRequest(req)
	if err != nil {
		return nil, err
	}

	res, err := t.Message(Request{Command: CmdAuthenticate, Param1: authEnforce, Data: buf})
	if err != nil {
		return nil, err
	}

	if res.Status != StatusNoError {
		if res.Status == StatusConditionsNotSatisfied {
			return nil, ErrPresenceRequired
		}
		return nil, fmt.Errorf("u2ftoken: unexpected error %d during authentication", res.Status)
	}

	if len(res.Data) < 6 {
		return nil, fmt.Errorf("u2ftoken: authenticate response is too short, got %d bytes", len(res.Data))
	}

	return &AuthenticateResponse{
		Counter:     binary.BigEndian.Uint32(res.Data[1:]),
		Signature:   res.Data[5:],
		RawResponse: res.Data,
	}, nil
}

// CheckAuthenticate checks if a key handle is known to the token without
// requiring a test for user presence. It returns ErrUnknownKeyHandle if the key
// handle is unknown to the token.
func (t *Token) CheckAuthenticate(req AuthenticateRequest) error {
	buf, err := encodeAuthenticateRequest(req)
	if err != nil {
		return err
	}

	res, err := t.Message(Request{Command: CmdAuthenticate, Param1: authCheckOnly, Data: buf})
	if err != nil {
		return err
	}

	switch res.Status {
	case StatusConditionsNotSatisfied:
		return nil
	case StatusWrongData:
		return ErrUnknownKeyHandle
	default:
		return fmt.Errorf("u2ftoken: unexpected error %d during auth check", res.Status)
	}
}

// Version returns the U2F protocol version implemented by the token.
func (t *Token) Version() (string, error) {
	res, err := t.Message(Request{Command: CmdVersion})
	if err != nil {
		return "", err
	}

	if res.Status != StatusNoError {
		return "", fmt.Errorf("u2ftoken: unexpected error %d during version request", res.Status)
	}

	return string(res.Data), nil
}

// Message sends a low-level request to the token and returns the response.
func (t *Token) Message(req Request) (*Response, error) {
	buf := make([]byte, 7, 7+len(req.Data))
	buf[1] = req.Command
	buf[2] = req.Param1
	buf[3] = req.Param2
	buf[4] = uint8(len(req.Data) >> 16)
	buf[5] = uint8(len(req.Data) >> 8)
	buf[6] = uint8(len(req.Data))
	buf = append(buf, req.Data...)

	data, err := t.d.Message(buf)
	if err != nil {
		return nil, err
	}
	if len(data) < 2 {
		return nil, fmt.Errorf("u2ftoken: response is too short, got %d bytes", len(data))
	}
	return &Response{
		Data:   data[:len(data)-2],
		Status: binary.BigEndian.Uint16(data[len(data)-2:]),
	}, nil
}
