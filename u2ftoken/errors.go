package u2ftoken

import "errors"

// ErrPresenceRequired is returned by Register and Authenticate if proof of user
// presence must be provide before the operation can be retried successfully.
var ErrPresenceRequired = errors.New("u2ftoken: user presence required")

// ErrUnknownKeyHandle is returned by Authenticate and CheckAuthenticate if the
// key handle is unknown to the token.
var ErrUnknownKeyHandle = errors.New("u2ftoken: unknown key handle")
