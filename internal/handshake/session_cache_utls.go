package handshake

import (
	utls "github.com/metacubex/utls"
)

// utlsSessionCache holds TLS 1.3 resumption tickets of the uTLS client path.
// It is process-wide because a new tls.Config / uTLS config is built for every
// connection, so there is nowhere else a ticket could survive until the next
// dial to the same server.
var utlsSessionCache = utls.NewLRUClientSessionCache(256)

// keyedSessionCache scopes the shared cache to one server address, so a ticket
// issued by one backend is never offered to another that happens to use the
// same SNI. uTLS itself keys by server name only.
type keyedSessionCache struct {
	inner  utls.ClientSessionCache
	suffix string
}

var _ utls.ClientSessionCache = keyedSessionCache{}

func (c keyedSessionCache) Get(key string) (*utls.ClientSessionState, bool) {
	return c.inner.Get(key + "|" + c.suffix)
}

func (c keyedSessionCache) Put(key string, cs *utls.ClientSessionState) {
	c.inner.Put(key+"|"+c.suffix, cs)
}
