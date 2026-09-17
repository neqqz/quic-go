package handshake

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/quic-go/quicvarint"
)

// utlsQUICConn adapts uTLS's UQUICConn to the tlsQUICConn interface, translating
// its QUIC event and connection-state types back into the crypto/tls
// equivalents. uTLS is a fork of crypto/tls, so the translation is mechanical.
type utlsQUICConn struct {
	conn *utls.UQUICConn
	// spec is retained because the transport parameters have to be written into
	// the ClientHello extension rather than handed to uTLS directly; see
	// SetTransportParameters.
	spec *utls.ClientHelloSpec
}

var _ tlsQUICConn = (*utlsQUICConn)(nil)

// newUTLSQUICClient creates a QUIC-TLS client emitting the parroted ClientHello.
//
// Session resumption and 0-RTT are disabled: crypto/tls and uTLS each have their
// own SessionState with unexported internals, so a uTLS session cannot be
// converted into the *tls.SessionState the resumption path expects. The events
// are turned off at the source rather than half-supported.
//
// clientRandomPrefixBind, when non-nil, is called right after ApplyPreset with
// this handshake's own key_share bytes (wire format) and its return value
// overwrites the full 32-byte ClientHello.random in place. This has to happen
// here rather than via the ClientRandomPrefix/Rand-wrapping mechanism because
// that mechanism fires on the first Rand read — before ApplyPreset has
// generated key_share — so it has nothing to bind to yet. ApplyPreset itself
// only populates uconn.HandshakeState.Hello (Random, KeyShares, ...); it does
// not marshal ClientHello.Raw or mark the client-hello build as complete, so
// patching Random here is a normal field write, not something the internal
// handshake machinery has already moved past — the real marshal happens
// later, when Start below actually kicks off the handshake, and reads
// whatever is in Hello.Random at that point (ApplyPreset special-cases an
// already-32-byte Random as "keep it" rather than regenerating it, which is
// what makes patching it here stick — see its "case 32" branch).
func newUTLSQUICClient(tlsConf *tls.Config, clientRandomPrefixBind func(keyShare []byte) []byte) (*utlsQUICConn, error) {
	uConf, err := utlsConfigFromStd(tlsConf)
	if err != nil {
		return nil, err
	}
	spec := chromeQUICClientHelloSpec(tlsConf.NextProtos)

	conn := utls.UQUICClient(&utls.QUICConfig{TLSConfig: uConf}, utls.HelloCustom)
	if err := conn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("applying Chrome ClientHello spec: %w", err)
	}
	if clientRandomPrefixBind != nil {
		if err := patchClientRandomFromKeyShare(conn, spec, clientRandomPrefixBind); err != nil {
			return nil, err
		}
	}
	return &utlsQUICConn{conn: conn, spec: spec}, nil
}

// patchClientRandomFromKeyShare overwrites conn's ClientHello.random with
// bind(key_share), where key_share is this handshake's own key_share
// extension body in wire format — the same format
// common/tls/utls_client.go's serializeKeyShares produces for the TCP path,
// reimplemented here rather than imported to avoid pulling sing-box's
// common/tls package into this quic-go fork. If either side's format ever
// drifts, DeriveRotatingRandomPrefixBound on the two ends stops agreeing and
// every handshake using rotation fails closed (see ServerClientRandomVerify)
// rather than silently accepting an unbound value — this is deliberately not
// a fallback-to-unbound path.
//
// Reads the generated key share from spec's own *utls.KeyShareExtension,
// NOT from conn.HandshakeState().Hello.KeyShares — the latter is only
// synced from the extension by (*UConn).ApplyConfig(), which ApplyPreset
// does not call; ApplyConfig only runs later, as part of the real
// handshake's buildHandshakeState(), by which point it's too late to affect
// what we bind Random to. spec.Extensions, on the other hand, holds the
// exact same *KeyShareExtension object ApplyPreset generated real key
// material into in place (uconn.Extensions is a shallow copy of
// spec.Extensions — same pointers, confirmed by reading ApplyPreset's own
// source), so it already has the real Data at this point, no separate sync
// step needed.
func patchClientRandomFromKeyShare(conn *utls.UQUICConn, spec *utls.ClientHelloSpec, bind func(keyShare []byte) []byte) error {
	hello := conn.HandshakeState().Hello
	if hello == nil || len(hello.Random) != 32 {
		return errors.New("quic: ClientRandomPrefixBind: ClientHello not built (no Random) after ApplyPreset")
	}
	var keyShareExt *utls.KeyShareExtension
	for _, ext := range spec.Extensions {
		if ks, ok := ext.(*utls.KeyShareExtension); ok {
			keyShareExt = ks
			break
		}
	}
	if keyShareExt == nil {
		return errors.New("quic: ClientRandomPrefixBind: spec has no KeyShareExtension")
	}
	// TEMP DIAGNOSTIC LOGGING — remove once confirmed working end to end.
	// Compare the "keyShare=" line here against the server's "extracted
	// key_share=" line for the SAME connection attempt: they must be
	// byte-for-byte identical, or DeriveRotatingRandomPrefixBound on the
	// two ends won't agree and the handshake fails closed.
	for i, ks := range keyShareExt.KeyShares {
		fmt.Fprintf(os.Stderr, "[randbind][client] KeyShares[%d]: group=0x%04x data_len=%d data=%s\n",
			i, uint16(ks.Group), len(ks.Data), hex.EncodeToString(ks.Data))
	}
	keyShare := serializeKeyShares(keyShareExt.KeyShares)
	fmt.Fprintf(os.Stderr, "[randbind][client] serialized keyShare (%d bytes)=%s\n", len(keyShare), hex.EncodeToString(keyShare))
	prefix := bind(keyShare)
	if len(prefix) == 0 {
		return errors.New("quic: ClientRandomPrefixBind returned no bytes")
	}
	if len(prefix) > 32 {
		prefix = prefix[:32]
	}
	fmt.Fprintf(os.Stderr, "[randbind][client] computed prefix=%s (patching into Random, was=%s)\n",
		hex.EncodeToString(prefix), hex.EncodeToString(hello.Random[:len(prefix)]))
	copy(hello.Random, prefix)
	fmt.Fprintf(os.Stderr, "[randbind][client] Random after patch=%s\n", hex.EncodeToString(hello.Random))
	return nil
}

// serializeKeyShares must byte-for-byte match its counterpart in sing-box's
// common/tls/utls_client.go: the concatenated group(2)+length(2)+
// key_exchange(length) entries of the key_share extension, with the leading
// 2-byte client_shares list-length field stripped.
func serializeKeyShares(shares []utls.KeyShare) []byte {
	var buf []byte
	for _, share := range shares {
		var lenBytes [2]byte
		binary.BigEndian.PutUint16(lenBytes[:], uint16(len(share.Data)))
		var groupBytes [2]byte
		binary.BigEndian.PutUint16(groupBytes[:], uint16(share.Group))
		buf = append(buf, groupBytes[:]...)
		buf = append(buf, lenBytes[:]...)
		buf = append(buf, share.Data...)
	}
	return buf
}

// utlsConfigFromStd converts a crypto/tls client config into the uTLS
// equivalent.
//
// uTLS ships no converter, so this copies field by field. Any field that cannot
// be carried across is a hard error rather than a silent omission: dropping
// something like VerifyConnection would quietly weaken certificate validation.
//
// VerifyConnection is supported via a thin adapter that converts
// utls.ConnectionState → tls.ConnectionState (same layout for the fields we
// care about). This is required for sing-box cert_domain and similar callers
// that install a custom verifier when ChromeParrot is enabled.
func utlsConfigFromStd(c *tls.Config) (*utls.Config, error) {
	if c == nil {
		return &utls.Config{MinVersion: utls.VersionTLS13}, nil
	}
	if c.GetConfigForClient != nil || len(c.Certificates) > 0 || c.GetCertificate != nil {
		return nil, errors.New("quic: server-side tls.Config fields are not supported with ChromeParrot")
	}

	uc := &utls.Config{
		Rand:                  c.Rand,
		Time:                  c.Time,
		RootCAs:               c.RootCAs,
		NextProtos:            c.NextProtos,
		ServerName:            c.ServerName,
		InsecureSkipVerify:    c.InsecureSkipVerify,
		VerifyPeerCertificate: c.VerifyPeerCertificate,
		KeyLogWriter:          c.KeyLogWriter,
		// TLS 1.3 only, which QUIC requires regardless.
		MinVersion: utls.VersionTLS13,
		MaxVersion: utls.VersionTLS13,
		// Resumption is off; see newUTLSQUICClient.
		SessionTicketsDisabled: true,
	}

	if c.VerifyConnection != nil {
		verify := c.VerifyConnection
		uc.VerifyConnection = func(cs utls.ConnectionState) error {
			return verify(tls.ConnectionState{
				Version:                     cs.Version,
				HandshakeComplete:           cs.HandshakeComplete,
				DidResume:                   cs.DidResume,
				CipherSuite:                 cs.CipherSuite,
				NegotiatedProtocol:          cs.NegotiatedProtocol,
				NegotiatedProtocolIsMutual:  true,
				ServerName:                  cs.ServerName,
				PeerCertificates:            cs.PeerCertificates,
				VerifiedChains:              cs.VerifiedChains,
				SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
				OCSPResponse:                cs.OCSPResponse,
			})
		}
	}

	if c.GetClientCertificate != nil {
		get := c.GetClientCertificate
		uc.GetClientCertificate = func(cri *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			cert, err := get(&tls.CertificateRequestInfo{
				AcceptableCAs:    cri.AcceptableCAs,
				SignatureSchemes: signatureSchemesToStd(cri.SignatureSchemes),
				Version:          cri.Version,
			})
			if err != nil {
				return nil, err
			}
			if cert == nil {
				return &utls.Certificate{}, nil
			}
			return &utls.Certificate{
				Certificate:                 cert.Certificate,
				PrivateKey:                  cert.PrivateKey,
				OCSPStaple:                  cert.OCSPStaple,
				SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
				Leaf:                        cert.Leaf,
			}, nil
		}
	}

	// GREASE ECH is covered by the ClientHello spec; a caller-supplied config list
	// takes precedence.
	if len(c.EncryptedClientHelloConfigList) > 0 {
		uc.EncryptedClientHelloConfigList = c.EncryptedClientHelloConfigList
	}
	return uc, nil
}

func signatureSchemesToStd(in []utls.SignatureScheme) []tls.SignatureScheme {
	out := make([]tls.SignatureScheme, len(in))
	for i, s := range in {
		out[i] = tls.SignatureScheme(s)
	}
	return out
}

func (c *utlsQUICConn) Start(ctx context.Context) error { return c.conn.Start(ctx) }
func (c *utlsQUICConn) Close() error                    { return c.conn.Close() }

func (c *utlsQUICConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	return c.conn.HandleData(utlsEncryptionLevel(level), data)
}

// SetTransportParameters installs quic-go's marshalled transport parameters into
// the ClientHello.
//
// uTLS's own SetTransportParameters does not reach the ClientHello when a preset
// is in use, so the bytes must be written into the spec's
// quic_transport_parameters extension. uTLS models that extension as (id, value)
// pairs and marshals it itself, so the blob is split back into pairs here.
// Splitting rather than re-deriving preserves our per-connection ordering.
func (c *utlsQUICConn) SetTransportParameters(params []byte) {
	// Still call through so uTLS's internal copy stays consistent.
	c.conn.SetTransportParameters(params)

	tps, err := splitTransportParameters(params)
	if err != nil {
		// Our own marshaller produced these, so this is unreachable short of a bug.
		panic(fmt.Sprintf("handshake BUG: cannot split marshalled transport parameters: %s", err))
	}
	for _, ext := range c.spec.Extensions {
		if qtp, ok := ext.(*utls.QUICTransportParametersExtension); ok {
			qtp.TransportParameters = tps
			return
		}
	}
	panic("handshake BUG: Chrome ClientHello spec has no quic_transport_parameters extension")
}

// splitTransportParameters parses a marshalled transport parameter blob back into
// individual (id, value) pairs, preserving order.
func splitTransportParameters(b []byte) (utls.TransportParameters, error) {
	var tps utls.TransportParameters
	for len(b) > 0 {
		id, n, err := quicvarint.Parse(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		l, n, err := quicvarint.Parse(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if uint64(len(b)) < l {
			return nil, fmt.Errorf("transport parameter 0x%x truncated: want %d bytes, have %d", id, l, len(b))
		}
		val := make([]byte, l)
		copy(val, b[:l])
		b = b[l:]
		tps = append(tps, &utls.FakeQUICTransportParameter{Id: id, Val: val})
	}
	return tps, nil
}

func (c *utlsQUICConn) NextEvent() tls.QUICEvent {
	ev := c.conn.NextEvent()
	out := tls.QUICEvent{
		Level: stdEncryptionLevel(ev.Level),
		Data:  ev.Data,
		Suite: ev.Suite,
	}
	switch ev.Kind {
	case utls.QUICNoEvent:
		out.Kind = tls.QUICNoEvent
	case utls.QUICSetReadSecret:
		out.Kind = tls.QUICSetReadSecret
	case utls.QUICSetWriteSecret:
		out.Kind = tls.QUICSetWriteSecret
	case utls.QUICWriteData:
		out.Kind = tls.QUICWriteData
	case utls.QUICTransportParameters:
		out.Kind = tls.QUICTransportParameters
	case utls.QUICTransportParametersRequired:
		out.Kind = tls.QUICTransportParametersRequired
	case utls.QUICRejectedEarlyData:
		out.Kind = tls.QUICRejectedEarlyData
	case utls.QUICHandshakeDone:
		out.Kind = tls.QUICHandshakeDone
	default:
		// QUICStoreSession and QUICResumeSession carry a *utls.SessionState that
		// cannot be converted. They only fire when EnableSessionEvents is set,
		// which newUTLSQUICClient never does, so reaching this is a bug.
		panic(fmt.Sprintf("handshake BUG: unexpected uTLS QUIC event kind %d", ev.Kind))
	}
	return out
}

func (c *utlsQUICConn) SendSessionTicket(tls.QUICSessionTicketOptions) error {
	return errors.New("quic: SendSessionTicket is server-only and unsupported with ChromeParrot")
}

func (c *utlsQUICConn) StoreSession(*tls.SessionState) error {
	return errors.New("quic: session resumption is unsupported with ChromeParrot")
}

func (c *utlsQUICConn) ConnectionState() tls.ConnectionState {
	s := c.conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  true,
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
	}
}

func utlsEncryptionLevel(l tls.QUICEncryptionLevel) utls.QUICEncryptionLevel {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return utls.QUICEncryptionLevelInitial
	case tls.QUICEncryptionLevelEarly:
		return utls.QUICEncryptionLevelEarly
	case tls.QUICEncryptionLevelHandshake:
		return utls.QUICEncryptionLevelHandshake
	case tls.QUICEncryptionLevelApplication:
		return utls.QUICEncryptionLevelApplication
	default:
		panic(fmt.Sprintf("handshake BUG: unknown encryption level %d", l))
	}
}

func stdEncryptionLevel(l utls.QUICEncryptionLevel) tls.QUICEncryptionLevel {
	switch l {
	case utls.QUICEncryptionLevelInitial:
		return tls.QUICEncryptionLevelInitial
	case utls.QUICEncryptionLevelEarly:
		return tls.QUICEncryptionLevelEarly
	case utls.QUICEncryptionLevelHandshake:
		return tls.QUICEncryptionLevelHandshake
	case utls.QUICEncryptionLevelApplication:
		return tls.QUICEncryptionLevelApplication
	default:
		panic(fmt.Sprintf("handshake BUG: unknown uTLS encryption level %d", l))
	}
}
