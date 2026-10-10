package handshake

import (
	"errors"
	"fmt"

	utls "github.com/metacubex/utls"
)

// genericQUICClientHelloSpec derives a QUIC-suitable ClientHello from one of
// uTLS's TCP fingerprints (Firefox, Safari, iOS, Edge, ...).
//
// Unlike chromeQUICClientHelloSpec this is NOT a faithful copy of what that
// browser sends over QUIC: it is the browser's own TLS-over-TCP hello with the
// parts that cannot (or never do) appear in a QUIC handshake removed. The
// result keeps the browser's cipher/curve/signature-algorithm/extension
// profile, which is far closer to it than Go's crypto/tls hello is, and — the
// reason this exists — exposes the generated key_share before the hello is
// sent, so the client_random can be bound to it (see
// patchClientRandomFromKeyShare). Transport parameters stay quic-go's.
//
// What is changed relative to the TCP spec:
//   - TLS 1.3 only: cipher suites other than TLS_AES_*/CHACHA20 are dropped
//     (GREASE placeholders are kept), supported_versions is reduced to TLS 1.3
//     (plus GREASE).
//   - Extensions that are TLS<=1.2 / TCP only or stateful are dropped:
//     session_ticket, extended_master_secret, renegotiation_info,
//     ec_point_formats, padding, status_request_v2, NPN, channel_id,
//     token_binding, cookie and any pre_shared_key from the TCP spec. A fresh
//     pre_shared_key placeholder is appended as the last extension, which uTLS
//     fills in when a cached session exists and omits otherwise.
//   - ALPN (and ALPS, if present) are taken from the caller's tls.Config.
//   - A quic_transport_parameters extension is appended if the spec has none;
//     its contents are filled in later from quic-go's own parameters.
func genericQUICClientHelloSpec(id utls.ClientHelloID, alpn []string) (*utls.ClientHelloSpec, error) {
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, fmt.Errorf("quic: uTLS fingerprint %s has no ClientHello spec: %w", id.Str(), err)
	}

	var suites []uint16
	for _, s := range spec.CipherSuites {
		switch s {
		case utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256, utls.GREASE_PLACEHOLDER:
			suites = append(suites, s)
		}
	}
	if len(suites) == 0 {
		suites = []uint16{utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256}
	}
	spec.CipherSuites = suites
	spec.TLSVersMin = utls.VersionTLS13
	spec.TLSVersMax = utls.VersionTLS13

	var (
		exts   []utls.TLSExtension
		hasKS  bool
		hasQTP bool
	)
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SessionTicketExtension,
			*utls.ExtendedMasterSecretExtension,
			*utls.RenegotiationInfoExtension,
			*utls.SupportedPointsExtension,
			*utls.UtlsPaddingExtension,
			*utls.StatusRequestV2Extension,
			*utls.NPNExtension,
			*utls.FakeChannelIDExtension,
			*utls.FakeTokenBindingExtension,
			*utls.CookieExtension,
			*utls.UtlsPreSharedKeyExtension,
			*utls.FakePreSharedKeyExtension:
			continue
		case *utls.ALPNExtension:
			e.AlpnProtocols = alpn
		case *utls.ApplicationSettingsExtension:
			e.SupportedProtocols = alpn
		case *utls.ApplicationSettingsExtensionNew:
			e.SupportedProtocols = alpn
		case *utls.SupportedVersionsExtension:
			var vs []uint16
			for _, v := range e.Versions {
				if v == utls.VersionTLS13 || v == utls.GREASE_PLACEHOLDER {
					vs = append(vs, v)
				}
			}
			if len(vs) == 0 {
				vs = []uint16{utls.VersionTLS13}
			}
			e.Versions = vs
		case *utls.KeyShareExtension:
			hasKS = true
		case *utls.QUICTransportParametersExtension:
			hasQTP = true
		}
		exts = append(exts, ext)
	}
	if !hasKS {
		return nil, errors.New("quic: uTLS fingerprint has no key_share extension")
	}
	if !hasQTP {
		exts = append(exts, &utls.QUICTransportParametersExtension{})
	}
	// A PSK offer needs psk_key_exchange_modes next to it; only browsers'
	// TLS 1.3 hellos carry that, so skip the placeholder if the spec lacks it.
	for _, ext := range exts {
		if _, ok := ext.(*utls.PSKKeyExchangeModesExtension); ok {
			exts = append(exts, &utls.UtlsPreSharedKeyExtension{})
			break
		}
	}
	spec.Extensions = exts
	return &spec, nil
}
