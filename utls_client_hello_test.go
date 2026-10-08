package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// parseClientHelloExts returns extension id -> body for a ClientHello
// handshake message (starting at the 4-byte handshake header).
func parseClientHelloExts(t *testing.T, ch []byte) map[uint16][]byte {
	t.Helper()
	b := ch[4:]
	b = b[2+32:]
	b = b[1+int(b[0]):]
	b = b[2+int(binary.BigEndian.Uint16(b)):]
	b = b[1+int(b[0]):]
	l := int(binary.BigEndian.Uint16(b))
	b = b[2 : 2+l]
	out := map[uint16][]byte{}
	for len(b) > 0 {
		id := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		out[id] = b[4 : 4+n]
		b = b[4+n:]
	}
	return out
}

func bindFn(keyShare []byte) []byte {
	h := sha256.Sum256(append([]byte("bind:"), keyShare...))
	return h[:]
}

func TestUTLSNonChromeClientRandomBind(t *testing.T) {
	cert := testCert(t)
	for name, id := range map[string]utls.ClientHelloID{
		"firefox":    utls.HelloFirefox_Auto,
		"safari":     utls.HelloSafari_Auto,
		"ios":        utls.HelloIOS_Auto,
		"edge":       utls.HelloEdge_Auto,
		"chrome_psk": utls.HelloChrome_100_PSK,
	} {
		id := id
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var exts map[uint16][]byte
			var verified bool
			var accumulated []byte
			srvConf := &Config{
				ServerClientRandomVerify: func(random [32]byte, ch []byte) bool {
					mu.Lock()
					defer mu.Unlock()
					accumulated = ch
					e := parseClientHelloExts(t, ch)
					exts = e
					ks := e[0x0033]
					if len(ks) < 2 {
						return false
					}
					want := bindFn(ks[2:])
					verified = string(want) == string(random[:])
					return verified
				},
			}
			ln, err := Listen(mustUDP(t), &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, srvConf)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				c, err := ln.Accept(context.Background())
				if err == nil {
					defer c.CloseWithError(0, "")
					<-c.Context().Done()
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer uc.Close()
			idCopy := id
			conn, err := Dial(ctx, uc, ln.Addr(),
				&tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"h3"}},
				&Config{UTLSClientHelloID: &idCopy, ClientRandomPrefixBind: bindFn})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			conn.CloseWithError(0, "")
			mu.Lock()
			defer mu.Unlock()
			if !verified {
				t.Fatal("server did not verify bound client_random")
			}
			for _, bad := range []uint16{0x0023, 0x0017, 0xff01, 0x000b, 0x0015, 0x0029} {
				if _, ok := exts[bad]; ok {
					t.Errorf("extension 0x%04x present in QUIC ClientHello", bad)
				}
			}
			if _, ok := exts[0x0039]; !ok {
				t.Error("quic_transport_parameters missing")
			}
			if alpn := exts[0x0010]; len(alpn) < 5 || string(alpn[3:]) != "h3" {
				t.Errorf("ALPN = %q", alpn)
			}
			_ = accumulated
		})
	}

	// Negative: wrong binding must be rejected.
	t.Run("mismatch-rejected", func(t *testing.T) {
		srvConf := &Config{ServerClientRandomVerify: func([32]byte, []byte) bool { return false }}
		ln, err := Listen(mustUDP(t), &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, srvConf)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		uc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		defer uc.Close()
		id := utls.HelloFirefox_Auto
		if conn, err := Dial(ctx, uc, ln.Addr(),
			&tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"h3"}},
			&Config{UTLSClientHelloID: &id, ClientRandomPrefixBind: bindFn}); err == nil {
			conn.CloseWithError(0, "")
			t.Fatal("handshake unexpectedly succeeded")
		}
	})
}

func mustUDP(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestUTLSChromeParrotStillBinds(t *testing.T) {
	cert := testCert(t)
	var ok bool
	var mu sync.Mutex
	srvConf := &Config{ServerClientRandomVerify: func(random [32]byte, ch []byte) bool {
		mu.Lock()
		defer mu.Unlock()
		ks := parseClientHelloExts(t, ch)[0x0033]
		ok = len(ks) > 2 && string(bindFn(ks[2:])) == string(random[:])
		return ok
	}}
	ln, err := Listen(mustUDP(t), &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, srvConf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		s, err := c.AcceptStream(context.Background())
		if err != nil {
			return
		}
		buf := make([]byte, 5)
		if _, err := s.Read(buf); err == nil {
			s.Write(buf)
		}
		s.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer uc.Close()
	conn, err := Dial(ctx, uc, ln.Addr(),
		&tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"h3"}},
		&Config{ChromeParrot: true, ClientRandomPrefixBind: bindFn})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo failed: %q %v", buf, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !ok {
		t.Fatal("chrome path: bound random not verified")
	}
}
