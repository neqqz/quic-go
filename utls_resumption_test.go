package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

// clientHelloExtOrder returns the extension ids of a ClientHello handshake
// message in wire order.
func clientHelloExtOrder(t *testing.T, ch []byte) []uint16 {
	t.Helper()
	b := ch[4:]
	b = b[2+32:]
	b = b[1+int(b[0]):]
	b = b[2+int(binary.BigEndian.Uint16(b)):]
	b = b[1+int(b[0]):]
	l := int(binary.BigEndian.Uint16(b))
	b = b[2 : 2+l]
	var ids []uint16
	for len(b) > 0 {
		ids = append(ids, binary.BigEndian.Uint16(b))
		n := int(binary.BigEndian.Uint16(b[2:]))
		b = b[4+n:]
	}
	return ids
}

// TestUTLSSessionResumption: on the uTLS paths (Chrome parrot and a generic
// browser fingerprint) the first connection to a server carries no
// pre_shared_key, the second one carries it as the last extension and actually
// resumes, 0-RTT is never used, and SessionTicketsDisabled turns it all off.
func TestUTLSSessionResumption(t *testing.T) {
	cert := testCert(t)
	type mode struct {
		name string
		conf func() *Config
	}
	modes := []mode{
		{"chrome", func() *Config { return &Config{ChromeParrot: true, ClientRandomPrefixBind: bindFn} }},
		{"firefox", func() *Config {
			id := utls.HelloFirefox_Auto
			return &Config{UTLSClientHelloID: &id, ClientRandomPrefixBind: bindFn}
		}},
		{"chrome_psk_preset", func() *Config {
			id := utls.HelloChrome_100_PSK
			return &Config{UTLSClientHelloID: &id, ClientRandomPrefixBind: bindFn}
		}},
	}
	for _, m := range modes {
		for _, ticketsOff := range []bool{false, true} {
			m, ticketsOff := m, ticketsOff
			name := m.name
			if ticketsOff {
				name += "_tickets_disabled"
			}
			t.Run(name, func(t *testing.T) {
				var mu sync.Mutex
				var hellos [][]uint16
				srvConf := &Config{
					Allow0RTT: true,
					ServerClientRandomVerify: func(random [32]byte, ch []byte) bool {
						mu.Lock()
						defer mu.Unlock()
						hellos = append(hellos, clientHelloExtOrder(t, ch))
						ks := parseClientHelloExts(t, ch)[0x0033]
						return len(ks) > 2 && string(bindFn(ks[2:])) == string(random[:])
					},
				}
				ln, err := ListenEarly(mustUDP(t), &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, srvConf)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				go func() {
					for {
						c, err := ln.Accept(context.Background())
						if err != nil {
							return
						}
						go func() {
							for {
								s, err := c.AcceptStream(context.Background())
								if err != nil {
									return
								}
								go func() { io.Copy(s, s); s.Close() }()
							}
						}()
					}
				}()

				uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer uc.Close()

				dial := func() (*Conn, tls.ConnectionState) {
					t.Helper()
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					conn, err := DialEarly(ctx, uc, ln.Addr(),
						&tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"h3"}, SessionTicketsDisabled: ticketsOff},
						m.conf())
					if err != nil {
						t.Fatalf("dial: %v", err)
					}
					s, err := conn.OpenStreamSync(ctx)
					if err != nil {
						t.Fatal(err)
					}
					s.Write([]byte("hello"))
					buf := make([]byte, 5)
					if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "hello" {
						t.Fatalf("echo failed: %q %v", buf, err)
					}
					st := conn.ConnectionState()
					return conn, st.TLS
				}

				c1, st1 := dial()
				if st1.DidResume {
					t.Fatal("first connection claims to have resumed")
				}
				// The session ticket arrives after the handshake.
				time.Sleep(300 * time.Millisecond)
				c1.CloseWithError(0, "")

				c2, st2 := dial()
				defer c2.CloseWithError(0, "")
				if c2.ConnectionState().Used0RTT {
					t.Fatal("0-RTT must never be used on the uTLS path")
				}

				mu.Lock()
				defer mu.Unlock()
				if len(hellos) != 2 {
					t.Fatalf("server saw %d ClientHellos, want 2", len(hellos))
				}
				hasPSK := func(ids []uint16) bool {
					for _, id := range ids {
						if id == 0x0029 {
							return true
						}
					}
					return false
				}
				if hasPSK(hellos[0]) {
					t.Fatal("first ClientHello must not carry pre_shared_key")
				}
				if ticketsOff {
					if hasPSK(hellos[1]) || st2.DidResume {
						t.Fatalf("tickets disabled, but second hello psk=%v resumed=%v", hasPSK(hellos[1]), st2.DidResume)
					}
					return
				}
				last := hellos[1][len(hellos[1])-1]
				if last != 0x0029 {
					t.Fatalf("second ClientHello: pre_shared_key must be the last extension, order=%x", hellos[1])
				}
				if !st2.DidResume {
					t.Fatal("second connection did not resume the session")
				}
			})
		}
	}
}
