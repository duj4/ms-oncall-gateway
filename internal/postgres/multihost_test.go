package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pgWireTestServer struct {
	listener net.Listener
	tlsCert  tlsCertificate
	readOnly bool
	accepts  atomic.Int64
	closed   chan struct{}
	wait     sync.WaitGroup
}

// tlsCertificate keeps the test helper independent from production TLS config.
type tlsCertificate struct {
	certificate [][]byte
	privateKey  any
}

func startPGWireTestServer(t *testing.T, certificate tlsCertificate, readOnly bool) *pgWireTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start PostgreSQL protocol test server: %v", err)
	}
	server := &pgWireTestServer{listener: listener, tlsCert: certificate, readOnly: readOnly, closed: make(chan struct{})}
	server.wait.Add(1)
	go server.acceptLoop()
	t.Cleanup(func() {
		_ = listener.Close()
		close(server.closed)
		server.wait.Wait()
	})
	return server
}

func (s *pgWireTestServer) port() uint16 {
	return uint16(s.listener.Addr().(*net.TCPAddr).Port)
}

func (s *pgWireTestServer) acceptLoop() {
	defer s.wait.Done()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.accepts.Add(1)
		s.wait.Add(1)
		go func() {
			defer s.wait.Done()
			s.serve(connection)
		}()
	}
}

func (s *pgWireTestServer) serve(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	packet, err := readStartupPacket(connection)
	if err != nil || len(packet) != 4 || binary.BigEndian.Uint32(packet) != 80877103 {
		return
	}
	if _, err := connection.Write([]byte{'S'}); err != nil {
		return
	}

	serverCertificate := tls.Certificate{Certificate: s.tlsCert.certificate, PrivateKey: s.tlsCert.privateKey}
	tlsConnection := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12})
	if err := tlsConnection.Handshake(); err != nil {
		return
	}
	if _, err := readStartupPacket(tlsConnection); err != nil {
		return
	}
	if err := writePGMessage(tlsConnection, 'R', int32Payload(0)); err != nil {
		return
	}
	if err := writePGMessage(tlsConnection, 'S', appendCString(nil, "server_version", "test")); err != nil {
		return
	}
	if err := writePGMessage(tlsConnection, 'S', appendCString(nil, "client_encoding", "UTF8")); err != nil {
		return
	}
	if err := writePGMessage(tlsConnection, 'K', append(int32Payload(1), int32Payload(1)...)); err != nil {
		return
	}
	if err := writePGMessage(tlsConnection, 'Z', []byte{'I'}); err != nil {
		return
	}

	for {
		messageType := make([]byte, 1)
		if _, err := io.ReadFull(tlsConnection, messageType); err != nil {
			return
		}
		payload, err := readLengthPayload(tlsConnection)
		if err != nil {
			return
		}
		switch messageType[0] {
		case 'Q':
			query := strings.TrimSuffix(string(payload), "\x00")
			if strings.Contains(strings.ToLower(query), "show transaction_read_only") {
				value := "off"
				if s.readOnly {
					value = "on"
				}
				if err := writeSingleTextRow(tlsConnection, "transaction_read_only", value); err != nil {
					return
				}
			} else {
				if err := writePGMessage(tlsConnection, 'C', append([]byte("SELECT 0"), 0)); err != nil {
					return
				}
			}
			if err := writePGMessage(tlsConnection, 'Z', []byte{'I'}); err != nil {
				return
			}
		case 'X':
			return
		default:
			return
		}
	}
}

func readStartupPacket(reader io.Reader) ([]byte, error) {
	return readLengthPayload(reader)
}

func readLengthPayload(reader io.Reader) ([]byte, error) {
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, lengthBytes); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(lengthBytes))
	if length < 4 || length > 1<<20 {
		return nil, errors.New("invalid protocol message length")
	}
	payload := make([]byte, length-4)
	_, err := io.ReadFull(reader, payload)
	return payload, err
}

func writePGMessage(writer io.Writer, messageType byte, payload []byte) error {
	message := make([]byte, 5+len(payload))
	message[0] = messageType
	binary.BigEndian.PutUint32(message[1:5], uint32(len(payload)+4))
	copy(message[5:], payload)
	_, err := writer.Write(message)
	return err
}

func int32Payload(value int32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(value))
	return payload
}

func appendCString(target []byte, values ...string) []byte {
	for _, value := range values {
		target = append(target, value...)
		target = append(target, 0)
	}
	return target
}

func writeSingleTextRow(writer io.Writer, name, value string) error {
	rowDescription := make([]byte, 2)
	binary.BigEndian.PutUint16(rowDescription, 1)
	rowDescription = appendCString(rowDescription, name)
	rowDescription = append(rowDescription, int32Payload(0)...)
	rowDescription = append(rowDescription, 0, 0)
	rowDescription = append(rowDescription, int32Payload(25)...)
	rowDescription = append(rowDescription, 0xff, 0xff)
	rowDescription = append(rowDescription, 0xff, 0xff, 0xff, 0xff)
	rowDescription = append(rowDescription, 0, 0)
	if err := writePGMessage(writer, 'T', rowDescription); err != nil {
		return err
	}
	dataRow := []byte{0, 1}
	dataRow = append(dataRow, int32Payload(int32(len(value)))...)
	dataRow = append(dataRow, value...)
	if err := writePGMessage(writer, 'D', dataRow); err != nil {
		return err
	}
	return writePGMessage(writer, 'C', append([]byte("SHOW"), 0))
}

func testTLSCertificate(t *testing.T) (tlsCertificate, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tlsCertificate{certificate: [][]byte{serverDER}, privateKey: serverKey}, caPath
}

func closedTestPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()
	return port
}

func multiHostTestURL(ports []uint16, caPath string) string {
	hosts := make([]string, len(ports))
	for index, port := range ports {
		hosts[index] = "localhost:" + strconv.Itoa(int(port))
	}
	return fmt.Sprintf(
		"postgresql://gateway_test_user@%s/gateway_test_database?sslmode=verify-full&sslrootcert=%s&target_session_attrs=read-write&connect_timeout=1&pool_max_conns=1",
		strings.Join(hosts, ","), url.QueryEscape(caPath),
	)
}

func TestPGXMultiHostSelectsFirstReadWriteNodeInOrder(t *testing.T) {
	certificate, caPath := testTLSCertificate(t)
	tests := []struct {
		name            string
		first           string
		wantFirstCalls  int64
		wantSecondCalls int64
	}{
		{name: "first unreachable falls back to second writable", first: "unreachable", wantSecondCalls: 1},
		{name: "first standby falls back to second writable", first: "standby", wantFirstCalls: 1, wantSecondCalls: 1},
		{name: "first writable does not connect to second", first: "writable", wantFirstCalls: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			second := startPGWireTestServer(t, certificate, false)
			var first *pgWireTestServer
			var firstPort uint16
			switch test.first {
			case "unreachable":
				firstPort = closedTestPort(t)
			case "standby":
				first = startPGWireTestServer(t, certificate, true)
				firstPort = first.port()
			case "writable":
				first = startPGWireTestServer(t, certificate, false)
				firstPort = first.port()
			}

			config, err := ParsePoolConfig(multiHostTestURL([]uint16{firstPort, second.port()}, caPath))
			if err != nil {
				t.Fatalf("parse config: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pool, err := Open(ctx, config)
			if err != nil {
				t.Fatalf("open logical pool: %v", err)
			}
			pool.Close()

			var firstCalls int64
			if first != nil {
				firstCalls = first.accepts.Load()
			}
			if firstCalls != test.wantFirstCalls || second.accepts.Load() != test.wantSecondCalls {
				t.Errorf("connection attempts = (%d, %d), want (%d, %d)", firstCalls, second.accepts.Load(), test.wantFirstCalls, test.wantSecondCalls)
			}
		})
	}
}

func TestPGXMultiHostFailsWhenNoReadWriteNodeExists(t *testing.T) {
	certificate, caPath := testTLSCertificate(t)
	t.Run("all unreachable", func(t *testing.T) {
		config, err := ParsePoolConfig(multiHostTestURL([]uint16{closedTestPort(t), closedTestPort(t)}, caPath))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if _, err := Open(ctx, config); !errors.Is(err, ErrConnect) {
			t.Errorf("error = %v, want ErrConnect", err)
		}
	})

	t.Run("all standby", func(t *testing.T) {
		first := startPGWireTestServer(t, certificate, true)
		second := startPGWireTestServer(t, certificate, true)
		config, err := ParsePoolConfig(multiHostTestURL([]uint16{first.port(), second.port()}, caPath))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if _, err := Open(ctx, config); !errors.Is(err, ErrConnect) {
			t.Errorf("error = %v, want ErrConnect", err)
		}
		if first.accepts.Load() == 0 || second.accepts.Load() == 0 {
			t.Error("pgx did not evaluate every configured standby")
		}
	})
}
