package chclient

import (
	"context"
	"crypto/elliptic"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jpillora/chisel/share/ccrypto"
	"golang.org/x/crypto/ssh"
)

func TestTargetDialContext(t *testing.T) {
	expectedErr := errors.New("target dial")
	var gotNetwork string
	var gotAddr string
	config := Config{
		TargetDialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			gotNetwork = network
			gotAddr = addr
			return nil, expectedErr
		},
	}
	c, err := NewClient(&config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.tunnel.TargetDialContext(context.Background(), "tcp", "database.example:5432")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected target dial error, got %v", err)
	}
	if gotNetwork != "tcp" {
		t.Fatalf("expected tcp network, got %q", gotNetwork)
	}
	if gotAddr != "database.example:5432" {
		t.Fatalf("expected database address, got %q", gotAddr)
	}
}

func TestAcceptServerTCPConnections(t *testing.T) {
	c, err := NewClient(&Config{AcceptServerTCPConnections: true})
	if err != nil {
		t.Fatal(err)
	}
	if !c.tunnel.Outbound {
		t.Fatal("expected outbound connections to be enabled")
	}
	if !c.tunnel.TCPOnly {
		t.Fatal("expected non-TCP connections to be disabled")
	}
	if c.tunnel.Socks {
		t.Fatal("expected SOCKS to be disabled")
	}
	if len(c.computed.Remotes) != 0 {
		t.Fatalf("expected no declared remotes, got %d", len(c.computed.Remotes))
	}
}

func TestCustomHeaders(t *testing.T) {
	//fake server, records the header for the main goroutine to
	//assert (t.Fatal must not be called from the handler goroutine)
	wg := sync.WaitGroup{}
	wg.Add(1)
	var gotFoo string
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotFoo = req.Header.Get("Foo")
		wg.Done()
	}))
	defer server.Close()
	//client
	headers := http.Header{}
	headers.Set("Foo", "Bar")
	config := Config{
		KeepAlive:        time.Second,
		MaxRetryInterval: time.Second,
		Server:           server.URL,
		Remotes:          []string{"9000"},
		Headers:          headers,
	}
	c, err := NewClient(&config)
	if err != nil {
		t.Fatal(err)
	}
	go c.Run()
	//wait for the fake server to receive the request
	wg.Wait()
	c.Close()
	if gotFoo != "Bar" {
		t.Fatalf("expected header Foo to be 'Bar', got %q", gotFoo)
	}
}

func TestFallbackLegacyFingerprint(t *testing.T) {
	config := Config{
		Fingerprint: "a5:32:92:c6:56:7a:9e:61:26:74:1b:81:a6:f5:1b:44",
	}
	c, err := NewClient(&config)
	if err != nil {
		t.Fatal(err)
	}
	r := ccrypto.NewDetermRand([]byte("test123"))
	priv, err := ccrypto.GenerateKeyGo119(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = c.verifyServer("", nil, pub)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyLegacyFingerprint(t *testing.T) {
	config := Config{
		Fingerprint: "a5:32:92:c6:56:7a:9e:61:26:74:1b:81:a6:f5:1b:44",
	}
	c, err := NewClient(&config)
	if err != nil {
		t.Fatal(err)
	}
	r := ccrypto.NewDetermRand([]byte("test123"))
	priv, err := ccrypto.GenerateKeyGo119(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = c.verifyLegacyFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFingerprint(t *testing.T) {
	config := Config{
		Fingerprint: "qmrRoo8MIqePv3jC8+wv49gU6uaFgD3FASQx9V8KdmY=",
	}
	c, err := NewClient(&config)
	if err != nil {
		t.Fatal(err)
	}
	r := ccrypto.NewDetermRand([]byte("test123"))
	priv, err := ccrypto.GenerateKeyGo119(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = c.verifyServer("", nil, pub)
	if err != nil {
		t.Fatal(err)
	}
}
