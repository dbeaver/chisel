package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDialTargetUsesConfiguredDialer(t *testing.T) {
	expectedErr := errors.New("target dial")
	var gotNetwork string
	var gotAddr string
	tunnel := &Tunnel{Config: Config{
		TargetDialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			gotNetwork = network
			gotAddr = addr
			return nil, expectedErr
		},
	}}
	_, err := tunnel.dialTarget(context.Background(), "tcp", "database.example:5432")
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
