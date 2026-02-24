package orchestrator

import (
	"context"
	"errors"
	"testing"
)

type fakeOutputRunner struct {
	out []byte
	err error
}

func (f fakeOutputRunner) Output(context.Context, string, ...string) ([]byte, error) {
	return f.out, f.err
}

func TestCheckRawPreroutingDropsFlagsLabSubnetDrop(t *testing.T) {
	out := []byte("-A PREROUTING ! -i br-9f0736dfd1ba -d 172.27.0.2/32 -j DROP\n")
	err := checkRawPreroutingDrops(context.Background(), fakeOutputRunner{out: out}, []string{"172.16.0.0/12"})
	if err == nil {
		t.Fatal("expected startup check failure")
	}
}

func TestCheckRawPreroutingDropsAllowsNonLabDrop(t *testing.T) {
	out := []byte("-A PREROUTING -d 8.8.8.8/32 -j DROP\n")
	err := checkRawPreroutingDrops(context.Background(), fakeOutputRunner{out: out}, []string{"172.16.0.0/12"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckRawPreroutingDropsAllowsNoDrop(t *testing.T) {
	out := []byte("-A PREROUTING -d 172.27.0.2/32 -j ACCEPT\n")
	err := checkRawPreroutingDrops(context.Background(), fakeOutputRunner{out: out}, []string{"172.16.0.0/12"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckRawPreroutingDropsAllowsMissingIptables(t *testing.T) {
	err := checkRawPreroutingDrops(context.Background(), fakeOutputRunner{err: errors.New("exec: \"iptables\": executable file not found in $PATH")}, []string{"172.16.0.0/12"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckRawPreroutingDropsAllowsPermissionDenied(t *testing.T) {
	err := checkRawPreroutingDrops(context.Background(), fakeOutputRunner{err: errors.New("iptables v1.8.10: Permission denied (you must be root)")}, []string{"172.16.0.0/12"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
