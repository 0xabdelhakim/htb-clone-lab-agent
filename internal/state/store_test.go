package state

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreUpsertAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	st, err := New(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	rec := InstanceRecord{InstanceID: "abc", Status: "running", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := st.Upsert(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	st2, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := st2.Get("abc")
	if !ok {
		t.Fatalf("expected record after reload")
	}
	if got.Status != "running" {
		t.Fatalf("unexpected status: %s", got.Status)
	}
}
