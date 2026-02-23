package wireguard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/csai/htb-clone-lab-agent/internal/config"
	"github.com/csai/htb-clone-lab-agent/internal/state"
)

type Manager interface {
	ProvisionPeer(instanceID, userID string) (state.WireGuardPeer, error)
	RemovePeer(publicKey string) error
}

type WGManager struct {
	cfg config.WireGuardConfig
}

func New(cfg config.WireGuardConfig) Manager {
	return &WGManager{cfg: cfg}
}

func (w *WGManager) ProvisionPeer(instanceID, userID string) (state.WireGuardPeer, error) {
	addr := derivePeerAddress(instanceID, userID)
	priv, pub, err := generateKeyPair(w.cfg.Mode)
	if err != nil {
		return state.WireGuardPeer{}, err
	}
	peer := state.WireGuardPeer{
		ClientPrivateKey: priv,
		ClientPublicKey:  pub,
		ClientAddress:    addr + "/32",
		ServerPublicKey:  w.cfg.ServerPublicKey,
		ServerEndpoint:   w.cfg.ServerEndpoint,
		AllowedIPs:       w.cfg.AllowedIPs,
		DNS:              w.cfg.DNS,
	}

	if strings.EqualFold(w.cfg.Mode, "wg") {
		if err := exec.Command("wg", "set", w.cfg.Interface, "peer", pub, "allowed-ips", peer.ClientAddress).Run(); err != nil {
			return state.WireGuardPeer{}, fmt.Errorf("wg set add peer: %w", err)
		}
	}
	return peer, nil
}

func (w *WGManager) RemovePeer(publicKey string) error {
	if publicKey == "" || !strings.EqualFold(w.cfg.Mode, "wg") {
		return nil
	}
	if err := exec.Command("wg", "set", w.cfg.Interface, "peer", publicKey, "remove").Run(); err != nil {
		return fmt.Errorf("wg remove peer: %w", err)
	}
	return nil
}

func derivePeerAddress(instanceID, userID string) string {
	seed := hmac.New(sha256.New, []byte("wg-peer-v1"))
	_, _ = seed.Write([]byte(userID + ":" + instanceID))
	sum := seed.Sum(nil)
	// 10.13.16.1 .. 10.13.31.254 (4094 peers)
	idx := int(sum[0])<<8 | int(sum[1])
	idx = idx%4094 + 1
	octet3 := 16 + (idx-1)/254
	octet4 := 1 + (idx-1)%254
	return fmt.Sprintf("10.13.%d.%d", octet3, octet4)
}

func generateKeyPair(mode string) (private, public string, err error) {
	if strings.EqualFold(mode, "wg") {
		privBytes, err := exec.Command("wg", "genkey").Output()
		if err != nil {
			return "", "", fmt.Errorf("wg genkey: %w", err)
		}
		private = strings.TrimSpace(string(privBytes))
		cmd := exec.Command("sh", "-c", fmt.Sprintf("printf '%%s' %q | wg pubkey", private))
		pubBytes, err := cmd.Output()
		if err != nil {
			return "", "", fmt.Errorf("wg pubkey: %w", err)
		}
		public = strings.TrimSpace(string(pubBytes))
		return private, public, nil
	}

	pk := make([]byte, 32)
	pub := make([]byte, 32)
	if _, err := rand.Read(pk); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(pub); err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pk), hex.EncodeToString(pub), nil
}
