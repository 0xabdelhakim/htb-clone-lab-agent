package orchestrator

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

type iptablesOutputRunner interface {
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

func (e *Engine) StartupSelfCheck(ctx context.Context) error {
	if !e.cfg.Orchestrator.StartupFirewallCheck {
		return nil
	}
	return checkRawPreroutingDrops(ctx, execRunner{}, e.cfg.Orchestrator.LabCIDRs)
}

func checkRawPreroutingDrops(ctx context.Context, runner iptablesOutputRunner, labCIDRs []string) error {
	labPrefixes := make([]netip.Prefix, 0, len(labCIDRs))
	for _, c := range labCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("parse lab cidr %q: %w", c, err)
		}
		labPrefixes = append(labPrefixes, p)
	}

	out, err := runner.Output(ctx, "iptables", "-t", "raw", "-S", "PREROUTING")
	if err != nil {
		// Don't hard-fail when iptables is unavailable (e.g., local dev) or
		// inaccessible to the current service account.
		lowerErr := strings.ToLower(err.Error())
		if strings.Contains(lowerErr, "executable file not found") || strings.Contains(lowerErr, "permission denied") || strings.Contains(lowerErr, "operation not permitted") {
			return nil
		}
		return fmt.Errorf("inspect raw prerouting rules: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	var offenders []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if isSuspiciousRawDrop(line, labPrefixes) {
			offenders = append(offenders, line)
		}
	}
	if len(offenders) == 0 {
		return nil
	}
	if len(offenders) > 3 {
		offenders = offenders[:3]
	}
	return fmt.Errorf("startup firewall check failed; found raw prerouting DROP rule(s) targeting lab subnets: %s", strings.Join(offenders, " | "))
}

func isSuspiciousRawDrop(rule string, labCIDRs []netip.Prefix) bool {
	fields := strings.Fields(rule)
	if len(fields) < 2 || fields[0] != "-A" || fields[1] != "PREROUTING" {
		return false
	}

	hasDrop := false
	dest := ""
	for i := 2; i < len(fields); i++ {
		switch fields[i] {
		case "-j", "--jump":
			if i+1 < len(fields) && fields[i+1] == "DROP" {
				hasDrop = true
			}
		case "-d", "--destination":
			if i+1 < len(fields) {
				dest = fields[i+1]
			}
		}
	}
	if !hasDrop || dest == "" {
		return false
	}
	dstPrefix, err := parseIPOrCIDR(dest)
	if err != nil {
		return false
	}
	if !overlapsAny(dstPrefix, labCIDRs) {
		return false
	}
	// Raw-table destination DROP on lab CIDRs breaks VPN->lab forwarding; fail fast.
	return true
}

func parseIPOrCIDR(value string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(value); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func overlapsAny(dst netip.Prefix, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(dst.Addr()) || dst.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
