package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func (e *Engine) ApplyManagedDockerUserRules(ctx context.Context) error {
	if !e.cfg.Orchestrator.ManageDockerUserRules {
		return nil
	}
	wgIf := strings.TrimSpace(e.cfg.WireGuard.Interface)
	if wgIf == "" {
		return errors.New("wireguard interface is empty")
	}
	if err := e.ensureDockerUserChain(ctx); err != nil {
		return err
	}

	// Allow VPN clients to reach lab networks.
	for _, cidr := range e.cfg.Orchestrator.LabCIDRs {
		rule := []string{"-i", wgIf, "-d", cidr, "-j", "ACCEPT"}
		if err := e.ensureDockerUserRule(ctx, rule); err != nil {
			return err
		}
	}
	// Allow established return traffic back to VPN clients.
	if err := e.ensureDockerUserRule(ctx, []string{"-o", wgIf, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}); err != nil {
		return err
	}
	return nil
}

func (e *Engine) CleanupManagedDockerUserRules(ctx context.Context) error {
	if !e.cfg.Orchestrator.ManageDockerUserRules {
		return nil
	}
	wgIf := strings.TrimSpace(e.cfg.WireGuard.Interface)
	if wgIf == "" {
		return nil
	}
	var errs []string
	for _, cidr := range e.cfg.Orchestrator.LabCIDRs {
		rule := []string{"-i", wgIf, "-d", cidr, "-j", "ACCEPT"}
		if err := e.removeDockerUserRuleAll(ctx, rule); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := e.removeDockerUserRuleAll(ctx, []string{"-o", wgIf, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (e *Engine) ensureDockerUserChain(ctx context.Context) error {
	if err := runIptables(ctx, "-t", "filter", "-nL", "DOCKER-USER"); err == nil {
		// chain exists
	} else {
		_ = runIptables(ctx, "-t", "filter", "-N", "DOCKER-USER")
	}

	exists, err := iptablesRuleExists(ctx, []string{"-t", "filter", "-C", "FORWARD", "-j", "DOCKER-USER"})
	if err != nil {
		return err
	}
	if !exists {
		if err := runIptables(ctx, "-t", "filter", "-I", "FORWARD", "1", "-j", "DOCKER-USER"); err != nil {
			return fmt.Errorf("ensure DOCKER-USER jump: %w", err)
		}
	}
	return nil
}

func (e *Engine) ensureDockerUserRule(ctx context.Context, rule []string) error {
	argsCheck := append([]string{"-t", "filter", "-C", "DOCKER-USER"}, rule...)
	exists, err := iptablesRuleExists(ctx, argsCheck)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	argsInsert := append([]string{"-t", "filter", "-I", "DOCKER-USER", "1"}, rule...)
	if err := runIptables(ctx, argsInsert...); err != nil {
		return fmt.Errorf("insert DOCKER-USER rule %q: %w", strings.Join(rule, " "), err)
	}
	return nil
}

func (e *Engine) removeDockerUserRuleAll(ctx context.Context, rule []string) error {
	for {
		argsCheck := append([]string{"-t", "filter", "-C", "DOCKER-USER"}, rule...)
		exists, err := iptablesRuleExists(ctx, argsCheck)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		argsDel := append([]string{"-t", "filter", "-D", "DOCKER-USER"}, rule...)
		if err := runIptables(ctx, argsDel...); err != nil {
			return fmt.Errorf("delete DOCKER-USER rule %q: %w", strings.Join(rule, " "), err)
		}
	}
}

func iptablesRuleExists(ctx context.Context, args []string) (bool, error) {
	cmd := exec.CommandContext(ctx, "iptables", args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// `-C` returns exit code 1 when rule is not found.
		if ee.ExitCode() == 1 {
			return false, nil
		}
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	return false, fmt.Errorf("iptables %s: %s", strings.Join(args, " "), msg)
}

func runIptables(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "iptables", args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("iptables %s: %s", strings.Join(args, " "), msg)
}
