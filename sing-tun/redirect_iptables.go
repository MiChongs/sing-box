//go:build linux

package tun

import (
	"os/exec"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

func (r *autoRedirect) setupIPTables() error {
	err := r.setupIPTablesSync()
	if err == nil {
		return nil
	}
	// If lock contention, set up asynchronously — don't block startup
	if isXtablesLockError(err) {
		r.logger.Warn("iptables lock contention during setup, will retry in background")
		go r.setupIPTablesAsync()
		return nil
	}
	return err
}

func (r *autoRedirect) setupIPTablesSync() error {
	if r.enableIPv4 {
		err := r.setupIPTablesForFamily(r.iptablesPath)
		if err != nil {
			return E.Cause(err, "setup iptables")
		}
	}
	if r.enableIPv6 {
		err := r.setupIPTablesForFamily(r.ip6tablesPath)
		if err != nil {
			return E.Cause(err, "setup ip6tables")
		}
	}
	return nil
}

func (r *autoRedirect) setupIPTablesAsync() {
	delays := []time.Duration{
		500 * time.Millisecond,
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
	}
	for i, delay := range delays {
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(delay):
		}
		r.cleanupIPTables()
		err := r.setupIPTablesSync()
		if err == nil {
			r.logger.Info("iptables rules applied successfully (background attempt ", i+1, ")")
			return
		}
		if !isXtablesLockError(err) {
			r.logger.Error("iptables setup failed: ", err)
			return
		}
		r.logger.Warn("iptables lock still held, retrying (", i+2, "/", len(delays)+1, ")")
	}
	// Final attempt with long wait
	select {
	case <-r.ctx.Done():
		return
	case <-time.After(15 * time.Second):
	}
	r.cleanupIPTables()
	err := r.setupIPTablesSync()
	if err != nil {
		r.logger.Error("iptables setup failed after all retries: ", err)
	} else {
		r.logger.Info("iptables rules applied successfully (final attempt)")
	}
}

func (r *autoRedirect) setupIPTablesForFamily(iptablesPath string) error {
	tableNameOutput := r.tableName + "-output"
	redirectPort := r.redirectPort()
	err := r.runShell(iptablesPath, "-w 1 -t nat -N", tableNameOutput)
	if err != nil {
		return err
	}
	err = r.runShell(iptablesPath, "-w 1 -t nat -A", tableNameOutput,
		"-p tcp -o", r.tunOptions.Name,
		"-j REDIRECT --to-ports", redirectPort)
	if err != nil {
		return err
	}
	err = r.runShell(iptablesPath, "-w 1 -t nat -I OUTPUT -j", tableNameOutput)
	if err != nil {
		return err
	}
	return nil
}

func (r *autoRedirect) cleanupIPTables() {
	if r.enableIPv4 {
		r.cleanupIPTablesForFamily(r.iptablesPath)
	}
	if r.enableIPv6 {
		r.cleanupIPTablesForFamily(r.ip6tablesPath)
	}
}

func (r *autoRedirect) cleanupIPTablesForFamily(iptablesPath string) {
	tableNameOutput := r.tableName + "-output"
	_ = r.runShell(iptablesPath, "-w 1 -t nat -D OUTPUT -j", tableNameOutput)
	_ = r.runShell(iptablesPath, "-w 1 -t nat -F", tableNameOutput)
	_ = r.runShell(iptablesPath, "-w 1 -t nat -X", tableNameOutput)
}

func (r *autoRedirect) runShell(commands ...any) error {
	commandStr := strings.Join(F.MapToString(commands), " ")
	var command *exec.Cmd
	if r.androidSu {
		command = exec.Command(r.suPath, "-c", commandStr)
	} else {
		commandArray := strings.Split(commandStr, " ")
		command = exec.Command(commandArray[0], commandArray[1:]...)
	}
	combinedOutput, err := command.CombinedOutput()
	if err != nil {
		return E.Extend(err, F.ToString(commandStr, ": ", string(combinedOutput)))
	}
	return nil
}

func isXtablesLockError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "xtables.lock") ||
		strings.Contains(msg, "Try again") ||
		strings.Contains(msg, "Resource temporarily unavailable")
}
