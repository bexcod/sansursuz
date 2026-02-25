// Package sysproxy configures the operating system's proxy settings.
// This file contains Windows-specific implementation using registry.
//
//go:build windows

package sysproxy

import (
	"fmt"
	"log"
	"os/exec"
)

// Set configures the system proxy to use Alcatraz on Windows.
func Set(port int) error {
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Enable proxy via registry
	if err := regSet(`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable", "1"); err != nil {
		return fmt.Errorf("failed to enable proxy: %w", err)
	}
	if err := regSet(`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyServer", proxyAddr); err != nil {
		return fmt.Errorf("failed to set proxy address: %w", err)
	}

	// Notify the system of the change
	exec.Command("cmd", "/c", "RUNDLL32.EXE", "inetcpl.cpl,LaunchConnectionDialog").Run()

	log.Printf("[Sansürsüz] System proxy set to %s", proxyAddr)
	return nil
}

// Unset removes the system proxy configuration on Windows.
func Unset() error {
	if err := regSet(`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable", "0"); err != nil {
		return fmt.Errorf("failed to disable proxy: %w", err)
	}
	log.Printf("[Sansürsüz] System proxy removed")
	return nil
}

// IsSet checks if the system proxy is currently configured to Alcatraz on Windows.
func IsSet(port int) bool {
	out, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable").Output()
	if err != nil {
		return false
	}
	return len(out) > 0
}

func regSet(key, name, value string) error {
	var regType string
	if value == "0" || value == "1" {
		regType = "REG_DWORD"
	} else {
		regType = "REG_SZ"
	}
	cmd := exec.Command("reg", "add", key, "/v", name, "/t", regType, "/d", value, "/f")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("reg command failed: %s (%w)", string(output), err)
	}
	return nil
}
