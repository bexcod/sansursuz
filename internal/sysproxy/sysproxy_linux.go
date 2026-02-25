// Package sysproxy configures the operating system's proxy settings.
// This file contains Linux-specific implementation.
//
//go:build linux

package sysproxy

import (
	"fmt"
	"log"
	"os/exec"
)

// Set configures the system proxy on Linux (GNOME).
func Set(port int) error {
	proxyAddr := fmt.Sprintf("127.0.0.1")
	portStr := fmt.Sprintf("%d", port)

	// Try GNOME gsettings first
	if gsettingsAvailable() {
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "host", proxyAddr).Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "port", portStr).Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "host", proxyAddr).Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "port", portStr).Run()
		log.Printf("[Sansürsüz] System proxy set via GNOME gsettings")
		return nil
	}

	log.Printf("[Sansürsüz] Warning: Could not set system proxy automatically on Linux.")
	log.Printf("[Sansürsüz] Please set HTTP/HTTPS proxy manually to 127.0.0.1:%d", port)
	return nil
}

// Unset removes the system proxy configuration on Linux.
func Unset() error {
	if gsettingsAvailable() {
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
		log.Printf("[Sansürsüz] System proxy removed via GNOME gsettings")
		return nil
	}
	return nil
}

// IsSet checks if the system proxy is configured on Linux.
func IsSet(port int) bool {
	if !gsettingsAvailable() {
		return false
	}
	out, err := exec.Command("gsettings", "get", "org.gnome.system.proxy", "mode").Output()
	if err != nil {
		return false
	}
	return string(out) == "'manual'\n"
}

func gsettingsAvailable() bool {
	_, err := exec.LookPath("gsettings")
	return err == nil
}
