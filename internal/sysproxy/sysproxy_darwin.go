// Package sysproxy configures the operating system's proxy settings.
// This file contains macOS-specific implementation using networksetup.
//
//go:build darwin

package sysproxy

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// Set configures the system proxy to use Sansürsüz.
func Set(port int) error {
	iface, err := getActiveInterface()
	if err != nil {
		return fmt.Errorf("could not detect active network interface: %w", err)
	}

	log.Printf("[Sansürsüz] Setting system proxy on interface: %s", iface)

	// Set HTTP proxy
	if err := runNetworkSetup("-setwebproxy", iface, "127.0.0.1", fmt.Sprintf("%d", port)); err != nil {
		return fmt.Errorf("failed to set HTTP proxy: %w", err)
	}

	// Set HTTPS proxy
	if err := runNetworkSetup("-setsecurewebproxy", iface, "127.0.0.1", fmt.Sprintf("%d", port)); err != nil {
		return fmt.Errorf("failed to set HTTPS proxy: %w", err)
	}

	log.Printf("[Sansürsüz] System proxy set to 127.0.0.1:%d", port)
	return nil
}

// Unset removes the system proxy configuration.
func Unset() error {
	iface, err := getActiveInterface()
	if err != nil {
		return fmt.Errorf("could not detect active network interface: %w", err)
	}

	log.Printf("[Sansürsüz] Removing system proxy from interface: %s", iface)

	// Disable HTTP proxy
	if err := runNetworkSetup("-setwebproxystate", iface, "off"); err != nil {
		return fmt.Errorf("failed to disable HTTP proxy: %w", err)
	}

	// Disable HTTPS proxy
	if err := runNetworkSetup("-setsecurewebproxystate", iface, "off"); err != nil {
		return fmt.Errorf("failed to disable HTTPS proxy: %w", err)
	}

	log.Printf("[Sansürsüz] System proxy removed")
	return nil
}

// IsSet checks if the system proxy is currently configured to Alcatraz.
func IsSet(port int) bool {
	iface, err := getActiveInterface()
	if err != nil {
		return false
	}

	out, err := exec.Command("networksetup", "-getwebproxy", iface).Output()
	if err != nil {
		return false
	}

	output := string(out)
	return strings.Contains(output, "Enabled: Yes") &&
		strings.Contains(output, "Server: 127.0.0.1") &&
		strings.Contains(output, fmt.Sprintf("Port: %d", port))
}

// getActiveInterface returns the name of the active network interface (e.g., "Wi-Fi").
func getActiveInterface() (string, error) {
	// Try common interfaces in order of likelihood
	interfaces := []string{"Wi-Fi", "Ethernet", "USB 10/100/1000 LAN", "Thunderbolt Ethernet"}

	for _, iface := range interfaces {
		out, err := exec.Command("networksetup", "-getinfo", iface).Output()
		if err != nil {
			continue
		}
		output := string(out)
		// Check if this interface has an IP address (is active)
		if strings.Contains(output, "IP address:") && !strings.Contains(output, "IP address: none") {
			return iface, nil
		}
	}

	// Fallback: list all network services and try each
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return "", fmt.Errorf("networksetup not available: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		// Check if interface is active
		info, err := exec.Command("networksetup", "-getinfo", line).Output()
		if err != nil {
			continue
		}
		if strings.Contains(string(info), "IP address:") && !strings.Contains(string(info), "IP address: none") {
			return line, nil
		}
	}

	return "Wi-Fi", nil // Default fallback
}

// runNetworkSetup executes a networksetup command.
func runNetworkSetup(args ...string) error {
	cmd := exec.Command("networksetup", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup %s failed: %s (%w)", strings.Join(args, " "), string(output), err)
	}
	return nil
}

// CleanupStale checks if proxy is set from a previous crash and clears it.
func CleanupStale(port int) {
	if IsSet(port) {
		log.Println("[Sansürsüz] ⚠️ Önceki oturumdan kalan proxy ayarı temizleniyor...")
		Unset()
	}
}
