// Package sysproxy configures the operating system's proxy settings.
// This file contains Windows-specific implementation using registry.
//
//go:build windows

package sysproxy

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var (
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
	// RunOnce key name — will auto-clear proxy on next boot if app crashes
	runOnceKeyName = "SansursuzProxyCleanup"
)

// Set configures the system proxy to use Sansürsüz on Windows.
// Also registers a RunOnce cleanup so proxy is auto-cleared on next boot
// if the app crashes or power is lost.
func Set(port int) error {
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Enable proxy via registry
	if err := regSet(`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable", "1"); err != nil {
		return fmt.Errorf("failed to enable proxy: %w", err)
	}
	if err := regSet(`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyServer", proxyAddr); err != nil {
		return fmt.Errorf("failed to set proxy address: %w", err)
	}

	// Register RunOnce: if next boot happens without proper Unset(), this will auto-clear the proxy.
	// RunOnce keys execute ONCE on next login and then auto-delete from registry.
	registerRunOnceCleanup()

	// Notify the system of proxy change silently (no dialog!)
	notifyProxyChange()

	log.Printf("[Sansürsüz] System proxy set to %s", proxyAddr)
	return nil
}

// Unset removes the system proxy configuration on Windows.
// Also removes the RunOnce cleanup key since proper shutdown occurred.
func Unset() error {
	if err := regSet(`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable", "0"); err != nil {
		return fmt.Errorf("failed to disable proxy: %w", err)
	}

	// Remove RunOnce key — clean shutdown, no cleanup needed on next boot
	removeRunOnceCleanup()

	notifyProxyChange()
	log.Printf("[Sansürsüz] System proxy removed")
	return nil
}

// registerRunOnceCleanup adds a RunOnce registry entry that will auto-clear the proxy
// on next Windows boot. This is the safety net for power loss / crash / BSOD.
func registerRunOnceCleanup() {
	// The command that will run on next boot to disable the proxy
	cleanupCmd := `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f`

	cmd := exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		"/v", runOnceKeyName,
		"/t", "REG_SZ",
		"/d", cleanupCmd,
		"/f",
	)
	if err := cmd.Run(); err != nil {
		log.Printf("[Sansürsüz] RunOnce kayıt hatası: %v", err)
	}
}

// removeRunOnceCleanup removes the RunOnce entry (called during clean shutdown).
func removeRunOnceCleanup() {
	exec.Command("reg", "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		"/v", runOnceKeyName,
		"/f",
	).Run()
}

// CleanupStale checks if the proxy is set to our address from a previous crash
// and clears it. Should be called at startup.
func CleanupStale(port int) {
	expectedAddr := fmt.Sprintf("127.0.0.1:%d", port)

	out, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyServer").Output()
	if err != nil {
		return
	}

	// Check if proxy points to our address
	if strings.Contains(string(out), expectedAddr) {
		// Also check if ProxyEnable is 1
		out2, err := exec.Command("reg", "query",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
			"/v", "ProxyEnable").Output()
		if err != nil {
			return
		}
		if strings.Contains(string(out2), "0x1") {
			log.Println("[Sansürsüz] ⚠️ Önceki oturumdan kalan proxy ayarı temizleniyor...")
			Unset()
		}
	}
}

// notifyProxyChange tells Windows to pick up the registry changes without opening any UI.
func notifyProxyChange() {
	procInternetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOptionW.Call(0, internetOptionRefresh, 0, 0)
	_ = unsafe.Pointer(nil) // keep unsafe import
}

// IsSet checks if the system proxy is currently configured on Windows.
func IsSet(port int) bool {
	out, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "0x1")
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
