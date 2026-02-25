//go:build !cgo
// +build !cgo

package ui

import (
	"context"
	"log"
)

// TrayApp is a no-op when CGO is disabled (cross-compiled builds).
type TrayApp struct{}

// NewTrayApp returns a stub tray app when CGO is disabled.
func NewTrayApp(onEnable, onDisable, onOpenUI func()) *TrayApp {
	return &TrayApp{}
}

// Run logs that tray is unavailable and blocks on context.
func (t *TrayApp) Run(ctx context.Context) {
	log.Println("[Sansürsüz] Tray ikonu mevcut değil (headless build)")
	log.Println("[Sansürsüz] Web UI üzerinden kontrol edin")
	<-ctx.Done()
}
