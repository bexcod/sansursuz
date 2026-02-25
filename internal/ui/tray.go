//go:build cgo
// +build cgo

package ui

import (
	"context"
	"log"

	"github.com/getlantern/systray"
)

// TrayApp manages the system tray icon and menu.
type TrayApp struct {
	onEnable  func()
	onDisable func()
	onOpenUI  func()
	isActive  bool
	mStatus   *systray.MenuItem
	mToggle   *systray.MenuItem
}

// NewTrayApp creates a new system tray application.
func NewTrayApp(onEnable, onDisable, onOpenUI func()) *TrayApp {
	return &TrayApp{
		onEnable:  onEnable,
		onDisable: onDisable,
		onOpenUI:  onOpenUI,
	}
}

// Run starts the system tray application. This blocks until the tray exits.
func (t *TrayApp) Run(ctx context.Context) {
	systray.Run(func() {
		t.onReady(ctx)
	}, func() {
		log.Println("[Sansürsüz] Tray kapatıldı")
	})
}

func (t *TrayApp) onReady(ctx context.Context) {
	systray.SetTitle("Sansürsüz")
	systray.SetTooltip("Sansürsüz — Sansür Aşma Aracı")

	// Menu items — start in active state since proxy auto-starts
	t.mStatus = systray.AddMenuItem("🟢 Etkin", "Mevcut durum")
	t.mStatus.Disable()
	systray.AddSeparator()

	mOpenUI := systray.AddMenuItem("⚙️ Ayarlar", "Arayüzü aç")
	t.mToggle = systray.AddMenuItem("⏸ Devre Dışı Bırak", "Proxy'yi kapat")
	t.isActive = true
	systray.AddSeparator()

	mQuit := systray.AddMenuItem("❌ Çıkış", "Programı kapat")

	go func() {
		for {
			select {
			case <-mOpenUI.ClickedCh:
				if t.onOpenUI != nil {
					t.onOpenUI()
				}
			case <-t.mToggle.ClickedCh:
				if t.isActive {
					t.isActive = false
					if t.onDisable != nil {
						t.onDisable()
					}
					t.mStatus.SetTitle("🔴 Devre Dışı")
					t.mToggle.SetTitle("▶ Etkinleştir")
					systray.SetTitle("Sansürsüz")
				} else {
					t.isActive = true
					if t.onEnable != nil {
						t.onEnable()
					}
					t.mStatus.SetTitle("🟢 Etkin")
					t.mToggle.SetTitle("⏸ Devre Dışı Bırak")
					systray.SetTitle("🟢 Sansürsüz")
				}
			case <-mQuit.ClickedCh:
				if t.isActive && t.onDisable != nil {
					t.onDisable()
				}
				systray.Quit()
				return
			case <-ctx.Done():
				systray.Quit()
				return
			}
		}
	}()
}
