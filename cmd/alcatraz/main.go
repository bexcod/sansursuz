// Sansürsüz — Cross-platform censorship circumvention tool for Turkey
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bex/alcatraz/internal/config"
	"github.com/bex/alcatraz/internal/dns"
	"github.com/bex/alcatraz/internal/domains"
	"github.com/bex/alcatraz/internal/proxy"
	"github.com/bex/alcatraz/internal/sysproxy"
	"github.com/bex/alcatraz/internal/ui"
)

const version = "2.0.0"

// App holds all runtime state.
type App struct {
	mu          sync.Mutex
	cfg         *config.Config
	resolver    *dns.Resolver
	matcher     *domains.Matcher
	proxyServer *proxy.Server
	webUI       *ui.WebUI
	proxyCtx    context.Context
	proxyCancel context.CancelFunc
	active      bool
}

func main() {
	noGUI := flag.Bool("no-gui", false, "Headless mode (no system tray)")
	port := flag.Int("port", 0, "Proxy port (default: from config or 8443)")
	mode := flag.String("mode", "", "Proxy mode: selective or all")
	dnsProvider := flag.String("dns", "", "DNS provider: cloudflare or google")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Sansürsüz v%s\n", version)
		os.Exit(0)
	}

	cfg := config.Load()
	if *port != 0 {
		cfg.Proxy.Port = *port
	}
	if *mode != "" {
		cfg.Proxy.Mode = *mode
	}
	if *dnsProvider != "" {
		cfg.DNS.Provider = *dnsProvider
	}

	app := &App{cfg: cfg}
	app.initComponents()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("[Sansürsüz] v%s başlatılıyor...", version)
	log.Printf("[Sansürsüz] DNS: %s | Mod: %s | Port: %d",
		cfg.DNS.Provider, cfg.Proxy.Mode, cfg.Proxy.Port)

	// DNS Prefetch
	go app.resolver.Prefetch(app.matcher.AllDomains())

	// Start proxy immediately
	app.startProxy(ctx)

	// Start web UI
	webUIPort := cfg.Proxy.Port + 1 // 8444 by default
	app.webUI = ui.NewWebUI(webUIPort, ui.Callbacks{
		OnToggle:         app.toggle,
		OnSettingsChange: app.changeSetting,
		GetState:         app.getState,
	})

	go func() {
		if err := app.webUI.Start(ctx); err != nil {
			log.Printf("[Sansürsüz] Web UI hatası: %v", err)
		}
	}()

	// Auto-open browser after a short delay for web server to start
	go func() {
		time.Sleep(500 * time.Millisecond)
		app.webUI.OpenInBrowser()
	}()

	if *noGUI {
		app.runHeadless(ctx, cancel)
	} else {
		app.runWithTray(ctx, cancel)
	}
}

func (a *App) initComponents() {
	a.resolver = createResolver(a.cfg)
	a.matcher = createMatcher(a.cfg)
	fragConfig := createFragConfig(a.cfg)

	a.proxyServer = proxy.NewServer(
		a.cfg.Proxy.Port,
		a.cfg.Proxy.Mode,
		a.resolver,
		a.matcher,
		fragConfig,
	)
}

func (a *App) startProxy(parentCtx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.active {
		return
	}

	a.proxyCtx, a.proxyCancel = context.WithCancel(parentCtx)
	go func() {
		if err := a.proxyServer.Start(a.proxyCtx); err != nil {
			log.Printf("[Sansürsüz] Proxy hatası: %v", err)
		}
	}()

	if err := sysproxy.Set(a.proxyServer.Port()); err != nil {
		log.Printf("[Sansürsüz] Sistem proxy ayarlanamadı: %v", err)
	} else {
		log.Printf("[Sansürsüz] ✅ Sistem proxy ayarlandı")
	}

	a.active = true
	log.Println("[Sansürsüz] ✅ Proxy aktif!")
}

func (a *App) stopProxy() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.active {
		return
	}

	sysproxy.Unset()
	a.proxyServer.Stop()
	if a.proxyCancel != nil {
		a.proxyCancel()
	}
	a.active = false
	log.Println("[Sansürsüz] Proxy durduruldu")
}

func (a *App) toggle() bool {
	a.mu.Lock()
	active := a.active
	a.mu.Unlock()

	if active {
		a.stopProxy()
		return false
	}

	a.startProxy(context.Background())
	return true
}

func (a *App) changeSetting(key, value string) error {
	switch key {
	case "dns":
		if value != "cloudflare" && value != "google" && value != "quad9" && value != "adguard" && value != "yandex" {
			return fmt.Errorf("geçersiz DNS: %s", value)
		}
		a.cfg.DNS.Provider = value
		a.resolver = createResolver(a.cfg)
		log.Printf("[Sansürsüz] DNS değiştirildi: %s", value)

	case "mode":
		if value != "selective" && value != "all" {
			return fmt.Errorf("geçersiz mod: %s", value)
		}
		a.cfg.Proxy.Mode = value
		// Need to restart proxy with new mode
		wasActive := a.active
		if wasActive {
			a.stopProxy()
		}
		fragConfig := createFragConfig(a.cfg)
		a.proxyServer = proxy.NewServer(
			a.cfg.Proxy.Port, value, a.resolver, a.matcher, fragConfig,
		)
		if wasActive {
			a.startProxy(context.Background())
		}
		log.Printf("[Sansürsüz] Mod değiştirildi: %s", value)

	case "port":
		newPort := 0
		for _, c := range value {
			if c < '0' || c > '9' {
				return fmt.Errorf("geçersiz port: %s", value)
			}
			newPort = newPort*10 + int(c-'0')
		}
		if newPort < 1024 || newPort > 65535 {
			return fmt.Errorf("port 1024-65535 arasında olmalı: %d", newPort)
		}
		a.cfg.Proxy.Port = newPort
		wasActive := a.active
		if wasActive {
			a.stopProxy()
		}
		fragConfig := createFragConfig(a.cfg)
		a.proxyServer = proxy.NewServer(
			a.cfg.Proxy.Port, a.cfg.Proxy.Mode, a.resolver, a.matcher, fragConfig,
		)
		if wasActive {
			a.startProxy(context.Background())
		}
		log.Printf("[Sansürsüz] Port değiştirildi: %d", newPort)

	default:
		return fmt.Errorf("bilinmeyen ayar: %s", key)
	}
	return nil
}

func (a *App) getState() ui.AppState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ui.AppState{
		Active:  a.active,
		DNS:     a.cfg.DNS.Provider,
		Mode:    a.cfg.Proxy.Mode,
		Port:    a.cfg.Proxy.Port,
		Version: version,
	}
}

func (a *App) runHeadless(ctx context.Context, cancel context.CancelFunc) {
	log.Printf("[Sansürsüz] Web UI: http://127.0.0.1:%d", a.cfg.Proxy.Port+1)
	log.Println("[Sansürsüz] ✅ Çalışıyor! Durdurmak için Ctrl+C basın.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[Sansürsüz] Kapatılıyor...")
	a.stopProxy()
	cancel()
}

func (a *App) runWithTray(ctx context.Context, cancel context.CancelFunc) {
	onEnable := func() {
		a.startProxy(ctx)
	}
	onDisable := func() {
		a.stopProxy()
	}
	onOpenUI := func() {
		a.webUI.OpenInBrowser()
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		a.stopProxy()
		cancel()
		os.Exit(0)
	}()

	tray := ui.NewTrayApp(onEnable, onDisable, onOpenUI)
	tray.Run(ctx)
}

func createResolver(cfg *config.Config) *dns.Resolver {
	switch cfg.DNS.Provider {
	case "google":
		return dns.NewResolver(dns.Google, dns.Cloudflare)
	case "quad9":
		return dns.NewResolver(dns.Quad9, dns.Cloudflare)
	case "adguard":
		return dns.NewResolver(dns.AdGuard, dns.Cloudflare)
	case "yandex":
		return dns.NewResolver(dns.Yandex, dns.Cloudflare)
	default:
		return dns.NewResolver(dns.Cloudflare, dns.Google)
	}
}

func createMatcher(cfg *config.Config) *domains.Matcher {
	matcher := domains.NewMatcher()
	if len(cfg.Domains.Extra) > 0 {
		matcher.AddDomains(cfg.Domains.Extra)
	}
	return matcher
}

func createFragConfig(cfg *config.Config) proxy.FragmentConfig {
	fc := proxy.DefaultFragmentConfig()

	switch cfg.Fragment.Strategy {
	case "first_byte":
		fc.Strategy = proxy.FragmentFirstByte
	case "before_sni":
		fc.Strategy = proxy.FragmentBeforeSNI
	case "middle":
		fc.Strategy = proxy.FragmentMiddle
	case "chunked":
		fc.Strategy = proxy.FragmentChunked
	}

	if cfg.Fragment.ChunkSize > 0 {
		fc.ChunkSize = cfg.Fragment.ChunkSize
	}

	return fc
}
