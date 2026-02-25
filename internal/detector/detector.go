// Package detector provides automatic ISP block detection.
// When a direct connection fails but a fragmented connection succeeds,
// the domain is confirmed as ISP-blocked and auto-added to the blocklist.
package detector

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"sync"
	"time"

	"github.com/bexcod/sansursuz/internal/domains"
)

// Result represents the outcome of a block detection probe.
type Result int

const (
	ResultUnknown     Result = iota
	ResultNotBlocked         // Direct connection works fine
	ResultISPBlocked         // Direct fails, fragmented works → ISP block confirmed
	ResultUnreachable        // Both fail → site actually down
)

func (r Result) String() string {
	switch r {
	case ResultNotBlocked:
		return "erişilebilir"
	case ResultISPBlocked:
		return "ISP engelli"
	case ResultUnreachable:
		return "erişilemez"
	default:
		return "bilinmiyor"
	}
}

// Detector detects ISP-blocked domains by comparing direct vs fragmented connections.
type Detector struct {
	matcher *domains.Matcher

	// Track recently probed domains to avoid redundant probes
	probed   map[string]time.Time
	probedMu sync.RWMutex

	// Track failure counts per domain to trigger probing
	failures   map[string]int
	failuresMu sync.Mutex

	// How many failures before triggering a probe
	failureThreshold int
	// How long to remember a probe result
	probeCooldown time.Duration
}

// New creates a new Detector.
func New(matcher *domains.Matcher) *Detector {
	return &Detector{
		matcher:          matcher,
		probed:           make(map[string]time.Time),
		failures:         make(map[string]int),
		failureThreshold: 1,
		probeCooldown:    10 * time.Minute,
	}
}

// OnConnectionFail is called by the proxy when a direct connection fails.
// It tracks failures and triggers block detection when threshold is reached.
// Returns true if the domain was detected as blocked and should be retried with fragmentation.
func (d *Detector) OnConnectionFail(host string, connErr error) bool {
	// Don't probe if already in blocklist
	if d.matcher.IsBlocked(host) {
		return false
	}

	// Extract base domain for tracking
	baseDomain := extractBaseDomain(host)

	// Check cooldown — don't re-probe recently probed domains
	d.probedMu.RLock()
	if lastProbe, ok := d.probed[baseDomain]; ok && time.Since(lastProbe) < d.probeCooldown {
		d.probedMu.RUnlock()
		return false
	}
	d.probedMu.RUnlock()

	// Increment failure count
	d.failuresMu.Lock()
	d.failures[baseDomain]++
	count := d.failures[baseDomain]
	d.failuresMu.Unlock()

	if count < d.failureThreshold {
		return false
	}

	// Threshold reached — probe the domain
	log.Printf("[Sansürsüz] 🔍 Engel tespiti başlatılıyor: %s", baseDomain)

	result := d.Probe(host)

	// Record probe time
	d.probedMu.Lock()
	d.probed[baseDomain] = time.Now()
	d.probedMu.Unlock()

	// Reset failure count
	d.failuresMu.Lock()
	d.failures[baseDomain] = 0
	d.failuresMu.Unlock()

	if result == ResultISPBlocked {
		log.Printf("[Sansürsüz] 🚫 ISP engeli tespit edildi: %s → listeye eklendi", baseDomain)
		d.matcher.AddDomain(baseDomain)
		d.matcher.SaveLearned()
		return true
	}

	if result == ResultUnreachable {
		log.Printf("[Sansürsüz] ⚠️ %s erişilemez (ISP engeli değil)", baseDomain)
	} else {
		log.Printf("[Sansürsüz] ✅ %s erişilebilir (geçici hata olabilir)", baseDomain)
	}

	return false
}

// Probe performs a direct vs fragmented connection test to detect ISP blocking.
// Returns ResultISPBlocked if direct fails but fragmented succeeds.
func (d *Detector) Probe(host string) Result {
	port := "443"
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}

	addr := net.JoinHostPort(host, port)

	// Step 1: Try direct TLS connection
	directOK := d.tryDirectTLS(addr, host)
	if directOK {
		return ResultNotBlocked
	}

	// Step 2: Direct failed → try with fragmented ClientHello
	fragmentedOK := d.tryFragmentedTLS(addr, host)
	if fragmentedOK {
		return ResultISPBlocked
	}

	return ResultUnreachable
}

// tryDirectTLS attempts a normal TLS connection.
func (d *Detector) tryDirectTLS(addr, sni string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// tryFragmentedTLS attempts a TLS connection with SNI fragmentation.
func (d *Detector) tryFragmentedTLS(addr, sni string) bool {
	// Connect TCP
	tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false
	}
	defer tcpConn.Close()

	tcpConn.SetDeadline(time.Now().Add(8 * time.Second))

	// Build a minimal TLS ClientHello
	clientHello := buildMinimalClientHello(sni)

	// Fragment: send first byte separately, then rest
	if _, err := tcpConn.Write(clientHello[:1]); err != nil {
		return false
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := tcpConn.Write(clientHello[1:]); err != nil {
		return false
	}

	// Read ServerHello — if we get any TLS response, the connection worked
	buf := make([]byte, 1024)
	n, err := tcpConn.Read(buf)
	if err != nil {
		return false
	}

	// Check if response starts with TLS record (0x16 = Handshake)
	if n > 0 && buf[0] == 0x16 {
		return true
	}

	return false
}

// buildMinimalClientHello creates a minimal TLS 1.2 ClientHello with the given SNI.
func buildMinimalClientHello(sni string) []byte {
	sniLen := len(sni)

	// SNI extension
	sniExt := make([]byte, 0, 9+sniLen)
	sniExt = append(sniExt, 0x00, 0x00)                                 // Extension type: server_name
	sniExt = append(sniExt, byte((sniLen+5)>>8), byte((sniLen+5)&0xff)) // Extension length
	sniExt = append(sniExt, byte((sniLen+3)>>8), byte((sniLen+3)&0xff)) // Server name list length
	sniExt = append(sniExt, 0x00)                                       // Name type: hostname
	sniExt = append(sniExt, byte(sniLen>>8), byte(sniLen&0xff))         // Name length
	sniExt = append(sniExt, []byte(sni)...)                             // Name

	// Supported versions extension (TLS 1.2, 1.3)
	supVer := []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03}

	extensions := append(sniExt, supVer...)
	extLen := len(extensions)

	// ClientHello body
	hello := make([]byte, 0, 512)
	hello = append(hello, 0x03, 0x03) // Client version: TLS 1.2

	// Random (32 bytes)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 42)
	}
	hello = append(hello, random...)

	hello = append(hello, 0x00) // Session ID length: 0

	// Cipher suites
	ciphers := []byte{
		0x00, 0x04, // Length: 4 (2 suites)
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	}
	hello = append(hello, ciphers...)

	hello = append(hello, 0x01, 0x00) // Compression methods: null

	// Extensions length
	hello = append(hello, byte(extLen>>8), byte(extLen&0xff))
	hello = append(hello, extensions...)

	helloLen := len(hello)

	// Handshake header
	handshake := make([]byte, 0, 4+helloLen)
	handshake = append(handshake, 0x01) // Handshake type: ClientHello
	handshake = append(handshake, byte(helloLen>>16), byte(helloLen>>8), byte(helloLen&0xff))
	handshake = append(handshake, hello...)

	handshakeLen := len(handshake)

	// TLS record header
	record := make([]byte, 0, 5+handshakeLen)
	record = append(record, 0x16)       // Content type: Handshake
	record = append(record, 0x03, 0x01) // Version: TLS 1.0 (compatibility)
	record = append(record, byte(handshakeLen>>8), byte(handshakeLen&0xff))
	record = append(record, handshake...)

	return record
}

// extractBaseDomain extracts the registrable domain from a hostname.
// e.g., "cdn.discord.com" → "discord.com"
func extractBaseDomain(host string) string {
	// Remove port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	parts := splitDomain(host)
	if len(parts) <= 2 {
		return host
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func splitDomain(host string) []string {
	var parts []string
	for host != "" {
		idx := -1
		for i := 0; i < len(host); i++ {
			if host[i] == '.' {
				idx = i
				break
			}
		}
		if idx < 0 {
			parts = append(parts, host)
			break
		}
		parts = append(parts, host[:idx])
		host = host[idx+1:]
	}
	return parts
}

// IsTLSReset checks if an error looks like a TLS/TCP reset (common ISP block signal).
func IsTLSReset(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, pattern := range []string{
		"connection reset",
		"connection refused",
		"broken pipe",
		"i/o timeout",
		"tls: ",
		"EOF",
	} {
		if contains(s, pattern) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
