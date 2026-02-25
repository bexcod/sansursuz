package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bexcod/sansursuz/internal/dns"
	"github.com/bexcod/sansursuz/internal/domains"
	tlsparser "github.com/bexcod/sansursuz/internal/tls"
)

// Server is the local HTTP/CONNECT proxy that applies DPI circumvention.
type Server struct {
	port       int
	mode       string // "selective" or "all"
	resolver   *dns.Resolver
	matcher    *domains.Matcher
	fragConfig FragmentConfig
	listener   net.Listener
	running    bool
	mu         sync.Mutex
	connPool   *ConnPool

	totalConns      atomic.Int64
	activeConns     atomic.Int64
	fragmentedConns atomic.Int64
	directConns     atomic.Int64
	detectedConns   atomic.Int64
}

// NewServer creates a new proxy server.
func NewServer(port int, mode string, resolver *dns.Resolver, matcher *domains.Matcher, fragConfig FragmentConfig) *Server {
	return &Server{
		port:       port,
		mode:       mode,
		resolver:   resolver,
		matcher:    matcher,
		fragConfig: fragConfig,
		connPool:   NewConnPool(60*time.Second, 100),
	}
}

// Start starts the proxy server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("proxy already running")
	}

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener
	s.running = true
	s.mu.Unlock()

	log.Printf("[Sansürsüz] Proxy dinleniyor: %s (mod: %s)", addr, s.mode)

	go s.connPool.CleanupLoop(ctx)

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			running := s.running
			s.mu.Unlock()
			if !running {
				return nil
			}
			log.Printf("[Sansürsüz] Accept hatası: %v", err)
			continue
		}

		s.totalConns.Add(1)
		s.activeConns.Add(1)

		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[Sansürsüz] PANIC kurtarıldı: %v", r)
				}
				s.activeConns.Add(-1)
			}()
			s.handleConnection(conn)
		}()
	}
}

// Stop stops the proxy server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}
	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
	s.connPool.CloseAll()
	log.Printf("[Sansürsüz] Proxy durduruldu")
}

// IsRunning returns whether the proxy is currently running.
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// handleConnection processes a single client connection.
func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 8192)
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	data := buf[:n]
	reqStr := string(data)

	if strings.HasPrefix(reqStr, "CONNECT ") {
		s.handleCONNECT(clientConn, reqStr)
		return
	}

	if isHTTPRequest(reqStr) {
		s.handleHTTP(clientConn, data)
		return
	}
}

// handleCONNECT handles HTTPS CONNECT tunnel requests.
func (s *Server) handleCONNECT(clientConn net.Conn, request string) {
	lines := strings.SplitN(request, "\r\n", 2)
	if len(lines) == 0 {
		return
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return
	}

	hostPort := parts[1]
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		port = "443"
	}

	shouldFragment := s.shouldProxy(host)

	targetAddr, err := s.resolveHost(host, port)
	if err != nil {
		log.Printf("[Sansürsüz] DNS çözümlenemedi %s: %v", host, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// TCP connect to target
	serverConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[Sansürsüz] Bağlantı hatası %s: %v", targetAddr, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	// Send 200 Connection Established
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	if shouldFragment {
		// Known blocked domain → always fragment
		s.handleTLSWithFragmentation(clientConn, serverConn, host)
	} else if s.mode == "selective" {
		// Unknown domain → try direct, detect if blocked at TLS/SNI level
		s.handleTLSWithDetection(clientConn, serverConn, host, targetAddr)
	} else {
		// "all" mode but somehow not shouldFragment — just fragment anyway
		s.handleTLSWithFragmentation(clientConn, serverConn, host)
	}
}

// handleTLSWithDetection tries sending ClientHello unfragmented first.
// If the server doesn't respond (ISP blocks SNI), it retries with fragmentation.
// If fragmented works → domain is ISP-blocked → auto-add to blocklist.
func (s *Server) handleTLSWithDetection(clientConn, serverConn net.Conn, host, targetAddr string) {
	// Read ClientHello from client
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 16384)
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	clientHello := buf[:n]

	// Check if it's actually a TLS ClientHello
	if !tlsparser.IsTLSClientHello(clientHello) {
		// Not TLS, just forward and tunnel
		serverConn.Write(clientHello)
		s.directConns.Add(1)
		bidirectionalCopy(clientConn, serverConn)
		return
	}

	// Step 1: Send ClientHello UNFRAGMENTED to server
	if _, err := serverConn.Write(clientHello); err != nil {
		return
	}

	// Step 2: Wait for ServerHello with a short timeout
	serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	responseBuf := make([]byte, 16384)
	rn, readErr := serverConn.Read(responseBuf)
	serverConn.SetReadDeadline(time.Time{})

	if readErr == nil && rn > 0 && responseBuf[0] == 0x16 {
		// Got a valid TLS ServerHello → NOT blocked!
		// Forward ServerHello to client and continue normally
		clientConn.Write(responseBuf[:rn])
		s.directConns.Add(1)
		bidirectionalCopy(clientConn, serverConn)
		return
	}

	// Step 3: Direct failed! ISP likely blocked the SNI.
	// Close old connection, try with fragmentation on a new one.
	serverConn.Close()

	log.Printf("[Sansürsüz] 🔍 %s: düz TLS başarısız, fragmentlı deneniyor...", host)

	newServerConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[Sansürsüz] ⚠️ %s: yeni TCP bağlantısı başarısız", host)
		return
	}
	defer newServerConn.Close()

	// Parse SNI offset for targeted fragmentation
	sniOffset := 0
	info, parseErr := tlsparser.ParseClientHello(clientHello)
	if parseErr == nil {
		sniOffset = info.SNIOffset
	}

	// Send ClientHello FRAGMENTED
	fragments := FragmentClientHello(clientHello, sniOffset, s.fragConfig)
	if err := SendFragmented(newServerConn, fragments); err != nil {
		log.Printf("[Sansürsüz] ⚠️ %s: fragmentlı gönderim başarısız", host)
		return
	}

	// Wait for ServerHello
	newServerConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	rn, readErr = newServerConn.Read(responseBuf)
	newServerConn.SetReadDeadline(time.Time{})

	if readErr != nil || rn == 0 {
		// Both direct and fragmented failed → genuinely unreachable
		log.Printf("[Sansürsüz] ⚠️ %s: hem düz hem fragmentlı başarısız — site erişilemez", host)
		return
	}

	// Fragmented worked! → ISP block confirmed!
	baseDomain := extractBaseDomain(host)
	log.Printf("[Sansürsüz] 🚫 ISP engeli tespit edildi: %s → listeye eklendi!", baseDomain)

	s.matcher.AddDomain(baseDomain)
	s.matcher.SaveLearned()
	s.fragmentedConns.Add(1)
	s.detectedConns.Add(1)

	// Forward ServerHello to client
	clientConn.Write(responseBuf[:rn])

	// Continue tunneling on the new fragmented connection
	bidirectionalCopy(clientConn, newServerConn)
}

// handleTLSWithFragmentation always fragments the ClientHello (for known blocked domains).
func (s *Server) handleTLSWithFragmentation(clientConn, serverConn net.Conn, host string) {
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 16384)
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	data := buf[:n]

	if tlsparser.IsTLSClientHello(data) {
		info, parseErr := tlsparser.ParseClientHello(data)
		sniOffset := 0
		if parseErr == nil {
			sniOffset = info.SNIOffset
			log.Printf("[Sansürsüz] ✂ SNI parçalandı: %s", info.SNI)
		} else {
			log.Printf("[Sansürsüz] ✂ TLS parçalandı: %s (SNI okunamadı)", host)
		}

		fragments := FragmentClientHello(data, sniOffset, s.fragConfig)
		if err := SendFragmented(serverConn, fragments); err != nil {
			return
		}

		s.fragmentedConns.Add(1)
	} else {
		if _, err := serverConn.Write(data); err != nil {
			return
		}
	}

	bidirectionalCopy(clientConn, serverConn)
}

// handleHTTP handles plain HTTP requests.
func (s *Server) handleHTTP(clientConn net.Conn, data []byte) {
	host := extractHTTPHost(string(data))
	if host == "" {
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	port := "80"
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}

	targetAddr, err := s.resolveHost(host, port)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	serverConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	if _, err := serverConn.Write(data); err != nil {
		return
	}

	s.directConns.Add(1)
	bidirectionalCopy(clientConn, serverConn)
}

// shouldProxy checks if a host should go through DPI circumvention.
func (s *Server) shouldProxy(host string) bool {
	if s.mode == "all" {
		return true
	}
	return s.matcher.IsBlocked(host)
}

// resolveHost resolves a hostname to an address string.
func (s *Server) resolveHost(host, port string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, port), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := s.resolver.Resolve(ctx, host)
	if err == nil && len(ips) > 0 {
		return net.JoinHostPort(ips[0].String(), port), nil
	}

	// Fallback to system DNS
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("DNS çözümlenemedi: %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("DNS sonuç yok: %s", host)
	}

	return net.JoinHostPort(addrs[0], port), nil
}

// bidirectionalCopy copies data between two connections in both directions.
func bidirectionalCopy(conn1, conn2 net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(conn2, conn1)
		if tc, ok := conn2.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		io.Copy(conn1, conn2)
		if tc, ok := conn1.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
}

// extractBaseDomain extracts the registrable base domain.
// e.g., "cdn.discord.com" → "discord.com"
func extractBaseDomain(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func extractHTTPHost(request string) string {
	lines := strings.Split(request, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

func isHTTPRequest(data string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}
	for _, m := range methods {
		if strings.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

// Port returns the proxy's listening port.
func (s *Server) Port() int {
	return s.port
}

// Stats returns a human-readable stats summary.
func (s *Server) Stats() string {
	return fmt.Sprintf("toplam=%d aktif=%d fragment=%d direkt=%d tespit=%d",
		s.totalConns.Load(), s.activeConns.Load(),
		s.fragmentedConns.Load(), s.directConns.Load(),
		s.detectedConns.Load())
}

// FragConfig returns the current fragmentation configuration.
func (s *Server) FragConfig() FragmentConfig {
	return s.fragConfig
}

// SetFragConfig updates the fragmentation configuration.
func (s *Server) SetFragConfig(fc FragmentConfig) {
	s.mu.Lock()
	s.fragConfig = fc
	s.mu.Unlock()
}

// AutoDetectStrategy tries each fragmentation mode against test domains.
// Returns the first mode that successfully connects, or "standard" as fallback.
func AutoDetectStrategy(resolver *dns.Resolver) FragmentMode {
	testDomains := []string{"discord.com", "twitter.com"}
	modes := AllFragmentModes()

	for _, mode := range modes {
		cfg := ConfigForMode(mode)
		success := true

		for _, domain := range testDomains {
			if !testFragmentConnection(resolver, domain, cfg) {
				success = false
				break
			}
		}

		if success {
			log.Printf("[Sansürsüz] ✅ Otomatik mod tespiti: %s çalışıyor", mode)
			return mode
		}
		log.Printf("[Sansürsüz] ❌ %s modu başarısız, sonraki deneniyor...", mode)
	}

	log.Println("[Sansürsüz] ⚠️ Hiçbir mod onaylanamadı, standart kullanılıyor")
	return FragmentModeStandard
}

// testFragmentConnection tests if a specific fragmentation config can connect to a domain.
func testFragmentConnection(resolver *dns.Resolver, domain string, cfg FragmentConfig) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := resolver.Resolve(ctx, domain)
	if err != nil || len(ips) == 0 {
		return false
	}

	addr := net.JoinHostPort(ips[0].String(), "443")
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Build a minimal TLS ClientHello with the test domain
	clientHello := buildTestClientHello(domain)
	if clientHello == nil {
		return false
	}

	sniOffset := findSNIOffset(clientHello, domain)
	fragments := FragmentClientHello(clientHello, sniOffset, cfg)

	if err := SendFragmented(conn, fragments); err != nil {
		return false
	}

	// Read response with timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return false
	}

	// Check if we got a TLS ServerHello (content type 0x16, version 0x03xx)
	return buf[0] == 0x16 && buf[1] == 0x03
}

// buildTestClientHello creates a minimal TLS 1.2 ClientHello for testing.
func buildTestClientHello(domain string) []byte {
	domainBytes := []byte(domain)
	domainLen := len(domainBytes)

	// SNI extension
	sniExt := []byte{
		0x00, 0x00, // SNI extension type
	}
	sniListLen := domainLen + 5
	sniExtLen := sniListLen + 2
	sniExt = append(sniExt, byte(sniExtLen>>8), byte(sniExtLen))
	sniExt = append(sniExt, byte(sniListLen>>8), byte(sniListLen))
	sniExt = append(sniExt, 0x00) // Host name type
	sniExt = append(sniExt, byte(domainLen>>8), byte(domainLen))
	sniExt = append(sniExt, domainBytes...)

	// Cipher suites (TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	cipherSuites := []byte{
		0x00, 0x04, // Length
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	}

	// Extensions length
	extLen := len(sniExt)

	// ClientHello body
	body := []byte{0x03, 0x03} // TLS 1.2
	// Random (32 bytes)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}
	body = append(body, random...)
	body = append(body, 0x00) // Session ID length
	body = append(body, cipherSuites...)
	body = append(body, 0x01, 0x00) // Compression methods
	body = append(body, byte(extLen>>8), byte(extLen))
	body = append(body, sniExt...)

	// Handshake header
	handshake := []byte{0x01} // ClientHello
	bodyLen := len(body)
	handshake = append(handshake, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	handshake = append(handshake, body...)

	// TLS record header
	record := []byte{0x16, 0x03, 0x01} // Handshake, TLS 1.0
	hsLen := len(handshake)
	record = append(record, byte(hsLen>>8), byte(hsLen))
	record = append(record, handshake...)

	return record
}

// findSNIOffset finds the byte offset of the SNI domain in a ClientHello.
func findSNIOffset(data []byte, domain string) int {
	domainBytes := []byte(domain)
	for i := 0; i <= len(data)-len(domainBytes); i++ {
		match := true
		for j := 0; j < len(domainBytes); j++ {
			if data[i+j] != domainBytes[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return len(data) / 2
}

// DiagnoseResult holds the result of a connection test.
type DiagnoseResult struct {
	Domain  string `json:"domain"`
	DNS     string `json:"dns"`
	TLS     string `json:"tls"`
	Latency string `json:"latency"`
}

// DiagnoseConnection runs diagnostic tests.
func DiagnoseConnection(resolver *dns.Resolver, domains []string) []DiagnoseResult {
	var results []DiagnoseResult

	for _, domain := range domains {
		result := DiagnoseResult{Domain: domain}
		start := time.Now()

		// Test DNS
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := resolver.Resolve(ctx, domain)
		cancel()

		if err != nil {
			result.DNS = "❌ " + err.Error()
			result.TLS = "⏭️ DNS başarısız"
			results = append(results, result)
			continue
		}
		result.DNS = fmt.Sprintf("✅ %s", ips[0].String())

		// Test TLS connection
		addr := net.JoinHostPort(ips[0].String(), "443")
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			result.TLS = "❌ Bağlanamadı"
			results = append(results, result)
			continue
		}
		conn.Close()
		result.TLS = "✅ Bağlantı başarılı"
		result.Latency = fmt.Sprintf("%dms", time.Since(start).Milliseconds())

		results = append(results, result)
	}

	return results
}
