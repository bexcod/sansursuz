package proxy

import (
	"context"
	"net"
	"sync"
	"time"
)

// ConnPool is a simple TCP connection pool that reuses idle connections.
// This avoids the overhead of TCP handshake + TLS negotiation for
// repeated connections to the same server.
type ConnPool struct {
	mu       sync.Mutex
	conns    map[string][]poolConn
	maxIdle  int
	idleTime time.Duration
}

type poolConn struct {
	conn      net.Conn
	createdAt time.Time
}

// NewConnPool creates a new connection pool.
func NewConnPool(idleTime time.Duration, maxIdle int) *ConnPool {
	return &ConnPool{
		conns:    make(map[string][]poolConn),
		maxIdle:  maxIdle,
		idleTime: idleTime,
	}
}

// Get retrieves an idle connection for the given address, or nil if none available.
func (p *ConnPool) Get(addr string) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	conns, ok := p.conns[addr]
	if !ok || len(conns) == 0 {
		return nil
	}

	// Take the most recent connection (LIFO — more likely to still be alive)
	pc := conns[len(conns)-1]
	p.conns[addr] = conns[:len(conns)-1]

	// Check if it's too old
	if time.Since(pc.createdAt) > p.idleTime {
		pc.conn.Close()
		return nil
	}

	return pc.conn
}

// Put returns a connection to the pool for reuse.
func (p *ConnPool) Put(addr string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	conns := p.conns[addr]
	if len(conns) >= p.maxIdle {
		conn.Close()
		return
	}

	p.conns[addr] = append(conns, poolConn{
		conn:      conn,
		createdAt: time.Now(),
	})
}

// CleanupLoop periodically removes expired connections.
func (p *ConnPool) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.cleanup()
		}
	}
}

func (p *ConnPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for addr, conns := range p.conns {
		var alive []poolConn
		for _, pc := range conns {
			if now.Sub(pc.createdAt) > p.idleTime {
				pc.conn.Close()
			} else {
				alive = append(alive, pc)
			}
		}
		if len(alive) > 0 {
			p.conns[addr] = alive
		} else {
			delete(p.conns, addr)
		}
	}
}

// CloseAll closes all pooled connections.
func (p *ConnPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, conns := range p.conns {
		for _, pc := range conns {
			pc.conn.Close()
		}
		delete(p.conns, addr)
	}
}

// Size returns the total number of pooled connections.
func (p *ConnPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, conns := range p.conns {
		total += len(conns)
	}
	return total
}
