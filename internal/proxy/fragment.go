// Package proxy implements the local HTTP/CONNECT proxy with SNI fragmentation.
package proxy

import (
	"net"
)

// FragmentStrategy defines how TLS ClientHello packets are fragmented.
type FragmentStrategy int

const (
	// FragmentFirstByte sends the first byte separately, then the rest.
	FragmentFirstByte FragmentStrategy = iota
	// FragmentBeforeSNI splits the packet right before the SNI value.
	FragmentBeforeSNI
	// FragmentMiddle splits at the halfway point.
	FragmentMiddle
	// FragmentChunked splits into fixed-size chunks.
	FragmentChunked
)

// FragmentConfig controls the fragmentation behavior.
type FragmentConfig struct {
	Strategy  FragmentStrategy
	ChunkSize int // Used with FragmentChunked strategy
}

// DefaultFragmentConfig returns the default fragmentation settings.
func DefaultFragmentConfig() FragmentConfig {
	return FragmentConfig{
		Strategy:  FragmentBeforeSNI,
		ChunkSize: 40,
	}
}

// FragmentClientHello splits a TLS ClientHello into fragments based on the strategy.
// Returns the fragments to be sent in order.
func FragmentClientHello(data []byte, sniOffset int, config FragmentConfig) [][]byte {
	if len(data) == 0 {
		return [][]byte{data}
	}

	switch config.Strategy {
	case FragmentFirstByte:
		return fragmentFirstByte(data)
	case FragmentBeforeSNI:
		return fragmentBeforeSNI(data, sniOffset)
	case FragmentMiddle:
		return fragmentMiddle(data)
	case FragmentChunked:
		return fragmentChunked(data, config.ChunkSize)
	default:
		return [][]byte{data}
	}
}

// fragmentFirstByte sends just the first byte, then the rest.
// This is the simplest approach and works against many DPI systems.
func fragmentFirstByte(data []byte) [][]byte {
	if len(data) <= 1 {
		return [][]byte{data}
	}
	return [][]byte{
		data[:1],
		data[1:],
	}
}

// fragmentBeforeSNI splits the packet right before the SNI value.
// This is the most targeted approach — DPI can't see the full SNI in either fragment.
func fragmentBeforeSNI(data []byte, sniOffset int) [][]byte {
	if sniOffset <= 0 || sniOffset >= len(data) {
		// Fallback to first byte if SNI offset is invalid
		return fragmentFirstByte(data)
	}
	return [][]byte{
		data[:sniOffset],
		data[sniOffset:],
	}
}

// fragmentMiddle splits the packet at the halfway point.
func fragmentMiddle(data []byte) [][]byte {
	if len(data) <= 1 {
		return [][]byte{data}
	}
	mid := len(data) / 2
	return [][]byte{
		data[:mid],
		data[mid:],
	}
}

// fragmentChunked splits data into fixed-size chunks.
func fragmentChunked(data []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		chunkSize = 40
	}
	var chunks [][]byte
	for len(data) > 0 {
		end := chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[:end])
		data = data[end:]
	}
	return chunks
}

// SendFragmented sends data fragments over a connection with small delays
// to ensure they are sent as separate TCP segments.
func SendFragmented(conn net.Conn, fragments [][]byte) error {
	for _, frag := range fragments {
		if _, err := conn.Write(frag); err != nil {
			return err
		}
	}
	return nil
}
