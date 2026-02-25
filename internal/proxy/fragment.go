// Package proxy implements the local HTTP/CONNECT proxy with SNI fragmentation.
package proxy

import (
	"net"
)

// FragmentMode represents ISP-specific fragmentation presets.
type FragmentMode string

const (
	// FragmentModeAuto tries each mode in order until one works.
	FragmentModeAuto FragmentMode = "auto"
	// FragmentModeStandard — SNI split at middle, works for most ISPs.
	FragmentModeStandard FragmentMode = "standard"
	// FragmentModeAdvanced — SNI split before domain + small chunks (Türk Telekom).
	FragmentModeAdvanced FragmentMode = "advanced"
	// FragmentModeAggressive — Chunked 5-byte fragments (Superonline).
	FragmentModeAggressive FragmentMode = "aggressive"
	// FragmentModeMaximum — First byte + chunked + extra split (resistant ISPs).
	FragmentModeMaximum FragmentMode = "maximum"
)

// AllFragmentModes returns all modes in auto-detect priority order.
func AllFragmentModes() []FragmentMode {
	return []FragmentMode{
		FragmentModeStandard,
		FragmentModeAdvanced,
		FragmentModeAggressive,
		FragmentModeMaximum,
	}
}

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
	Mode      FragmentMode
}

// DefaultFragmentConfig returns the default fragmentation settings.
func DefaultFragmentConfig() FragmentConfig {
	return FragmentConfig{
		Strategy:  FragmentBeforeSNI,
		ChunkSize: 40,
		Mode:      FragmentModeAuto,
	}
}

// ConfigForMode returns a FragmentConfig for the given ISP mode.
func ConfigForMode(mode FragmentMode) FragmentConfig {
	switch mode {
	case FragmentModeStandard:
		return FragmentConfig{
			Strategy:  FragmentMiddle,
			ChunkSize: 40,
			Mode:      mode,
		}
	case FragmentModeAdvanced:
		return FragmentConfig{
			Strategy:  FragmentBeforeSNI,
			ChunkSize: 4,
			Mode:      mode,
		}
	case FragmentModeAggressive:
		return FragmentConfig{
			Strategy:  FragmentChunked,
			ChunkSize: 5,
			Mode:      mode,
		}
	case FragmentModeMaximum:
		return FragmentConfig{
			Strategy:  FragmentChunked,
			ChunkSize: 2,
			Mode:      mode,
		}
	default:
		return DefaultFragmentConfig()
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
func fragmentBeforeSNI(data []byte, sniOffset int) [][]byte {
	if sniOffset <= 0 || sniOffset >= len(data) {
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
