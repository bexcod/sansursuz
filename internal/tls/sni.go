// Package tls provides TLS ClientHello parsing utilities for SNI extraction.
package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrNotTLS         = errors.New("not a TLS record")
	ErrNotClientHello = errors.New("not a ClientHello message")
	ErrSNINotFound    = errors.New("SNI extension not found")
	ErrTruncated      = errors.New("packet truncated")
)

// ClientHelloInfo contains parsed information from a TLS ClientHello message.
type ClientHelloInfo struct {
	SNI           string // Server Name Indication hostname
	SNIOffset     int    // Byte offset of SNI value within the raw packet
	SNILength     int    // Length of the SNI value
	RecordLength  int    // Total TLS record length
}

// ParseClientHello parses a TLS ClientHello message and extracts the SNI.
// Returns ClientHelloInfo with the SNI hostname and its position in the packet.
func ParseClientHello(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 5 {
		return nil, ErrTruncated
	}

	// Check TLS record header: ContentType=Handshake(0x16), Version=TLS 1.x
	if data[0] != 0x16 {
		return nil, ErrNotTLS
	}
	if data[1] != 0x03 || (data[2] != 0x01 && data[2] != 0x03) {
		return nil, fmt.Errorf("%w: version %d.%d", ErrNotTLS, data[1], data[2])
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		// We might have a partial packet, that's OK for our purposes
		// as long as we have enough to find SNI
		recordLen = len(data) - 5
	}

	info := &ClientHelloInfo{
		RecordLength: recordLen + 5,
	}

	// Parse handshake message
	pos := 5
	if pos >= len(data) {
		return nil, ErrTruncated
	}

	// HandshakeType: ClientHello = 0x01
	if data[pos] != 0x01 {
		return nil, ErrNotClientHello
	}
	pos++

	// Handshake length (3 bytes)
	if pos+3 > len(data) {
		return nil, ErrTruncated
	}
	pos += 3 // skip handshake length

	// Client version (2 bytes)
	if pos+2 > len(data) {
		return nil, ErrTruncated
	}
	pos += 2

	// Client random (32 bytes)
	if pos+32 > len(data) {
		return nil, ErrTruncated
	}
	pos += 32

	// Session ID
	if pos+1 > len(data) {
		return nil, ErrTruncated
	}
	sessionIDLen := int(data[pos])
	pos++
	if pos+sessionIDLen > len(data) {
		return nil, ErrTruncated
	}
	pos += sessionIDLen

	// Cipher suites
	if pos+2 > len(data) {
		return nil, ErrTruncated
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+cipherSuitesLen > len(data) {
		return nil, ErrTruncated
	}
	pos += cipherSuitesLen

	// Compression methods
	if pos+1 > len(data) {
		return nil, ErrTruncated
	}
	compMethodsLen := int(data[pos])
	pos++
	if pos+compMethodsLen > len(data) {
		return nil, ErrTruncated
	}
	pos += compMethodsLen

	// Extensions
	if pos+2 > len(data) {
		return nil, ErrSNINotFound
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Iterate through extensions to find SNI (type 0x0000)
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))

		if extType == 0x0000 { // server_name extension
			return parseSNIExtension(data, pos+4, extLen, info)
		}

		pos += 4 + extLen
	}

	return nil, ErrSNINotFound
}

// parseSNIExtension parses the SNI extension value.
func parseSNIExtension(data []byte, offset, length int, info *ClientHelloInfo) (*ClientHelloInfo, error) {
	pos := offset

	if pos+2 > len(data) {
		return nil, ErrTruncated
	}
	// Server name list length
	pos += 2

	if pos+1 > len(data) {
		return nil, ErrTruncated
	}
	// Server name type (should be 0x00 for hostname)
	nameType := data[pos]
	pos++

	if nameType != 0x00 {
		return nil, ErrSNINotFound
	}

	if pos+2 > len(data) {
		return nil, ErrTruncated
	}
	nameLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+nameLen > len(data) {
		return nil, ErrTruncated
	}

	info.SNI = string(data[pos : pos+nameLen])
	info.SNIOffset = pos
	info.SNILength = nameLen

	return info, nil
}

// IsTLSClientHello checks if the data starts with a TLS ClientHello.
// A quick check without full parsing — useful for fast filtering.
func IsTLSClientHello(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	// ContentType=Handshake(0x16), Version=TLS 1.x, HandshakeType=ClientHello(0x01)
	return data[0] == 0x16 &&
		data[1] == 0x03 &&
		(data[2] == 0x01 || data[2] == 0x03) &&
		data[5] == 0x01
}
