package proxy

import (
	"testing"
)

func TestFragmentFirstByte(t *testing.T) {
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03}

	config := FragmentConfig{Strategy: FragmentFirstByte}
	frags := FragmentClientHello(data, 0, config)

	if len(frags) != 2 {
		t.Fatalf("Expected 2 fragments, got %d", len(frags))
	}

	if len(frags[0]) != 1 {
		t.Errorf("First fragment should be 1 byte, got %d", len(frags[0]))
	}

	if len(frags[1]) != len(data)-1 {
		t.Errorf("Second fragment should be %d bytes, got %d", len(data)-1, len(frags[1]))
	}
}

func TestFragmentBeforeSNI(t *testing.T) {
	data := make([]byte, 100)
	sniOffset := 50

	config := FragmentConfig{Strategy: FragmentBeforeSNI}
	frags := FragmentClientHello(data, sniOffset, config)

	if len(frags) != 2 {
		t.Fatalf("Expected 2 fragments, got %d", len(frags))
	}

	if len(frags[0]) != sniOffset {
		t.Errorf("First fragment should be %d bytes, got %d", sniOffset, len(frags[0]))
	}

	if len(frags[1]) != 100-sniOffset {
		t.Errorf("Second fragment should be %d bytes, got %d", 100-sniOffset, len(frags[1]))
	}
}

func TestFragmentBeforeSNI_InvalidOffset(t *testing.T) {
	data := make([]byte, 100)

	// Invalid offset should fallback to first byte
	config := FragmentConfig{Strategy: FragmentBeforeSNI}
	frags := FragmentClientHello(data, 0, config)

	if len(frags) != 2 {
		t.Fatalf("Expected 2 fragments (fallback), got %d", len(frags))
	}

	if len(frags[0]) != 1 {
		t.Error("Should fallback to first byte fragmentation")
	}
}

func TestFragmentMiddle(t *testing.T) {
	data := make([]byte, 100)

	config := FragmentConfig{Strategy: FragmentMiddle}
	frags := FragmentClientHello(data, 0, config)

	if len(frags) != 2 {
		t.Fatalf("Expected 2 fragments, got %d", len(frags))
	}

	if len(frags[0]) != 50 || len(frags[1]) != 50 {
		t.Errorf("Fragments should be 50+50, got %d+%d", len(frags[0]), len(frags[1]))
	}
}

func TestFragmentChunked(t *testing.T) {
	data := make([]byte, 100)

	config := FragmentConfig{Strategy: FragmentChunked, ChunkSize: 30}
	frags := FragmentClientHello(data, 0, config)

	// 100 / 30 = 3 full chunks + 1 partial (10 bytes)
	if len(frags) != 4 {
		t.Fatalf("Expected 4 fragments, got %d", len(frags))
	}

	totalLen := 0
	for _, f := range frags {
		totalLen += len(f)
	}
	if totalLen != 100 {
		t.Errorf("Total fragment length should be 100, got %d", totalLen)
	}
}

func TestFragmentEmpty(t *testing.T) {
	config := FragmentConfig{Strategy: FragmentFirstByte}
	frags := FragmentClientHello([]byte{}, 0, config)

	if len(frags) != 1 || len(frags[0]) != 0 {
		t.Error("Empty data should return single empty fragment")
	}
}

func TestFragmentSingleByte(t *testing.T) {
	data := []byte{0x16}
	config := FragmentConfig{Strategy: FragmentFirstByte}
	frags := FragmentClientHello(data, 0, config)

	if len(frags) != 1 {
		t.Error("Single byte should return single fragment")
	}
}
