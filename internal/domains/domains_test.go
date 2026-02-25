package domains

import (
	"testing"
)

func TestMatcher_IsBlocked(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		host     string
		expected bool
	}{
		// Direct matches from turkey.txt
		{"discord.com", true},
		{"roblox.com", true},
		{"pornhub.com", true},

		// Subdomain matches
		{"cdn.discord.com", true},
		{"media.discordapp.com", true},
		{"www.roblox.com", true},
		{"tr.pornhub.com", true},
		{"a.b.c.discord.com", true},

		// Non-blocked sites
		{"google.com", false},
		{"youtube.com", false},
		{"github.com", false},
		{"garanti.com.tr", false},

		// Edge cases
		{"", false},
		{"com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := m.IsBlocked(tt.host)
			if result != tt.expected {
				t.Errorf("IsBlocked(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestMatcher_AddDomain(t *testing.T) {
	m := NewMatcher()

	// Custom domain should not be blocked initially
	if m.IsBlocked("custom-site.example.com") {
		t.Error("custom-site.example.com should not be blocked initially")
	}

	// Add it
	m.AddDomain("example.com")

	// Now it should be blocked
	if !m.IsBlocked("custom-site.example.com") {
		t.Error("custom-site.example.com should be blocked after adding example.com")
	}
	if !m.IsBlocked("example.com") {
		t.Error("example.com should be blocked")
	}
}

func TestMatcher_Count(t *testing.T) {
	m := NewMatcher()

	count := m.Count()
	if count == 0 {
		t.Error("Matcher should have domains loaded from turkey.txt")
	}

	m.AddDomain("new-domain.com")
	if m.Count() != count+1 {
		t.Errorf("Count should be %d after adding 1 domain, got %d", count+1, m.Count())
	}
}

func TestMatcher_CaseInsensitive(t *testing.T) {
	m := NewMatcher()

	if !m.IsBlocked("DISCORD.COM") {
		t.Error("Matching should be case-insensitive")
	}
	if !m.IsBlocked("Discord.Com") {
		t.Error("Matching should be case-insensitive")
	}
}
