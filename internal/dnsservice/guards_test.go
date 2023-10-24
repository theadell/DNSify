package dnsservice

import (
	"testing"
)

func TestIsValidGuard(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"A/ns1", true},
		{"NS/@", true},
		{"*/ns1", true},
		{"InvalidType/ns1", false},
		{"A/*", false},
		{"A/..", false},
	}

	for _, test := range tests {
		got := isValidGuard(test.input)
		if got != test.expect {
			t.Errorf("isValidGuard(%q) = %v; want %v", test.input, got, test.expect)
		}
	}
}

func TestParseGuardString(t *testing.T) {
	tests := []struct {
		input  string
		zone   string
		expect RecordGuard
		valid  bool
	}{
		{"A/ns1", "example.com.", NewRecordGuard("A", "ns1.example.com."), true},
		{"NS/@", "example.com.", NewRecordGuard("NS", "example.com."), true},
		{"*/ns1", "example.com.", NewRecordGuard("*", "ns1.example.com."), true},
		{"InvalidType/ns1", "example.com.", RecordGuard{}, false},
		{"A/*", "example.com.", RecordGuard{}, false},
	}

	for _, test := range tests {
		got, valid := parseGuardString(test.input, test.zone)
		if valid != test.valid {
			t.Errorf("parseGuardString(%q, %q) valid = %v; want %v", test.input, test.zone, valid, test.valid)
		}
		if got != test.expect {
			t.Errorf("parseGuardString(%q, %q) = %v; want %v", test.input, test.zone, got, test.expect)
		}
	}
}

func TestParseGuards(t *testing.T) {
	guards := RecordGuards{
		Immutable:     []string{"A/ns1", "NS/@"},
		AdminEditable: []string{"*/ns1"},
	}
	expectedImmutable := map[RecordGuard]bool{
		NewRecordGuard("A", "ns1.example.com."): true,
		NewRecordGuard("NS", "example.com."):    true,
	}
	expectedAdminOnly := map[RecordGuard]bool{
		NewRecordGuard("*", "ns1.example.com."): true,
	}

	guardMap := parseGuards(guards, "example.com.")

	if !mapsAreEqual(guardMap.Immutable, expectedImmutable) {
		t.Errorf("Immutable guards = %v; want %v", guardMap.Immutable, expectedImmutable)
	}
	if !mapsAreEqual(guardMap.AdminOnly, expectedAdminOnly) {
		t.Errorf("Admin only guards = %v; want %v", guardMap.AdminOnly, expectedAdminOnly)
	}
}

func mapsAreEqual(a, b map[RecordGuard]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, found := b[key]; !found {
			return false
		}
	}
	return true
}
