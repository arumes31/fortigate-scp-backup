package auth

import (
	"slices"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// TestRadiusGroupsCollectsFilterIDAndClass covers the attributes used for role
// mapping.
func TestRadiusGroupsCollectsFilterIDAndClass(t *testing.T) {
	packet := radius.New(radius.CodeAccessAccept, []byte("shared-secret-0123456789"))
	if err := rfc2865.FilterID_AddString(packet, "fortisafe-ops"); err != nil {
		t.Fatal(err)
	}
	if err := rfc2865.Class_AddString(packet, "fortisafe-users"); err != nil {
		t.Fatal(err)
	}
	groups := radiusGroups(packet)
	if !slices.Contains(groups, "fortisafe-ops") || !slices.Contains(groups, "fortisafe-users") {
		t.Fatalf("radiusGroups() = %v, want Filter-Id and Class values", groups)
	}
	if got := radiusGroups(radius.New(radius.CodeAccessAccept, []byte("shared-secret-0123456789"))); len(got) != 0 {
		t.Fatalf("radiusGroups() without attributes = %v, want none", got)
	}
}
