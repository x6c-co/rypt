package rypt

import (
	"encoding/json"
	"testing"
)

func TestPatchJSON(t *testing.T) {
	cases := []struct {
		name   string
		params UpdateAPITokenParams
		want   string
	}{
		{"zero leaves everything", UpdateAPITokenParams{}, `{}`},
		{"set firewall", UpdateAPITokenParams{FirewallID: Set(firewallID)}, `{"firewall_id":"` + firewallID + `"}`},
		{"clear firewall and keys", UpdateAPITokenParams{FirewallID: Clear[string](), KeyIDs: Clear[[]string]()}, `{"firewall_id":null,"key_ids":null}`},
		{"set keys", UpdateAPITokenParams{KeyIDs: Set([]string{keyID})}, `{"key_ids":["` + keyID + `"]}`},
		// A nil slice must never clear a restriction by accident.
		{"set nil keys", UpdateAPITokenParams{KeyIDs: Set[[]string](nil)}, `{"key_ids":[]}`},
		{"set no actions", UpdateAPITokenParams{AllowedActions: Set([]Action{})}, `{"allowed_actions":[]}`},
		{"set nil actions", UpdateAPITokenParams{AllowedActions: Set[[]Action](nil)}, `{"allowed_actions":[]}`},
		{"set actions", UpdateAPITokenParams{AllowedActions: Set([]Action{ActionRead, ActionWrap})}, `{"allowed_actions":["read","wrap"]}`},
	}
	for _, tc := range cases {
		got, err := json.Marshal(tc.params)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(got) != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestPatchAccessors(t *testing.T) {
	var keep Patch[string]
	if v, ok := keep.Value(); ok || v != "" || keep.IsClear() || !keep.IsZero() {
		t.Error("the zero Patch is not a keep")
	}
	set := Set("x")
	if v, ok := set.Value(); !ok || v != "x" || set.IsClear() || set.IsZero() {
		t.Error("Set is not a set")
	}
	clr := Clear[string]()
	if _, ok := clr.Value(); ok || !clr.IsClear() || clr.IsZero() {
		t.Error("Clear is not a clear")
	}
	if b, _ := json.Marshal(Set(map[string]int(nil))); string(b) != "null" {
		t.Errorf("a nil map encodes as %s; only slices become []", b)
	}
	if b, _ := json.Marshal(Set[any](nil)); string(b) != "null" {
		t.Errorf("a nil interface encodes as %s", b)
	}
}
