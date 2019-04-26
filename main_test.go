package main

import "testing"

func TestSplitStringParam(t *testing.T) {
	tests := []struct {
		given    string
		expected map[string]bool
	}{
		{given: "Sleeping", expected: map[string]bool{"Sleeping": true}},
		{given: "Sleeping,Zombie", expected: map[string]bool{"Sleeping": true, "Zombie": true}},
		{given: "", expected: map[string]bool{}},
		{given: " Sleeping ", expected: map[string]bool{"Sleeping": true}},
		{given: " Sleeping , Zombie", expected: map[string]bool{"Sleeping": true, "Zombie": true}},
	}

	for _, tt := range tests {
		got := splitStringParam(tt.given)
		if len(got) != len(tt.expected) {
			t.Errorf("wrong length (%d / %d) : splitStringParam(%s) returned   %+v. Expected %+v", len(got), len(tt.expected), tt.given, got, tt.expected)
			continue
		}
		for k, _ := range tt.expected {
			if !got[k] {
				t.Errorf("missing key %s :  splitStringParam(%s) returned %v. Expected %v", k, tt.given, got, tt.expected)
			}
		}
	}

}
