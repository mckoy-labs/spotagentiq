package main

import "testing"

func TestLoopbackOnly(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8484": true, "localhost:8484": true, "[::1]:8484": true,
		":8484": false, "0.0.0.0:8484": false, "192.168.1.5:8484": false, "[::]:8484": false, "nonsense": false,
	} {
		if got := loopbackOnly(addr); got != want {
			t.Errorf("loopbackOnly(%q) = %v, want %v", addr, got, want)
		}
	}
}
