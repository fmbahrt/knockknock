package auth

import "testing"

func TestMAC(t *testing.T) {
	var key Key
	for i := range key {
		key[i] = byte(i)
	}
	tag := MAC(key, HostToJoiner, []byte("hello"), []byte("world"))
	if !Verify(key, HostToJoiner, tag[:], []byte("helloworld")) {
		t.Error("MAC over split parts should equal MAC over the concatenation")
	}
	if Verify(key, JoinerToHost, tag[:], []byte("helloworld")) {
		t.Error("direction must change the MAC")
	}
	tag[0] ^= 1
	if Verify(key, HostToJoiner, tag[:], []byte("helloworld")) {
		t.Error("corrupted tag verified")
	}
}

func TestReplayWindow(t *testing.T) {
	var w ReplayWindow
	steps := []struct {
		seq  uint32
		want bool
	}{
		{5, true}, {5, false}, {3, true}, {3, false}, {6, true}, {4, true},
		{100, true}, {36, false}, {37, true}, {37, false}, {99, true}, {200, true}, {100, false},
	}
	for i, s := range steps {
		if got := w.Accept(s.seq); got != s.want {
			t.Errorf("step %d: Accept(%d) = %v, want %v", i, s.seq, got, s.want)
		}
	}
}
