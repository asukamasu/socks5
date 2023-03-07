package socks5

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestWriteRequestSuccessMessge(t *testing.T) {
	var buf bytes.Buffer
	ip := net.IP([]byte{123, 123, 123, 123})

	err := WriteRequestSuccessMessage(&buf, ip, 1081)
	if err != nil {
		t.Fatalf("error while writing: %s", err)
	}
	want := []byte{SOCKS5Version, ReplySuccess, ReservedField, TypeIPv4, 123, 123, 123, 123, 0x04, 0x39}
	got := buf.Bytes()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("message not match: want %v, got %v", want, got)
	}
}
