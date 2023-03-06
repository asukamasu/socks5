package socks5

import (
	"errors"
	"io"
)

type ClientAuthMessage struct {
	Version byte
	NMethod byte
	Methods []Method
}

func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	// Read version, nMethods
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	// Validate version
	if buf[0] != SOCKS5Version {
		return nil, errors.New("protocol version not supported")
	}
	// Read methods
	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return &ClientAuthMessage{
		Version: SOCKS5Version,
		NMethod: nmethods,
		Methods: buf,
	}, nil
}

func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	return err
}

type Method = byte

const (
	MethodNoAuth      Method = 0x00
	MethodGSSAPI      Method = 0x01
	MethodPassword    Method = 0x02
	MethodNoAcceptble Method = 0xFF
)
