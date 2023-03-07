package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

var (
	ErrVersionNotSupported     = errors.New("protocol version not supported")
	ErrCommandNotSupported     = errors.New("request command not supported")
	ErrInvalidReservedField    = errors.New("invalid reverse field")
	ErrAddressTypeNotSupported = errors.New("address type not supported")
)

const (
	SOCKS5Version = 0x05
	ReservedField = 0x00
)

type Server interface {
	Run() error
}

type SOCKS5Server struct {
	IP   string
	Port int
}

func (s *SOCKS5Server) Run() error {
	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("connect failure from %s: %s", conn.RemoteAddr(), err)
			continue
		}
		go func() {
			defer conn.Close()
			err := handleConnection(conn)
			if err != nil {
				log.Printf("handle failure from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConnection(conn net.Conn) error {
	if err := auth(conn); err != nil {
		return err
	}
	targetConn, err := request(conn)
	if err != nil {
		return err
	}
	return forward(conn, targetConn)
}

func forward(conn io.ReadWriter, targetConn io.ReadWriteCloser) error {
	defer targetConn.Close()
	go io.Copy(targetConn, conn)
	_, err := io.Copy(conn, targetConn)
	return err
}

func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	message, err := NewClientRequestMessage(conn)
	if err != nil {
		return nil, err
	}
	// Check if the command supported
	if message.Cmd != CmdConnect {
		return nil, WriteRequestFailureMessage(conn, ReplyCommandNotSupported)
	}
	// Check if the address type is	supported
	if message.AddrType == IPv6Length {
		return nil, WriteRequestFailureMessage(conn, ReplyAddressTypeNotSupported)
	}

	address := fmt.Sprintf("%s:%d", message.Address, message.Port)
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, WriteRequestFailureMessage(conn, ReplyConnectionRefused)
	}

	// Send success reply
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.TCPAddr)
	return targetConn, WriteRequestSuccessMessage(conn, addr.IP, uint16(addr.Port))
}

func auth(conn net.Conn) error {
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}

	var acceptable bool
	for _, method := range clientMessage.Methods {
		if method == MethodNoAuth {
			acceptable = true
		}
	}

	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptble)
		return errors.New("method not supported")
	}

	return NewServerAuthMessage(conn, MethodNoAuth)
}
