package socks5

import (
	"errors"
	"fmt"
	"log"
	"net"
)

const SOCKS5Version = 0x05

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
	return nil
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
