package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

var (
	ErrVersionNotSupported       = errors.New("protocol version not supported")
	ErrMethodVersionNotSupported = errors.New("sub-negotiation method version not supported")
	ErrCommandNotSupported       = errors.New("request command not supported")
	ErrInvalidReservedField      = errors.New("invalid reverse field")
	ErrAddressTypeNotSupported   = errors.New("address type not supported")
)

const (
	SOCKS5Version = 0x05
	ReservedField = 0x00
)

type Server interface {
	Run() error
}

type SOCKS5Server struct {
	IP     string
	Port   int
	Config *Config
}

type Config struct {
	AuthMethod      Method
	PasswordChecker func(username, password string) bool
}

func initConfig(config *Config) error {
	if config.AuthMethod == MethodPassword && config.PasswordChecker == nil {
		return ErrPasswordCheckerNotSet
	}
	return nil
}

func (s *SOCKS5Server) Run() error {
	// Initialize server configuration
	if err := initConfig(s.Config); err != nil {
		return err
	}

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
			err := handleConnection(conn, s.Config)
			if err != nil {
				log.Printf("handle failure from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConnection(conn net.Conn, config *Config) error {
	if err := auth(conn, config); err != nil {
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

func auth(conn io.ReadWriter, config *Config) error {
	// Read client auth message
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}

	// Check if the auth method is supported
	var acceptable bool
	for _, method := range clientMessage.Methods {
		if method == config.AuthMethod {
			acceptable = true
		}
	}

	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptble)
		return errors.New("method not supported")
	}

	if err := NewServerAuthMessage(conn, config.AuthMethod); err != nil {
		return err
	}

	if config.AuthMethod == MethodPassword {
		clientPasswordMessage, err := NewClientPasswordMessage(conn)
		if err != nil {
			return err
		}
		if !config.PasswordChecker(clientPasswordMessage.Username, clientPasswordMessage.Password) {
			WriteServerPasswordMessage(conn, PasswordAuthFailure)
			return ErrPasswordAuthFailure
		}

		if err = WriteServerPasswordMessage(conn, PasswordAuthSuccess); err != nil {
			return err
		}
	}
	return nil
}
