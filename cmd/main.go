package main

import (
	"log"

	"github.com/asukamasu/socks5"
)

func main() {
	server := socks5.SOCKS5Server{
		IP:   "localhost",
		Port: 1080,
	}

	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}