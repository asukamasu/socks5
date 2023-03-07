package main

import (
	"log"

	"github.com/asukamasu/socks5"
)

func main() {
	users := map[string]string{
		"admin":    "123456",
		"zhangsan": "1234",
		"lisi":     "abde",
	}

	server := socks5.SOCKS5Server{
		IP:   "172.19.64.1",
		Port: 1080,
		Config: &socks5.Config{
			AuthMethod: socks5.MethodPassword,
			PasswordChecker: func(username, password string) bool {
				wantpassword, ok := users[username]
				if !ok {
					return false
				}
				return wantpassword == password
			},
		},
	}

	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}
