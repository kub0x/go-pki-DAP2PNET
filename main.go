package main

import (
	"dap2pnet/pki/server"
	"log"
)

func main() {
	err := server.Run()
	if err != nil {
		log.Fatal("server gave error: " + err.Error())
	}
}
