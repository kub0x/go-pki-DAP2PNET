package main

import (
	"dap2pnet/server"
	"log"
)

func main() {
	err := server.Initialize()
	if err != nil {
		log.Fatal("cannot initialize server: " + err.Error())
	}
}
