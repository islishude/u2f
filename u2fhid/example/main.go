package main

import (
	"bytes"
	"log"

	"github.com/islishude/u2f/u2fhid"
)

func main() {
	first, err := u2fhid.First()
	if err != nil {
		log.Printf("Get devices error: %s\n", err)
		return
	}

	device, err := u2fhid.Open(first)
	if err != nil {
		log.Printf("open error: %s\n", err)
		return
	}
	defer device.Close()

	log.Printf("Opened %s at %s\n", first.Product, first.Path)

	msg := []byte("echo")
	res, err := device.Ping(msg)
	if err != nil {
		log.Printf("ping error: %s\n", err)
		return
	}

	if !bytes.Equal(res, msg) {
		log.Printf("expected %x, got %x\n", msg, res)
		return
	}

	log.Println("successfully pinged")
}
