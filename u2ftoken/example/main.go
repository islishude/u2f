package main

import (
	"crypto/rand"
	"log"
	"time"

	"github.com/islishude/u2f/u2fhid"
	"github.com/islishude/u2f/u2ftoken"
)

func register(app []byte) error {
	first, err := u2fhid.First()
	if err != nil {
		return err
	}
	log.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x\n", first.Manufacturer, first.Product, first.ProductID, first.VendorID)

	dev, err := u2fhid.Open(first)
	if err != nil {
		return err
	}
	defer dev.Close()

	token := u2ftoken.NewToken(dev)
	version, err := token.Version()
	if err != nil {
		return err
	}
	log.Println("version:", version)

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}

	var res []byte
	log.Println("registering, provide user presence")
	for {
		res, err = token.Register(u2ftoken.RegisterRequest{Challenge: challenge, Application: app})
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			return err
		}
		break
	}

	log.Printf("registered: %x\n", res)
	res = res[66:]
	khLen := int(res[0])
	res = res[1:]
	keyHandle := res[:khLen]
	log.Printf("key handle: %x\n", keyHandle)
	return nil
}

func login(app, keyHandle []byte) error {
	first, err := u2fhid.First()
	if err != nil {
		return nil
	}
	dev, err := u2fhid.Open(first)
	if err != nil {
		return err
	}
	defer dev.Close()

	token := u2ftoken.NewToken(dev)
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	req := u2ftoken.AuthenticateRequest{
		Challenge:   challenge,
		Application: app,
		KeyHandle:   keyHandle,
	}
	if err := token.CheckAuthenticate(req); err != nil {
		return err
	}

	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	log.Println("authenticating, provide user presence")
	for {
		res, err := token.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			return err
		}
		log.Printf("counter = %d, signature = %x", res.Counter, res.Signature)
		break
	}

	if dev.CapabilityWink {
		log.Println("testing wink in 2s...")
		time.Sleep(2 * time.Second)
		if err := dev.Wink(); err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
	}
	log.Println("no wink capability")
	return nil
}

func main() {
	_ = register(nil)
	_ = login(nil, nil)
}
