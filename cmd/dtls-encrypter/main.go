package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/pion/dtls"
	"github.com/pion/dtls/examples/util"
)

func main() {

	/*
	   Prepare our listener. It receives filtered data from loopback on a given port
	   This is the connection from which we read UDP data that is desired to be encrypted
	*/

	// Read the first argument, the port on which we should listen for UPD data
	portIn, _ := strconv.Atoi(os.Args[1])
	// Our address to listen to is 127.0.0.1, the address of the loopback device
	addrIn := net.UDPAddr{
		Port: portIn,
		IP:   net.ParseIP("127.0.0.1"),
	}
	// Get a socket
	connIn, err := net.ListenUDP("udp", &addrIn)
	// Error checking
	if err != nil {
		panic(err)
	}
	// Close our socket on exit
	defer connIn.Close()

	/*
	   Certificate handling and DTLS setup
	*/

	// Generate a certificate and private key to secure the outgoing connection
	certificate, privKey, err := dtls.GenerateSelfSigned()
	// Error checking
	if err != nil {
		panic(err)
	}

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificate:          certificate,
		PrivateKey:           privKey,
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	// Prepare the end point to connect to, it will receive encrypted and filtere IPFIX data from us
	addrOut := &net.UDPAddr{IP: net.ParseIP(os.Args[2]), Port: 2055}
	// "Connection" to our dtls-decrypter
	var dtlsConn *dtls.Conn
	// Close the connection on exit
	defer func() {
		util.Check(dtlsConn.Close())
	}()

	/*
	   Main functionality.
	   We want to offer the receiving side to start and stop their decrypter on demand without trouble.
	   So we keep track whether there are any errors when sending out data and immediately initiate new handshakes
	*/

	// A boolean variable that keeps track ouf our relation to the receiving / decrypting side
	var connected bool
	connected = false

	// Following lines are for logging purposes
	currentTime := time.Now()
	fmt.Printf(currentTime.Format("2006-01-02 13:37:42"))
	fmt.Printf(": Waiting for listener on ")
	fmt.Printf(os.Args[2])
	fmt.Printf(":2055\n")

	// Size of our buffer
	const bufSize int = 1500
	// This buffer is used for temporal storage of data between the incoming and outgoing sockets
	buf := make([]byte, bufSize)

	// Loop forever (until shutdown)
	for {
		// If we aren't "connected" try to perform a DTLS handshake with our decrypter
		if connected == false {
			// Dial in to our receiving side. This will initiate a DTLS handshake
			dtlsConn, err = dtls.Dial("udp", addrOut, config)
			// If successful, we can start sending data
			if err == nil {
				connected = true
				// And do some logging once again
				fmt.Printf(currentTime.Format("2006-01-02 15:04:05"))
				fmt.Printf(": Connected to ")
				fmt.Printf(os.Args[2])
				fmt.Printf(":2055\n")
			} else {
				// Otherwise, wait a couple of seconds before retry
				time.Sleep(5 * time.Second)
				//fmt.Println(err)
				//dtlsConn.Close()
			}
		}
		// If we are connected, we want to read the plain UDP data and send it out on the DTLS socket
		if connected == true {
			// Clear the buffer (might be removed once checked if it is actually needed)
			for i := 0; i < bufSize; i++ {
				buf[i] = 0
			}
			// Read from the plain UDP connection and count the bytes
			n, _, err := connIn.ReadFromUDP(buf)
			// Error checking
			if err != nil {
				panic(err)
			}
			// Write as many bytes read out to the encrypted socket
			ln, err := dtlsConn.Write(buf[0:n])
			// Count how many bytes were sent. If 0 bytes could be transmitted, we consider the connection to be dead
			if ln == 0 {
				//fmt.Println(err)
				dtlsConn.Close()
				connected = false
			} else
			// Do some more error checking
			if err != nil {
				//fmt.Println(err)
				dtlsConn.Close()
				connected = false
			} else {
				// Successful export
			}
		}
	}
}
