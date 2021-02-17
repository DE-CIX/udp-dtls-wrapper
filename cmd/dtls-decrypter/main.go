package main

import (
	"flag"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/pion/dtls"
)

var listenAddress string
var outputAddress string

func main() {
	flag.StringVar(&listenAddress, "listen", "192.0.2.1", "Address to listen to")
	flag.StringVar(&outputAddress, "output", "127.0.0.1", "Address to send to")
	flag.Parse()
	/*
	   Addresses and sockets handling
	*/

	// Prepare the IP address from which we want to receive DTLS data
	var addr *net.UDPAddr
	if listenAddress != "" {
		addr = &net.UDPAddr{IP: net.ParseIP(listenAddress), Port: 2055}
	} else {
		// Usage "help"
		fmt.Printf("Please provide an IP address to bind to.")
		runtime.Goexit() //TODO doesn't work for me right now
	}

	// We want the decrypted data to be sent to our loop back device on port 2055 so we can collect it using:
	// sudo tcpdump -i lo udp port 2055 -G 30 -w my_ipfix_%F-%T-%Z.pcap
	// for example
	ServerAddr, err := net.ResolveUDPAddr("udp", outputAddress+":2055")
	// Error checking
	if err != nil {
		panic(err)
	}

	// Open the socket to send UDP data towards our loop back device
	Conn, _ := net.DialUDP("udp", nil, ServerAddr)
	// Close the socket afterwards
	defer Conn.Close()

	/*
	   DTLS connection handling
	*/

	// Generate a certificate and private key to secure the connection
	// TODO use DE-CIX official certificates
	certificate, privKey, genErr := dtls.GenerateSelfSigned()
	if genErr != nil {
		panic(err)
	}

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificate:          certificate,
		PrivateKey:           privKey,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	/*
	   Main functionality
	   Perform handshake and read from the encrypted socket
	   Decrypted data is sent out to loop back device on port 2055
	*/

	// Size of the buffer
	const bufSize int = 1500
	// A buffer for storing decrypted data that is then written out to the loop back device
	buf := make([]byte, bufSize)
	// Counter for counting bytes received
	var bytesReceived int = 0
	// Counter for counting packets received
	var packetsReceived int = 0

	for {
		// Prepare the DTLS socket
		listener, err := dtls.Listen("udp", addr, config)
		// Error checking
		if err != nil {
			panic(err)
		}
		// Close the socket on exit
		defer func() {
			listener.Close(time.Duration(10))
		}()
		// Wait for a connection and perform the handshake
		conn, err := listener.Accept()
		// Some more error checking
		if err != nil {
			panic(err)
		}

		// At this point, we are connected. Loop forever and read from the DTLS socket
		for {
			// Clear the buffer (still needs to be examined if doing so is actually necessary)
			for i := 0; i < bufSize; i++ {
				buf[i] = 0
			}
			// Read from the encrypted socket, store the decrypted data in the buffer and count the read bytes
			ln, err := conn.Read(buf)
			// If some error occurs, we want to retry
			if err != nil {
				conn.Close()
				fmt.Printf("Connection closed.\n")
				fmt.Println(err)
				break
			} else
			// Print some info to the user if there wasn't anything read (hasn't ever occurred throughout testing)
			if ln == 0 {
				fmt.Printf("Empty response.\n")
				break
			}
			// At this point we have received encrypted data and can send it out unencrypted
			// Increment our counters accordingly
			bytesReceived += ln
			packetsReceived++
			// Print some status to the user
			fmt.Printf("Packets received: %d\tBytes received: %d\r", packetsReceived, bytesReceived)
			// Just send against the loop back device, no error handling is done here.
			_, _ = Conn.Write(buf[:ln])
		}
		// Close the connections and start again from the beginning with a new connection
		conn.Close()
		listener.Close(time.Duration(10))
	}
}
