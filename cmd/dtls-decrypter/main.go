package main

import (
	"crypto/tls"
	"fmt"
	"net"
//	"time"
	"os"
	"github.com/pion/dtls"
	"github.com/pion/dtls/examples/util"
	"github.com/pion/dtls/pkg/crypto/selfsign"
)

func main() {
	// Prepare the IP to connect to
	var addr *net.UDPAddr
	if len(os.Args) > 1 {
		addr = &net.UDPAddr{IP: net.ParseIP(os.Args[1]), Port: 2055}
	} else {
		fmt.Printf("Please provide an IP address to bind to.")
	}

	ServerAddr, err := net.ResolveUDPAddr("udp","127.0.0.1:2055")			//IP address where the decrypted data is sent to
	util.Check(err)
    LocalAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	util.Check(err)

	Conn, _ := net.DialUDP("udp", LocalAddr, ServerAddr)				//open the socket to send UPD data
    defer Conn.Close()


	// Generate a certificate and private key to secure the connection
	// TODO use DE-CIX official certificates
	certificate, genErr := selfsign.GenerateSelfSigned()
	util.Check(genErr)

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	//	ConnectTimeout:       dtls.ConnectTimeoutOption(4 * time.Second),
	}

	for{
		// Connect to a DTLS server
		listener, err := dtls.Listen("udp", addr, config)
		util.Check(err)
		defer func() {
			util.Check(listener.Close())
		}()
		// Wait for a connection.
		//fmt.Println("Listening on", addr)
		conn, err := listener.Accept()
		//fmt.Println("Accepted.")
		util.Check(err)
		const bufsize int = 1500
		buf := make([]byte, bufsize)
		var bytes_recv int = 0
		var pkts_recv int = 0

		for {
			for i := 0; i < bufsize; i ++ {
				buf[i] = 0
			}
			ln, err := conn.Read(buf)
			//fmt.Println("Read %i bytes", ln)
			if err != nil {
				conn.Close()
				fmt.Printf("Connection closed.\n")
				fmt.Println(err)
				break
			} else if ln == 0 {
				fmt.Printf("Empty response.\n")
			}
			bytes_recv += ln
			pkts_recv++
			fmt.Printf("Packets received: %d\tBytes received: %d\r", pkts_recv, bytes_recv)
			_,_ = Conn.Write(buf[:ln])
		}
		conn.Close()
		listener.Close()
	}
}
