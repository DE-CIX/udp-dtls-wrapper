package main

import (
	"crypto/tls"
//	"encoding/binary"
//	"bytes"
	"fmt"
	"net"
	"time"
	"os"
	"strconv"
	"github.com/pion/dtls"
	"github.com/pion/dtls/examples/util"
	"github.com/pion/dtls/pkg/crypto/selfsign"
)

func main() {

	// Prepare our listener. It receives filtered data from loopback on a given port
	portIn, _ := strconv.Atoi(os.Args[1])
	addrIn := net.UDPAddr{
		Port: portIn,
	    IP:   net.ParseIP("127.0.0.1"),
	}
	connIn, err := net.ListenUDP("udp", &addrIn)
	if err != nil {
	    panic(err)
	}
	defer connIn.Close()


	// Generate a certificate and private key to secure the connection
	certificate, genErr := selfsign.GenerateSelfSigned()
	util.Check(genErr)

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	//	ConnectTimeout:       dtls.ConnectTimeoutOption(8 * time.Second),
	}



	// Prepare the end point to connect to, it will receive encrypted and filtere IPFIX data from us
	addrOut := &net.UDPAddr{IP: net.ParseIP(os.Args[2]), Port: 2055}
	// Connect to a DTLS server
	var dtlsConn *dtls.Conn
	defer func() {
		util.Check(dtlsConn.Close())
	}()
	var connected bool
	connected = false
	currentTime := time.Now()
	fmt.Printf(currentTime.Format("2006-01-02 13:37:42"))
	fmt.Printf(": Waiting for listener on ")
	fmt.Printf(os.Args[2])
	fmt.Printf(":2055\n")
	const bufsize int = 1500
	buf := make([]byte, bufsize)
	for {
		if connected == false {
			dtlsConn, err = dtls.Dial("udp", addrOut, config)
			if err == nil {
				connected = true
				fmt.Printf(currentTime.Format("2006-01-02 15:04:05"))
				fmt.Printf(": Connected to ")
				fmt.Printf(os.Args[2])
				fmt.Printf(":2055\n")
			} else {
				time.Sleep(5 * time.Second)
				//fmt.Println(err)
				//dtlsConn.Close()
			}
		}
		if connected == true {
			for i := 0; i < bufsize; i++ {
				buf[i] = 0
			}
			n, _, err := connIn.ReadFromUDP(buf)
			if err != nil{
				panic(err)
			}
			ln, err := dtlsConn.Write(buf[0:n])
			if ln == 0 {
				//fmt.Println(err)
				dtlsConn.Close()
				connected = false
			} else if err != nil {
				//fmt.Println(err)
				dtlsConn.Close()
				connected = false
			} else {
				//fmt.Printf("Successful export.\n")
			}
		}
	}
}
