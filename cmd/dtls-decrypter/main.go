package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
	"strings"
	"strconv"
	"github.com/pion/dtls"
)

/*
		Variables for storing raw and parsed intput flags
*/


var flag0 string			// User input of form 10.10.10.10:2055, specified via --input flag
var listenAddress string	// IP address parsed from above string
var listenPort uint16		// Port parsed from above string

var flag1 string			// User input of form 127.0.0.1:2055, specified via --output flag
var outputAddress string	// IP address parsed from above string
var outputPort uint16		// Port parsed from above string

var listenHelp string
var outputHelp string

func main() {

	/*
		Get the user input
	*/

	listenHelp = "Address to listen to.\tFormat: <ip addr>[:2055]."
	outputHelp = "Address to output to.\tFormat: [127.0.0.1][:2055]"


	flag.StringVar(&flag0, "listen", "", listenHelp)
	flag.StringVar(&flag1, "output", "127.0.0.1", outputHelp)
	flag.Parse()


	/*
		Parse the input and fall back to default values if needed
	*/

	var usageString string
	usageString = "Usage:\n\t-listen string\n\t\t" + listenHelp + "\n\t-output string\n\t\t" + outputHelp + "\n"

	listenArgs := strings.Split(flag0, ":")

	// No listen address provided - we can't bint to any device
	if listenArgs[0] == "" {
		fmt.Printf(usageString)
		os.Exit(1)
	}

	// Some string provided. TODO sanity check whether this is a valid IPv4 string
	listenAddress = listenArgs[0]

	// No port to listen to provided. Defaulting to 2055
	if len(listenArgs) == 1{
		listenArgs = append(listenArgs, "2055")
		fmt.Println("Defaulting to listen port 2055")
	}

	// Parse the given listen port. Also make sure it is in 16 bit range
	listenPort64, err := strconv.ParseUint(listenArgs[1], 10, 16)
	listenPort = uint16(listenPort64)
	if err != nil {
		fmt.Println("Could not parse listen port!")
		os.Exit(1)
	}

	outputArgs := strings.Split(flag1, ":")

	// No output address provided. Fall back to default value of loop back device, 127.0.0.1
	if len(outputArgs) == 0 {
		outputArgs = append(outputArgs, "127.0.0.1")
		fmt.Println("Defaulting to output address 127.0.0.1")
	}

	// If some string was provided, use it. Otherwise this would be the default address at this point
	// TODO sanity check for input string being an IPv4 address
	outputAddress = outputArgs[0]

	// No port to output to provided. Defaulting to 2055
	if len(outputArgs) == 1{
		outputArgs = append(outputArgs, "2055")
		fmt.Println("Defaulting to output port 2055")
	}

	//Pares the given output port. Also make sure it is in 16 bit range
	outputPort64, err := strconv.ParseUint(outputArgs[1], 10, 16)
	outputPort = uint16(outputPort64)
	if err != nil {
		fmt.Println("Could not parse output port!")
		os.Exit(1)
	}

	fmt.Printf("Listening on %s:%d (UDP) for DTLS traffic.\n", listenAddress, listenPort)
	fmt.Printf("Sending decrypted traffic to %s:%d (UDP)\n", outputAddress, outputPort)

	//Flag handling
	// Prepare the IP address from which we want to receive DTLS data
	var addr *net.UDPAddr


	/*
	   Addresses and sockets handling
	*/

	addr = &net.UDPAddr{IP: net.ParseIP(listenAddress), Port: int(listenPort)}

	// We want the decrypted data to be sent to our loop back device on port 2055 so we can collect it using:
	// sudo tcpdump -i lo udp port 2055 -G 30 -w my_ipfix_%F-%T-%Z.pcap

	ServerAddr, err := net.ResolveUDPAddr("udp", outputAddress+":"+strconv.Itoa(int(outputPort)))
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
