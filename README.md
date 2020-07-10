# DE-CIX UDP-DTLS WRAPPER

This wrapper is used for encrypting IPFIX data trasported via UDP:2055 (CFlow).
It finds practical usage for all DE-CIX customers that request their subset of IFPIX data generated on our peering platform.


Usage:
 * Log in to the DE-CIX customer portal and look for IPFIX Export in the menu to the left (link to come...)
 * Choose a desired MAC adress and the IP address to which your IPFIX data should be exported to
 * Run the dtls-decrypter and provide it with the IP address of your request (Note that the dtls-decrypter must be run on the machine with that IP address)



To compile, run
go get ./cmd/dtls-decrypter/main.go
go build ./cmd/dtls-decrypter/main.go
./main


Please make sure that your Golang environment is properly configured ($GOPATH, $GOBIN, $GOROOT, etc.)
Compilation tested on linux/amd64 (go version 1.13.3)
Functionality tested on CentOS 7 (kernel 3.10.0-1127)
