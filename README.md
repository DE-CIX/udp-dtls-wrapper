# DE-CIX UDP-DTLS WRAPPER

Used for encrypting IPFIX data trasported via UDP:2055 (CFlow)

Depends on https://github.com/pion/dtls and all its dependencies.


To compile, run
go get ./cmd/dtls-decrypter/main.go
go build ./cmd/dtls-decrypter/main.go
./main

Please make sure that your Golang environment is properly configured ($GOPATH, $GOBIN, $GOROOT, etc.)

Compilation tested on linux/amd64 (go version 1.13.3)
Functionality tested on CentOS 7 (kernel 3.10.0-1127)
