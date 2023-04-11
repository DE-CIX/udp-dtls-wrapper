##
## Build
##
FROM golang:alpine AS build

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY cmd/dtls-decrypter/*.go ./
RUN go get -v -d ./... \
 && go build -o /dtls-decrypter

##
## Deploy
##
FROM alpine:edge

ENV USERNAME=appuser \
    USER_UID=1000 \
    USER_GID=1000

WORKDIR /
COPY --from=build /dtls-decrypter /dtls-decrypter

RUN addgroup -g $USER_GID $USERNAME \
 && adduser -D -u $USER_UID -G $USERNAME $USERNAME

EXPOSE 2055
USER appuser:appuser
ENTRYPOINT ["/dtls-decrypter"]