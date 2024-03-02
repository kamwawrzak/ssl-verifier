FROM golang:1.21

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN make build-server

ENTRYPOINT [ "./bin/ssl-verifier-server" ]
