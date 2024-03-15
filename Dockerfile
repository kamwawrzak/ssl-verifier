FROM golang:1.22

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN make build-server

ENTRYPOINT [ "./bin/ssl-verifier-server" ]
