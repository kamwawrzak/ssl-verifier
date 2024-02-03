FROM golang:1.20

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN make build

ENTRYPOINT [ "./bin/ssl-verifier" ]
