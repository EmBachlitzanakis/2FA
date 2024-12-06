FROM golang:1.23.0

WORKDIR /usr/src

RUN go install github.com/air-verse/air@latest



COPY . .
RUN go mod tidy
