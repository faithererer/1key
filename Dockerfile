FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v3 go build -o sso-ws-server-new

FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/sso-ws-server-new .

EXPOSE 8080

CMD ["./sso-ws-server-new"]