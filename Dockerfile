FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v3 go build -o sso-ws-server-new

FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/sso-ws-server-new .
COPY --from=builder /app/index.html .

EXPOSE 80

CMD ["./sso-ws-server-new"]