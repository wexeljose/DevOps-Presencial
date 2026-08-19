FROM golang:1.23-alpine AS build
WORKDIR /app
COPY monitoreoDeRouter.go .
RUN go mod init monitor && go build -o monitor .

FROM alpine:3.20
RUN apk add --no-cache iputils
WORKDIR /app
COPY --from=build /app/monitor .
COPY index.html .
EXPOSE 8080
CMD ["./monitor"]
