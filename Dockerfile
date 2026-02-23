FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/lab-agent ./cmd/lab-agent

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/lab-agent /lab-agent
EXPOSE 9000
ENTRYPOINT ["/lab-agent"]
