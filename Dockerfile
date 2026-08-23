FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/broker ./cmd/broker
RUN mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/broker /broker
COPY --from=builder --chown=nonroot:nonroot /data /data
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/broker"]
