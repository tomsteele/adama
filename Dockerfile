FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/seed ./cmd/seed \
 && CGO_ENABLED=0 go build -o /out/nmap ./cmd/nmap \
 && CGO_ENABLED=0 go build -o /out/nmap-svc ./cmd/nmap-svc \
 && CGO_ENABLED=0 go build -o /out/discover ./cmd/discover \
 && CGO_ENABLED=0 go build -o /out/gowitness ./cmd/gowitness \
 && CGO_ENABLED=0 go build -o /out/report ./cmd/report

FROM alpine:3.21 AS seed
COPY --from=build /out/seed /usr/local/bin/seed
ENTRYPOINT ["seed"]

FROM alpine:3.21 AS nmap
RUN apk add --no-cache nmap nmap-scripts
COPY --from=build /out/nmap /usr/local/bin/nmap-worker
COPY --from=build /out/nmap-svc /usr/local/bin/nmap-svc-worker
COPY --from=build /out/discover /usr/local/bin/discover-worker
ENTRYPOINT ["nmap-worker"]

FROM alpine:3.21 AS report
COPY --from=build /out/report /usr/local/bin/report
ENTRYPOINT ["report"]

FROM ghcr.io/sensepost/gowitness:latest AS gowitness
USER root
COPY --from=build /out/gowitness /usr/local/bin/gowitness-worker
ENTRYPOINT ["gowitness-worker"]
