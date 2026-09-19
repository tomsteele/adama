FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/seed ./cmd/seed \
 && CGO_ENABLED=0 go build -o /out/nmap ./cmd/nmap \
 && CGO_ENABLED=0 go build -o /out/nmap-svc ./cmd/nmap-svc \
 && CGO_ENABLED=0 go build -o /out/nmap-discover ./cmd/nmap-discover \
 && CGO_ENABLED=0 go build -o /out/asurl ./cmd/asurl \
 && CGO_ENABLED=0 go build -o /out/dnsx ./cmd/dnsx \
 && CGO_ENABLED=0 go build -o /out/tlsx ./cmd/tlsx \
 && CGO_ENABLED=0 go build -o /out/nuclei ./cmd/nuclei \
 && CGO_ENABLED=0 go build -o /out/httpx ./cmd/httpx \
 && CGO_ENABLED=0 go build -o /out/report ./cmd/report

FROM alpine:3.21 AS seed
COPY --from=build /out/seed /usr/local/bin/seed
ENTRYPOINT ["seed"]

FROM alpine:3.21 AS nmap
RUN apk add --no-cache nmap nmap-scripts
COPY --from=build /out/nmap /usr/local/bin/nmap-worker
COPY --from=build /out/nmap-svc /usr/local/bin/nmap-svc-worker
COPY --from=build /out/nmap-discover /usr/local/bin/nmap-discover-worker
COPY --from=build /out/asurl /usr/local/bin/asurl-worker
COPY profiles /profiles
ENTRYPOINT ["nmap-worker"]

FROM alpine:3.21 AS report
COPY --from=build /out/report /usr/local/bin/report
ENTRYPOINT ["report"]

FROM projectdiscovery/dnsx:latest AS dnsx
COPY --from=build /out/dnsx /usr/local/bin/dnsx-worker
COPY wordlists /wordlists
ENV DNSX_WORDLIST=/wordlists/dns.txt
ENTRYPOINT ["dnsx-worker"]

FROM projectdiscovery/tlsx:latest AS tlsx
COPY --from=build /out/tlsx /usr/local/bin/tlsx-worker
ENTRYPOINT ["tlsx-worker"]

FROM projectdiscovery/nuclei:latest AS nuclei
COPY --from=build /out/nuclei /usr/local/bin/nuclei-worker
COPY profiles /profiles
ENV NUCLEI_PROFILE=/profiles/nuclei.yaml
ENTRYPOINT ["nuclei-worker"]

FROM projectdiscovery/httpx:latest AS httpx
USER root
RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont
COPY --from=build /out/httpx /usr/local/bin/httpx-worker
COPY profiles /profiles
ENV HTTPX_PROFILE=/profiles/httpx.yaml
ENV SCREENSHOT_DIR=/screenshots
ENV CHROME_PATH=/usr/bin/chromium-browser
ENTRYPOINT ["httpx-worker"]
