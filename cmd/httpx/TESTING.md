# Screenshot endpoint integration tests

Normal `go test ./...` covers result validation and the task-local resolver. The
`integration` build tag adds real HTTPX/Chromium tests using the shipped profile:
concurrent copies of the same hostname on two IPv4 backends and IPv6, HTTP and
HTTPS, Host/SNI/path/query preservation, screenshot pixels, unavailable backends,
and honest attribution after a redirect to another IP.

Run inside the worker image with networking disabled. No NATS deployment or real
scan targets are needed. From the repository root (use `amd64` on x86 Docker):

```bash
docker build --target httpx -t adama-httpx-test .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -tags integration -o /tmp/adama-httpx.test ./cmd/httpx
docker run --rm --network none \
  --entrypoint /tests/httpx.test \
  -v /tmp/adama-httpx.test:/tests/httpx.test:ro \
  -v "$PWD":/src:ro -w /src/cmd/httpx \
  adama-httpx-test -test.run TestIntegration -test.v -test.timeout 3m
```

The tests shorten scanner timeouts and disable update checks; all fixtures are
on loopback. Tests exercise the current worker code through the compiled test
binary, and the scanner/browser installed in the image. An image build alone
does not exercise these cases. This is an endpoint check, not a worker-kill,
NATS recovery, or full deployment acceptance test.
