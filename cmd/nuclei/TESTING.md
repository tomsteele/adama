# Nuclei integration checks

The `integration` build tag tests the real scanner against loopback fixtures:

- The same hostname/port on two IPv4 addresses and IPv6, using ordinary and raw HTTP over HTTP/HTTPS, checking Host, SNI, path/query, and finding identity.
- Successful requests with no matches versus failed requests, including TCP.
- Valid findings retained when another request fails.
- Cancellation/deadline propagation and detection of an unused binding configuration.
- Redirects to another hostname still reaching that hostname's own IP.
- TCP and TLS hostname/IP bindings across simultaneous IPv4/IPv6 backends on the same nonstandard port, including TLS SNI.
- Successful non-matches on a template-selected wrong port failing the requested task; positive findings on that port retain their actual endpoint while the task fails.
- Synthetic DNS answers being suppressed if a custom profile mixes DNS templates with backend binding.

From the repository root (use `amd64` for x86 Docker):

```bash
docker build --target nuclei -t adama-nuclei-test .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -tags integration -o /tmp/adama-nuclei.test ./cmd/nuclei
docker run --rm --network none \
  --entrypoint /tests/nuclei.test \
  -v /tmp/adama-nuclei.test:/tests/nuclei.test:ro \
  -v "$PWD":/src:ro -w /src/cmd/nuclei \
  adama-nuclei-test -test.run TestIntegration -test.v -test.timeout 3m
```

Tests select only the local templates under `testdata`, disable OAST, and shorten
request timeouts/retries (TLS fixtures use one attempt; TLSX sends no handshake with zero). No NATS deployment or external scan target is needed.
They exercise current worker code in the test binary and the image's installed
Nuclei binary. The initial checks used Nuclei v3.11.1.

The request log follows Nuclei's [output writer](https://github.com/projectdiscovery/nuclei/blob/v3.11.1/pkg/output/output.go),
including successful non-matches. It cannot certify applicability or execution
of an entire template catalog. The [SSL implementation](https://github.com/projectdiscovery/nuclei/blob/v3.11.1/pkg/protocols/ssl/ssl.go)
can log the input address instead of the template's actual address; the service
trace check therefore does not prove an SSL non-match reached the requested port.
DNS/JavaScript service coverage, headless, exact SSL non-match destinations,
redirect attribution, and full deployment recovery need separate acceptance
checks. No unsupported transport is silently considered tested: the default
network profile rejects UDP before execution, leaving a terminal task failure.
