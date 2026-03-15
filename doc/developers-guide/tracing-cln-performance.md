---
title: Tracing CLN Performance
slug: tracing-cln-performance
privacy:
  view: public
---
CLN includes a simple opentracing exporter that allows tracing the execution of the node in real-time, without incurring a performance penalty when not listening for traces. Quoting the [Wikipedia](https://en.wikipedia.org/wiki/Tracing_(software)) entry on Tracing:

> In software engineering, tracing involves a specialized use of logging to record information about a program's execution. This information is typically used by programmers for debugging purposes, and additionally, depending on the type and detail of information contained in a trace log, by experienced system administrators or technical-support personnel and by software monitoring tools to diagnose common problems with software.

CLN supports two tracing backends:

1. **USDT probes** (eBPF-based) -- events are emitted into the kernel ring buffer, where an exporter can receive them. Requires kernel access and `systemtap-sdt-dev` headers at compile time.
2. **Unix Domain Socket datagrams** -- completed spans are sent as self-contained Zipkin JSON payloads to a `SOCK_DGRAM` UDS socket. Works in restricted environments (e.g., Kubernetes) where kernel eBPF access is unavailable.

The tracing logic (span management, JSON serialization) is always compiled in. When no backend is active, all tracing functions return early with negligible overhead.

## Backend 1: USDT Probes (eBPF)

The USDT backend is implemented using [USDTs](https://illumos.org/books/dtrace/chp-usdt.html) (no, not that kind of [USDT](https://en.wikipedia.org/wiki/Tether_(cryptocurrency))). As such it emits events into the kernel, from where an exporter can receive them. If no exporter is configured then the kernel will replace the call-sites of the probe with a `NOP`, thus causing only minimal overhead when not tracing.

### Compiling with USDT support

CLN will build with USDT support if the necessary headers (`sys/sdt.h`) are present during the compilation. For debian and ubuntu based systems that is easily achieved by installing `systemtap-sdt-dev`:

```bash
# apt-get install -y systemtap-sdt-dev
```

- Don't forget to run `./configure` and `make` to recompile after installing the dependencies. `config.vars` should contain the following line after running `./configure`:

```
HAVE_USDT=1
```

If you have a compiled binary you can verify whether it was compiled with USDT support with the following command:

```bash
$ readelf -S lightningd/lightningd | grep -i sdt
```

Alternatively you can list the tracepoints in the binary with the following:

```bash
$ sudo bpftrace -l 'U:lightningd/lightningd:*'
usdt:lightningd/lightningd:lightningd:span_emit
usdt:lightningd/lightningd:lightningd:span_end
usdt:lightningd/lightningd:lightningd:span_resume
usdt:lightningd/lightningd:lightningd:span_start
usdt:lightningd/lightningd:lightningd:span_suspend
```

### USDT Exporters

The simplest way to get started with eBPF in general (which the tracing is built upon) is the `bpftrace` command that we've already seen above when checking if the binary was built with tracing support.

```bash
$ sudo bpftrace -l 'U:lightningd/lightningd:*'
usdt:lightningd/lightningd:lightningd:span_emit
usdt:lightningd/lightningd:lightningd:span_end
usdt:lightningd/lightningd:lightningd:span_resume
usdt:lightningd/lightningd:lightningd:span_start
usdt:lightningd/lightningd:lightningd:span_suspend
```

There is a sample exporter that can be used to instrument a single
binary, batch the spans it receives and submit them as a batch to an
`otelcol` or `tempo` instance in [contrib/cln-tracer][cln-tracer]
using the zipkin format for spans and traces.

[cln-tracer]: https://github.com/ElementsProject/lightning/tree/master/contrib/cln-tracer


Notice that due to a [limitation][bpftracer305] in the way the eBPF
script is handled you'll at most get the first 495 bytes of the
payload. This is due to the 512 byte limitation for eBPF programs out
of the box.

[bpftracer]: https://github.com/iovisor/bpftrace/issues/305

## Backend 2: Unix Domain Socket Datagrams

The UDS backend sends completed spans as atomic datagrams to a Unix
domain socket. This is designed for environments where kernel eBPF
access is unavailable, such as Kubernetes pods.

### How it works

Set the `CLN_TRACE_SOCKET` environment variable to the filesystem path
of a `SOCK_DGRAM` Unix domain socket:

```bash
$ CLN_TRACE_SOCKET=/tmp/cln-traces.sock lightningd
```

When a span completes, its Zipkin-format JSON payload is sent via
`sendto()` to the specified socket. Key properties:

- **Atomic delivery**: Each datagram contains a complete, self-contained
  JSON span payload. No framing or reassembly needed.
- **Non-blocking**: The socket is set to `O_NONBLOCK`. If the collector
  is down or the socket buffer is full, the `sendto()` silently fails
  without affecting the node.
- **Multi-writer safe**: Multiple CLN daemons can write to the same
  socket path concurrently. The kernel guarantees datagram boundaries
  are preserved.
- **No USDT dependency**: Works on any system, regardless of whether
  `systemtap-sdt-dev` is installed or `HAVE_USDT` is set.

### Payload format

Each datagram is a Zipkin v2 JSON array containing a single span:

```json
[{"id":"00f067aa0ba902b7","name":"lightningd/jsonrpc",
  "timestamp":1700000000123000,"duration":500,
  "localEndpoint":{"serviceName":"lightningd"},
  "parentId":"d981248067b5e396",
  "tags":{"method":"getinfo"},
  "traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}]
```

Payloads are capped at 2048 bytes, well below the UDS datagram limit
(~200KB on Linux).

### Setting up a collector

Any process that binds a `SOCK_DGRAM` Unix domain socket at the
configured path can receive spans. A minimal Python collector:

```python
import socket, os, json

path = "/tmp/cln-traces.sock"
if os.path.exists(path):
    os.unlink(path)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.bind(path)

while True:
    data = sock.recv(4096)
    spans = json.loads(data)
    print(spans[0]["name"], spans[0]["duration"], "us")
```

In a Kubernetes deployment, the socket file is typically placed on a
shared `emptyDir` volume so a sidecar container can collect spans and
forward them to Jaeger, Tempo, or an OpenTelemetry Collector.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `CLN_TRACE_SOCKET` | Path to a `SOCK_DGRAM` UDS socket. Completed spans are sent as Zipkin JSON datagrams. |
| `CLN_TRACEPARENT` | Inject a W3C Trace Context parent (`00-<trace_id>-<span_id>-<flags>`). All spans inherit this trace ID. |
| `CLN_DEV_TRACE_FILE` | (Developer) Write all trace lifecycle events to `<path>.<pid>` files. Used for testing. |

## Tracing Overhead

While we try to make tracing as lightweight as possible it isn't
free. To quantify how much time is spent actually maintaining the
tracing context we built a small test in `common/test/run-trace` which
creates a sequence of 25'000 traces, with a total of 1'000'000 spans,
without any additional operations.

The following run with [hyperfine][hf] shows the runtime for that test
without an exporter attached:


```bash

$ hyperfine common/test/run-trace
Benchmark 1: common/test/run-trace
  Time (mean ± σ):     368.4 ms ±   4.8 ms    [User: 142.7 ms, System: 225.1 ms]
  Range (min … max):   358.3 ms … 377.2 ms    10 runs
```

While the following is the same run, but with an exporter attached:

```bash
$ ❯ hyperfine common/test/run-trace
Benchmark 1: common/test/run-trace
  Time (mean ± σ):     561.5 ms ±  14.1 ms    [User: 164.5 ms, System: 396.5 ms]
  Range (min … max):   546.5 ms … 598.9 ms    10 runs
```

So depending on whether an exporter is attached, creating and emitting
span without and with an exporter takes around 370ns and 560ns
respectively.
