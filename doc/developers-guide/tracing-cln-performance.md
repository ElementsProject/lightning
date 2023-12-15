---
title: "Tracing CLN Performance"
slug: "tracing-cln-performance"
hidden: false
---
CLN includes a simple opentracing exporter that allows tracing the execution of the node in real-time, without incurring a performance penalty when not listening for traces. Quoting the [Wikipedia](https://en.wikipedia.org/wiki/Tracing_(software)) entry on Tracing:

> In software engineering, tracing involves a specialized use of logging to record information about a program's execution. This information is typically used by programmers for debugging purposes, and additionally, depending on the type and detail of information contained in a trace log, by experienced system administrators or technical-support personnel and by software monitoring tools to diagnose common problems with software.

The tracing system in CLN is implemented using [USDTs](https://illumos.org/books/dtrace/chp-usdt.html) (no, not that kind of [USDT](https://en.wikipedia.org/wiki/Tether_(cryptocurrency))). As such it emits events into the kernel, from where an exporter can receive them. If no exporter is configured then the kernel will replace the call-sites of the probe with a `NOP`, thus causing only minimal overhead when not tracing.

## Compiling with tracing support

CLN will build with tracing support if the necessary headers (`sys/sdt.h`) are present during the compilation. For debian and ubuntu based systems that is easily achieved by installing `systemtap-sdt-dev`:

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

## Exporters

The simplest way to get started with eBPF in general (which the tracing is built upon) is the `bpftrace` command that we've already seen above when checking if the binary was built with tracing support.

```bash
$ sudo bpftrace -l 'U:lightningd/lightningd:*'
usdt:lightningd/lightningd:lightningd:span_emit
usdt:lightningd/lightningd:lightningd:span_end
usdt:lightningd/lightningd:lightningd:span_resume
usdt:lightningd/lightningd:lightningd:span_start
usdt:lightningd/lightningd:lightningd:span_suspend
```

We want to attach to the `span_emit` probe, as that's the one getting the opentracing-compatible JSON string passed as an argument, and we'd like to extract that.

```bash
$ export BPFTRACE_STRLEN=200
$ sudo -E bpftrace -e 'U:../lightning/lightningd/lightningd:span_emit {printf("%s\n", str(arg1, 10240));}'

Attaching 1 probe...
[{"id": "5006000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202283751653, "duration": 154,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "sql"}, "traceId": "b7f9b1
[{"id": "5106000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202283752515, "duration": 146,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "listnodes"}, "traceId": "
[{"id": "8206000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202283759889, "duration": 657,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "dev-memleak"}, "traceId":
[{"id": "8306000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202283784095, "duration": 135,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "dev-report-fds"}, "traceI
[{"id": "8406000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202283785116, "duration": 204,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "stop"}, "traceId": "f6d42
[{"id": "3100000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202283860017, "duration": 770,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "dev-memleak"}, "traceId":
[{"id": "3200000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202283992271, "duration": 155,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "dev-report-fds"}, "traceI
[{"id": "3300000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202283993745, "duration": 370,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "stop"}, "traceId": "92576
[{"id": "5206000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202284070125, "duration": 911,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "dev-memleak"}, "traceId":
[{"id": "5506000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202284313462, "duration": 62,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "dev-report-fds"}, "traceId
[{"id": "5606000000000000", "name": "lightningd/jsonrpc", "timestamp": 1690202284314014, "duration": 117,"localEndpoint": { "serviceName": "lightningd"}, "tags": {"method": "stop"}, "traceId": "b7f9b
[{"id": "5406000000000000", "name": "plugin/bitcoind", "timestamp": 1690202284312469, "duration": 4774,"localEndpoint": { "serviceName": "lightningd"}, "parentId": "5306000000000000","tags": {"method
[{"id": "5306000000000000", "name": "extend_tip", "timestamp": 1690202284312428, "duration": 4902,"localEndpoint": { "serviceName": "lightningd"}, "tags": {}, "traceId": "b7f9b1e8af12d252"}]

```





Notice that due to a [limitation](https://github.com/iovisor/bpftrace/issues/305) in `bpftrace` you'll at most get the first 200 bytes of the payload. If you write your own exporter you'll be able to specify the size of the buffer that is being used, and can extract the entire span.

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
