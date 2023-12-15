#!/usr/bin/env python3

"""A simple way to receive spans from an instrumented binary.

Currently only supports a single binary given as the first command
line argument.
"""

import threading
from urllib import request
from bcc import BPF, USDT
import json
import sys
from pathlib import Path
import time
from queue import Queue

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} [zipkin_url] [binary]")
    sys.exit(1)

zipkin_url = sys.argv[1]
binaries = [sys.argv[2]]

# Path to the eBPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[495];
    bpf_usdt_readarg(2, ctx, &addr);
    bpf_probe_read(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("%s\\n", path);
    return 0;
};
"""


def instrument(binary: Path) -> USDT:
    """Given a binary isntrument it with the USDT context."""
    path = binary.resolve()
    usdt_ctx = USDT(path=str(path))

    usdt_ctx.enable_probe(
        probe="span_emit",
        fn_name="do_trace"
    )
    return usdt_ctx


def submit_once(queue: Queue):
    """Submit accumulated spans to an otelcol."""
    spans = []
    while not queue.empty():
        span = queue.get_nowait()
        spans.append(span)
        queue.task_done()

    print(f"Submitting a batch of {len(spans)} spans")
    req = request.Request(
        zipkin_url,
        data=json.dumps(spans).encode('ASCII'),
        headers={
            'Content-Type': 'application/json',
        },
        method='POST'
    )
    request.urlopen(req).read()


def submit(queue: Queue):
    """Repeatedly submit batches of spans to otelcol."""
    while True:
        time.sleep(1)
        try:
            submit_once(queue)
        except Exception as e:
            print(f"Error submitting spans to otelcol: {e}")


# An queue to accumulate spans in.
queue = Queue()


# Run the submission to otelcol in the background.
thread = threading.Thread(
    target=submit,
    args=(queue,),
    daemon=True
)
thread.start()

binaries = [Path(i) for i in binaries]
ctxs = [instrument(b) for b in binaries]
b = BPF(
    text=bpf_text,
    usdt_contexts=ctxs,
    debug=0,
)

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        queue.put(json.loads(msg)[0])
    except Exception as e:
        print(f"Failed to parse message {msg}: {e}")
