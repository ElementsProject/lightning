#!/usr/bin/env python3
import json
import glob
import os
import sys

def main():
    trace_dir = os.environ.get("TRACE_DIR", os.getcwd())
    pattern = os.path.join(trace_dir, ".trace.*.json")
    files = glob.glob(pattern)

    events = []
    for p in files:
        try:
            with open(p, "r") as f:
                events.append(json.load(f))
        except Exception as e:
            print(f"Skipping {p}: {e}", file=sys.stderr)

    # Generate flow events to show caller->callee relationships
    flow_events = []
    flow_id_counter = 0

    # Build a map of tid -> event for quick lookup
    tid_to_event = {}
    for event in events:
        tid = event.get("tid")
        if tid is not None:
            tid_to_event[tid] = event

    for event in events:
        # Check if this event has a trace_parent_pid (indicating a parent->child relationship)
        args = event.get("args", {})
        parent_tid = args.get("trace_parent_pid")

        if parent_tid is not None and parent_tid in tid_to_event:
            parent_event = tid_to_event[parent_tid]
            child_event = event

            # Create a flow event from parent start to child start
            # This will show as a connecting arrow in the trace viewer
            flow_id = f"flow_{flow_id_counter}"
            flow_id_counter += 1

            # Flow event at parent's end point (outgoing)
            parent_flow = {
                "name": f"→ {args.get('binary', 'cmd')}",
                "cat": "flow",
                "ph": "s",  # flow start
                "ts": parent_event["ts"] + parent_event["dur"],  # End of parent
                "dur": 0,
                "pid": parent_event["pid"],
                "tid": parent_tid,
                "flow_id": flow_id
            }

            # Flow event at child's start point (incoming)
            child_flow = {
                "name": f"← {args.get('binary', 'cmd')}",
                "cat": "flow",
                "ph": "f",  # flow finish
                "ts": child_event["ts"],  # Start of child
                "dur": 0,
                "pid": child_event["pid"],
                "tid": child_event["tid"],
                "flow_id": flow_id
            }

            flow_events.extend([parent_flow, child_flow])

    output_file = "trace.json"
    if len(sys.argv) > 1:
        output_file = sys.argv[1]

    # Combine events and flow events, then sort by timestamp
    all_events = events + flow_events
    all_events.sort(key=lambda x: (x["ts"], x.get("ph", "")))

    with open(output_file, "w") as f:
        json.dump(all_events, f, indent=2)

    print(f"Merged {len(events)} trace events and {len(flow_events)} flow events into {output_file}")

    # Optional: cleanup
    # for p in files:
    #     os.remove(p)

if __name__ == "__main__":
    main()
