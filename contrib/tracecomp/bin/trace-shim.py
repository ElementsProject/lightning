#!/usr/bin/env python3
import sys
import time
import subprocess
import json
import os
import threading
import shutil

def main():
    # Chrome Tracing uses microsecond precision
    start_ts = time.time() * 1000000
    
    # 1. Determine who we are impersonating (e.g., 'cc', 'make')
    my_name = os.path.basename(sys.argv[0])
    
    # If we are somehow run directly as the python script (shouldn't happen with symlinks setup correctly)
    if my_name == "trace-shim.py":
        print("trace-shim: This script should be run via a symlink (e.g., ln -s trace-shim.py cc)", file=sys.stderr)
        sys.exit(1)

    # 2. Find the *real* executable.
    # We must filter out the directory containing this script from PATH to avoid infinite recursion.
    current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    original_path = os.environ.get("PATH", "")
    
    path_dirs = original_path.split(os.pathsep)
    filtered_path_dirs = []
    
    for p in path_dirs:
        # Skip empty paths (current dir) and the specific shim dir
        if not p: 
            continue
        try:
            # Resolve to absolute path to compare safely
            abs_p = os.path.abspath(p)
            if abs_p != current_dir:
                filtered_path_dirs.append(p)
        except OSError:
            pass

    # Construct a PATH string without our directory
    new_path_env = os.pathsep.join(filtered_path_dirs)
    
    # Find executable using `which` logic
    real_cmd_path = shutil.which(my_name, path=new_path_env)
    
    if not real_cmd_path:
        print(f"trace-shim: Could not find real '{my_name}' in PATH (excluding {current_dir})", file=sys.stderr)
        print(f"trace-shim: PATH was: {original_path}", file=sys.stderr)
        sys.exit(127)

    # Prepare command
    cmd = [real_cmd_path] + sys.argv[1:]
    name = " ".join(cmd)
    
    # Determine Root PID (trace 'pid') and Parent PID (for flow events)
    # If CLN_TRACE_ROOT_PID is set, we are a child. Use it to group under the single root process.
    # If not, we are the root.
    env_root_pid = os.environ.get("CLN_TRACE_ROOT_PID")
    env_parent_pid = os.environ.get("CLN_TRACE_PARENT_PID")

    if env_root_pid:
        try:
            root_pid = int(env_root_pid)
        except ValueError:
            root_pid = os.getpid()
    else:
        root_pid = os.getpid()

    if env_parent_pid:
        try:
            parent_pid = int(env_parent_pid)
        except ValueError:
            parent_pid = None
    else:
        parent_pid = None

    # Set up environment for the child process
    # Pass the Root PID and Parent PID down so everyone groups correctly.
    child_env = os.environ.copy()
    child_env["CLN_TRACE_ROOT_PID"] = str(root_pid)
    child_env["CLN_TRACE_PARENT_PID"] = str(os.getpid())

    # Execute the command
    try:
        proc = subprocess.run(cmd, env=child_env)
        return_code = proc.returncode
    except Exception as e:
        print(f"trace-shim: Error running {real_cmd_path}: {e}", file=sys.stderr)
        return_code = 1

    end_ts = time.time() * 1000000
    duration = end_ts - start_ts

    # Skip spans below 1 second (1,000,000 microseconds)
    MIN_DURATION = 1000000
    if duration >= MIN_DURATION:
        # Chrome Trace Event Format (Complete Event 'X')
        # We use the Root PID as the 'pid' in the trace. This puts EVERY build command
        # into a single "Process" track in the viewer.
        # We use our own PID as the 'tid', so every command appears as a separate "thread"
        # within that root process.
        event = {
            "name": name,
            "cat": my_name,
            "ph": "X",  # Complete event
            "ts": start_ts,
            "dur": duration,
            "pid": root_pid,           # Everyone shares this (Single Process view)
            "tid": os.getpid(),        # Distinct threads for parallelism
            "args": {
                "command_line": name,  # Full string for easy reading
                "binary": my_name,     # The tool shimmed (e.g. 'cc')
                "return_code": return_code,
                "cwd": os.getcwd(),
                "ppid": os.getppid(),  # Actual direct parent (for manual reconstruction)
                "trace_parent_pid": parent_pid  # Parent in the trace system (for flow events)
            }
        }

        # Write to a unique fragment file
        trace_dir = os.environ.get("TRACE_DIR", os.getcwd())

        # Filename includes name and pid to avoid collisions
        fragment_path = os.path.join(trace_dir, f".trace.{my_name}.{os.getpid()}.json")

        try:
            with open(fragment_path, "w") as f:
                json.dump(event, f)
        except Exception as e:
            # Don't fail the build just because tracing failed, but warn
            print(f"trace-shim: Failed to write trace to {fragment_path}: {e}", file=sys.stderr)

    sys.exit(return_code)

if __name__ == "__main__":
    main()
