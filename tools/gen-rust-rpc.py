#!/usr/bin/env python3
import json
import logging
import os
import sys

import msggen

logging.basicConfig(stream=sys.stdout, encoding="utf-8", level=logging.INFO)
logger = logging.getLogger(__name__)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} [input-schema.json] [output.rs]")
        sys.exit(1)

    # Use the command name as prefix
    cmdname = os.path.basename(sys.argv[1]).split(".")[0]
    schema = json.load(open(sys.argv[1], "r"))
    command = msggen.parse_doc(cmdname, schema)
    gen = msggen.gen_rust(command)

    with open(sys.argv[2], "w") as f:
        f.write(gen)
