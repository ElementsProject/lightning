# Tool to compile a combined schema file from the individual schema
# files in the CLN source.

# This is intended to be run by devs to sync with the schemas in the
# CLN repository, not by users of the tool.

from pathlib import Path
from msggen.utils.utils import methods
import json


def run():
    msggendir = Path(__file__).parent
    d = msggendir / ".." / ".." / "doc" / "schemas"
    schema = {'methods': {}}

    for fname, opts in methods.items():
        req = d / f"{fname.lower()}.request.json"
        res = d / f"{fname.lower()}.schema.json"

        method_name = opts.get("name", fname)

        schema['methods'][method_name] = {
            'request': json.load(req.open()),
            'response': json.load(res.open()),
        }

    dest = msggendir / "msggen" / "schema.json"

    with dest.open(mode='w') as f:
        json.dump(
            schema,
            f,
            indent=2,
            # Can't sort, that'd change the ordering of method
            # arguments too.
            sort_keys=False,
        )


if __name__ == "__main__":
    run()
