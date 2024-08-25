---
title: "Writing JSON Schemas"
slug: "writing-json-schemas"
hidden: false
createdAt: "2023-01-25T05:46:43.718Z"
updatedAt: "2024-01-18T15:36:28.523Z"
---
A JSON Schema is a JSON file which defines what a structure should look like; in our case we use it in our testsuite to check that they match command requests and responses, and also use it to generate our documentation.

Yes, schemas are horrible to write, but they're damn useful.  We can only use a subset of the full [JSON Schema Specification](https://json-schema.org/), but if you find that limiting it's probably a sign that you should simplify your JSON output.

## Updating a Schema

If you add a field, you should add it to the field schema, and you must add "added": "VERSION" (where VERSION is the next release version!).

Similarly, if you deprecate a field, add "deprecated": "VERSION" (where VERSION is the next release version) to the field.  They will be removed two versions later.

## How to Write a Schema

Name the schema doc/schemas/lightning-`command`.json: the testsuite should pick it up and check all invocations of that command against it.
The core lightning RPC commands use custom schema specification defined in [rpc-schema-draft](https://github.com/ElementsProject/lightning/doc/rpc-schema-draft.json).

I recommend copying an existing one to start. If something goes wrong, try tools/fromscheme.py doc/schemas/lightning-`command`.json to see how far it got before it died.

You should always list all fields which are _always_ present in `"required"`.

We extend the basic types; see [fixtures.py](https://github.com/ElementsProject/lightning/tree/master/contrib/pyln-testing/pyln/testing/fixtures.py).

In addition, before committing a new schema or a new version of it, make sure that it is well formatted. If you don't want to do it by hand, use `make fmt-schema` that uses jq under the hood.

### Using Conditional Fields

Sometimes one field is only sometimes present; if you can, you should make the schema know when it should (and should not!) be there.

There are two kinds of conditional fields expressible: fields which are only present if another field is present, or fields only present if another field has certain values.

To add conditional fields:

1. Do _not_ mention them in the main "properties" section.
2. Set `"additionalProperties": true` for the main "properties" section.
3. Add an `"allOf": [` array at the same height as `"properties"'`.  Inside this place one `if`/`then` for each conditional field.
4. If a field simply requires another field to be present, use the pattern `"required": [ "field" ]` inside the "if".
5. If a field requires another field value, use the pattern  
   `"properties": { "field": { "enum": [ "val1", "val2" ] } }` inside the "if".
6. Inside the "then", use `"additionalProperties": false` and place empty `{}` for all the other possible properties.
7. If you haven't covered all the possibilities with `if` statements, add an `else` with `"additionalProperties": false` which simply mentions every allowable property.  This ensures that the fields can _only_ be present when conditions are met.

### Exceptions in dynamic schema generation

- If response (`RETURN VALUE`) should not be generated dynamically, and you want it to be a custom text message instead. You can use `return_value_notes` to add custom text with empty `properties`. Examples: `setpsbtversion`, `commando`, `recover`.
- If only one of multiple request parameters can be provided then utilize `oneOfMany`
   key with condition defining arrays. For example, `plugin` command defines it as
   `"oneOfMany": [["plugin", "directory"]]` and it prints the parameter output as
   `[*plugin|directory*]`.
- If request parameters are paired with other parameter and either all of them can be passed
   to the command or none of them; then utilize `pairedWith` key with condition defining arrays.
   For example, `delpay` command defines it as `"pairedWith": [["partid", "groupid"]]` 
   and it prints the parameter output as `[*partid* *groupid*]`.
- - If some of the optional request parameters are dependent upon other optional parameters,
   use `dependentUpon` key where object key can be mapped with the array of dependent params.
   For example, `listforwards` command has `start` and `limit` params dependent upon `index` and
   it can be defined as `"dependentUpon": { "index": ["start", "limit"] }` in the json and it will
   generate the Markdown syntax as `[*index* [*start*] [*limit*]]`.

### Re-generate examples listed in rpc schemas (doc/schemas/lightning-*.json)

1. The `autogenerate-rpc-examples.py` script regenerates RPC examples for methods listed in `doc/schemas/lightning-*.json` files.
2. It uses our pre-existing pytest suite to perform this task.
3. The script runs a test named `test_generate_examples`, which sets up test nodes, records RPC requests, and captures responses. If you have added an RPC, make sure to add its use to the scripts here.
4. To prevent accidental overwriting of examples with other tests, set the environment variable `GENERATE_EXAMPLES=True` before running the script.
5. By default, all methods are regenerated. To specify which methods to regenerate, set the `REGENERATE` environment variable with a comma-separated list of method names. Eg. `REGENERATE='getinfo,connect'` will only regenerate examples for the getinfo and connect RPCs.
6. The dev-bitcoind-poll is set to 3 seconds. Ensure the `TIMEOUT` environment variable is set to more than 3 seconds to avoid test failures due to a short waiting time for bitcoind responses.
7. To run the script using Poetry, use the following command:
```
rm -rf /tmp/ltests* && REGENERATE='getinfo,connect' VALGRIND=0 TIMEOUT=10 TEST_DEBUG=1 pytest -vvv -s -p no:logging -n 6 tests/autogenerate-rpc-examples.py
```
8. The script saves logs in a file named `autogenerate-examples-status.log`, located in the root directory.
9. After running the script, execute `make` to ensure that the schema has been updated in all relevant locations, such as `...msggen/schema.json`.

### JSON Drinking Game!

1. Sip whenever you have an additional comma at the end of a sequence.
2. Sip whenever you omit a comma in a sequence because you cut & paste.
3. Skull whenever you wish JSON had comments.