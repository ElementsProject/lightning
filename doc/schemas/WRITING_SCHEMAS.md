# Writing JSON Schemas

A JSON Schema is a JSON file which defines what a structure should
look like; in our case we use it in our testsuite to check that they
match command responses, and also use it to generate our
documentation.

Yes, schemas are horrible to write, but they're damn useful.  We can
only use a subset of the full [https://json-schema.org/](JSON Schema
Specification), but if you find that limiting it's probably a sign
that you should simplify your JSON output.

## How to Write a Schema

Name the schema doc/schemas/`command`.schema.json: the testsuite should
pick it up and check all invocations of that command against it.

I recommend copying an existing one to start.

You will need to put the magic lines in the manual page so `make doc-all`
will fill it in for you:

```
[comment]: # (GENERATE-FROM-SCHEMA-START)
[comment]: # (GENERATE-FROM-SCHEMA-END)
```

If something goes wrong, try tools/fromscheme.py
doc/schemas/`command`.schema.json to see how far it got before it died.

You should always use `"additionalProperties": false`, otherwise
your schema might not be covering everything.  Deprecated fields
simply have `"deprecated": true` in their properties, so they
are allowed by omitted from the documentation.

You should always list all fields which are *always* present in
`"required"`.

We extend the basic types; see
[contrib/pyln-testing/pyln/testing/fixtures.py](fixtures.py).

In addition, before committing a new schema or a new version of it, make sure that it
is well formatted. If you don't want do it by hand, use `make fmt-schema` that uses
jq under the hood.

### Using Conditional Fields

Sometimes one field is only sometimes present; if you can, you should make
the schema know when it should (and should not!) be there.

There are two kinds of conditional fields expressable: fields which
are only present if another field is present, or fields only present
if another field has certain values.

To add conditional fields:

1. Do *not* mention them in the main "properties" section.
2. Set `"additionalProperties": true` for the main "properties" section.
3. Add an `"allOf": [` array at the same height as `"properties"'`.  Inside
   this place one `if`/`then` for each conditional field.
4. If a field simply requires another field to be present, use the pattern
   `"required": [ "field" ]` inside the "if".
5. If a field requires another field value, use the pattern
   `"properties": { "field": { "enum": [ "val1", "val2" ] } }` inside
   the "if".
6. Inside the "then", use `"additionalProperties": false` and place
   empty `{}` for all the other possible properties.
7. If you haven't covered all the possibilties with `if` statements,
   add an `else` with `"additionalProperties": false` which simply
   mentions every allowable property.  This ensures that the fields
   can *only* be present when conditions are met.

### JSON Drinking Game!

1. Sip whenever you have an additional comma at the end of a sequence.
2. Sip whenever you omit a comma in a sequence because you cut & paste.
3. Skull whenever you wish JSON had comments.

Good luck!
Rusty.
