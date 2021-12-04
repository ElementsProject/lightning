# Care And Feeding of Your Fellow Coders

Style is an individualistic thing, but working on software is group
activity, so consistency is important.  Generally our coding style
is similar to the [Linux coding style][style].

[style]: https://www.kernel.org/doc/html/v4.10/process/coding-style.html

## Communication

We communicate with each other via code; we polish each others code,
and give nuanced feedback.  Exceptions to the rules below always
exist: accept them.  Particularly if they're funny!

## Prefer Short Names

`num_foos` is better than `number_of_foos`, and `i` is better than
`counter`.  But `bool found;` is better than `bool ret;`.  Be as
short as you can but still descriptive.

## Prefer 80 Columns

We have to stop somewhere.  The two tools here are extracting
deeply-indented code into their own functions, and use of short-cuts
using early returns or continues, eg:

```C
	for (i = start; i != end; i++) {
		if (i->something)
			continue;

		if (!i->something_else)
			continue;

		do_something(i);
}
```

## Tabs and indentaion

The C code uses TAB charaters with a visual indentation of 8 whitespaces.
If you submit code for a review, make sure your editor knows this.

When breaking a line with more than 80 characters, align parameters and
arguments like so:

```C
static void subtract_received_htlcs(const struct channel *channel,
				    struct amount_msat *amount)
```

Note: For more details, the files `.clang-format` and `.editorconfig` are
located in the projects root directory.

## Prefer Simple Statements

Notice the statement above uses separate tests, rather than combining
them.  We prefer to only combine conditionals which are fundamentally
related, eg:

```C
	if (i->something != NULL && *i->something < 100)
```

## Use of `take()`

Some functions have parameters marked with `TAKES`, indicating that
they can take lifetime ownership of a parameter which is passed using
`take()`.  This can be a useful optimization which allows the function
to avoid making a copy, but if you hand `take(foo)` to something which
doesn't support `take()` you'll probably leak memory!

In particular, our automatically generated marshalling code doesn't
support `take()`.

If you're allocating something simply to hand it via `take()` you
should use NULL as the parent for clarity, eg:

```C
	msg = towire_shutdown(NULL, &peer->channel_id, peer->final_scriptpubkey);
	enqueue_peer_msg(peer, take(msg));
```

## Use of `tmpctx`

There's a convenient temporary tal context which gets cleaned
regularly: you should use this for throwaways rather than (as you'll
see some of our older code do!) grabbing some passing object to hang
your temporaries off!

## Enums and Switch Statements

If you handle various enumerated values in a `switch`, don't use
`default:` but instead mention every enumeration case-by-case.  That
way when a new enumeration case is added, most compilers will warn that you
don't cover it.  This is particularly valuable for code auto-generated
from the specification!

## Initialization of Variables

Avoid double-initialization of variables; it's better to set them when
they're known, eg:

```C
	bool is_foo;
	
	if (bar == foo)
		is_foo = true;
	else
		is_foo = false;

	...
	if (is_foo)...
```

This way the compiler will warn you if you have one path which doesn't set the
variable.  If you initialize with `bool is_foo = false;` then you'll
simply get that value without warning when you change the code and
forget to set it on one path.

## Initialization of Memory

`valgrind` warns about decisions made on uninitialized memory.  Prefer
`tal` and `tal_arr` to `talz` and `tal_arrz` for this reason, and
initialize only the fields you expect to be used.

Similarly, you can use `memcheck(mem, len)` to explicitly assert that
memory should have been initialized, rather than having valgrind
trigger later.  We use this when placing things on queues, for example.

## Use of static and const

Everything should be declared static and const by default.  Note that
`tal_free()` can free a const pointer (also, that it returns `NULL`, for
convenience).

## Typesafety Is Worth Some Pain

If code is typesafe, refactoring is as simple as changing a type and
compiling to find where to refactor.  We rely on this,
so most places in the code will break if you hand the wrong type, eg
`type_to_string` and `structeq`.

The two tools we have to help us are complicated macros in
`ccan/typesafe_cb` allow you to create callbacks which must match the
type of their argument, rather than using `void *`.  The other is
`ARRAY_SIZE`, a macro which won't compile if you hand it a pointer
instead of an actual array.

## Use of `FIXME`

There are two cases in which you should use a `/* FIXME: */` comment:
one is where an optimization is possible but it's not clear that it's
yet worthwhile, and the second one is to note an ugly corner case
which could be improved (and may be in a following patch).

There are always compromises in code: eventually it needs to ship.
`FIXME` is `grep`-fodder for yourself and others, as well as useful
warning signs if we later encounter an issue in some part of the code.

## If You Don't Know The Right Thing, Do The Simplest Thing

Sometimes the right way is unclear, so it's best not to spend time on
it.  It's far easier to rewrite simple code than complex code, too.

## Write For Today: Unused Code Is Buggy Code

Don't overdesign: complexity is a killer.  If you need a fancy data
structure, start with a brute force linked list.  Once that's working,
perhaps consider your fancy structure, but don't implement a generic
thing.  Use `/* FIXME: ...*/` to salve your conscience.

## Keep Your Patches Reviewable

Try to make a single change at a time.  It's tempting to do "drive-by"
fixes as you see other things, and a minimal amount is unavoidable, but
you can end up shaving infinite yaks.  This is a good time to drop a 
`/* FIXME: ...*/` comment and move on.

## Creating JSON APIs

Our JSON RPCs always return a top-level object.  This allows us to add
warnings (e.g. that we're still starting up) or other optional fields
later.

Prefer to use JSON names which are already in use, or otherwise names
from the BOLT specifications.

The same command should always return the same JSON format: this is
why e.g. `listchannels` return an array even if given an argument so
there's only zero or one entries.

All `warning` fields should have unique names which start with
`warning_`, the value of which should be an explanation.  This allows
for programs to deal with them sanely, and also perform translations.

### Documenting JSON APIs

We use JSON schemas to validate that JSON-RPC returns are in the
correct form, and also to generate documentation.  See
[doc/schemas/WRITING_SCHEMAS.md](WRITING_SCHEMAS.md).

## Changing JSON APIs

All JSON API changes need a Changelog line (see below).

You can always add a new output JSON field (Changelog-Added), but you
cannot remove one without going through a 6-month deprecation cycle
(Changelog-Deprecated)

So, only output it if `allow-deprecated-apis` is true, so users can test
their code is futureproof.  In 6 months remove it (Changelog-Removed).

Changing existing input parameters is harder, and should generally be
avoided.  Adding input parameters is possible, but should be done
cautiously as too many parameters get unwieldy quickly.

## Github Workflows

We have adopted a number of workflows to facilitate the development of
c-lightning, and to make things more pleasant for contributors.

### Changelog Entries in Commit Messages

We are maintaining a changelog in the top-level directory of this
project. However since every pull request has a tendency to touch the file and
therefore create merge-conflicts we decided to derive the changelog file from
the pull requests that were added between releases. In order for a pull
request to show up in the changelog at least one of its commits will have to
have a line with one of the following prefixes:

 - `Changelog-Added: ` if the pull request adds a new feature
 - `Changelog-Changed: ` if a feature has been modified and might require
   changes on the user side
 - `Changelog-Deprecated: ` if a feature has been marked for deprecation, but
   not yet removed
 - `Changelog-Fixed: ` if a bug has been fixed
 - `Changelog-Removed: ` if a (previously deprecated) feature has been removed
 - `Changelog-Experimental: ` if it only affects --enable-experimental-features builds, or experimental- config options.
 
In case you think the pull request is small enough not to require a changelog
entry please use `Changelog-None` in one of the commit messages to opt out.
 
Under some circumstances a feature may be removed even without deprecation
warning if it was not part of a released version yet, or the removal is
urgent.

In order to ensure that each pull request has the required `Changelog-*:` line
for the changelog our trusty @bitcoin-bot will check logs whenever a pull
request is created or updated and search for the required line. If there is no
such line it'll mark the pull request as `pending` to call out the need for an
entry.
