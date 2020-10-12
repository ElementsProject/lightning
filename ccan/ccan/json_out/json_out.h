/* MIT (BSD) license - see LICENSE file for details */
#ifndef CCAN_JSON_OUT_H
#define CCAN_JSON_OUT_H
#include <ccan/compiler/compiler.h>
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <stddef.h>

struct json_out;

/**
 * json_out_new - allocate a json_out stream.
 * @ctx: the tal_context to allocate from, or NULL
 *
 * Returns NULL if tal allocation fails.
 */
struct json_out *json_out_new(const tal_t *ctx);

/**
 * json_out_call_on_move - callback for when buffer is reallocated.
 * @jout: the json_out object to attach to.
 * @cb: the callback to call.
 * @arg: the argument to @cb (must match type).
 *
 * A NULL @cb disables.  You can't currently have more than one callback.
 * The @delta argument to @cb is the difference between the old location
 * and the new one, and is never zero.
 */
#define json_out_call_on_move(jout, cb, arg)				\
	json_out_call_on_move_((jout),					\
			       typesafe_cb_preargs(void, void *,	\
						   (cb), (arg),		\
						   struct json_out *,	\
						   ptrdiff_t),		\
			       (arg))

void json_out_call_on_move_(struct json_out *jout,
			    void (*cb)(struct json_out *jout, ptrdiff_t delta,
				       void *arg),
			    void *arg);

/**
 * json_out_dup - duplicate a json_out stream.
 * @ctx: the tal_context to allocate from, or NULL
 * @src: the json_out to copy.
 */
struct json_out *json_out_dup(const tal_t *ctx, const struct json_out *src);

/**
 * json_out_start - start an array or object.
 * @jout: the json_out object to write into.
 * @fieldname: the fieldname, if inside an object, or NULL if inside an array.
 * @type: '[' or '{' to start an array or object, respectively.
 *
 * Returns true unless tal_resize() fails.
 * Literally writes '"@fieldname": @type' or '@type ' if fieldname is NULL.
 * @fieldname must not need JSON escaping.
 */
bool json_out_start(struct json_out *jout, const char *fieldname, char type);

/**
 * json_out_end - end an array or object.
 * @jout: the json_out object to write into.
 * @type: '}' or ']' to end an array or object, respectively.
 *
 * Returns true unless tal_resize() fails.
 *
 * Literally writes ']' or '}', keeping track of whether we need to append
 * a comma.
 */
bool json_out_end(struct json_out *jout, char type);

/**
 * json_out_add - add a formatted member.
 * @jout: the json_out object to write into.
 * @fieldname: optional fieldname to prepend (must not need escaping).
 * @quote: if true, surround fmt by " and ".
 * @fmt...: the printf-style format
 *
 * Returns true unless tal_resize() fails.
 *
 * If you're in an array, @fieldname must be NULL.  If you're in an
 * object, @fieldname must be non-NULL.  This is checked if
 * CCAN_JSON_OUT_DEBUG is defined.
 * @fieldname must not need JSON escaping.
 *
 * If the resulting string requires escaping, and @quote is true, we
 * call json_escape().
 */
PRINTF_FMT(4,5)
bool json_out_add(struct json_out *jout,
		  const char *fieldname,
		  bool quote,
		  const char *fmt, ...);

/**
 * json_out_addv - add a formatted member (vararg variant)
 * @jout: the json_out object to write into.
 * @fieldname: optional fieldname to prepend.
 * @quote: if true, surround fmt by " and ".
 * @fmt: the printf-style format
 * @ap: the argument list.
 *
 * See json_out_add() above.
 */
bool json_out_addv(struct json_out *jout,
		   const char *fieldname,
		   bool quote,
		   const char *fmt,
		   va_list ap);

/**
 * json_out_addstr - convenience helper to add a string field.
 * @jout: the json_out object to write into.
 * @fieldname: optional fieldname to prepend.
 * @str: the string to add (must not be NULL).
 *
 * Equivalent to json_out_add(@jout, @fieldname, true, "%s", @str);
 */
bool json_out_addstr(struct json_out *jout,
		     const char *fieldname,
		     const char *str);

/**
 * json_out_member_direct - add a field, with direct access.
 * @jout: the json_out object to write into.
 * @fieldname: optional fieldname to prepend.
 * @extra: how many bytes to allocate.
 *
 * @fieldname must not need JSON escaping.  Returns a direct pointer into
 * the @extra bytes, or NULL if tal_resize() fails.
 *
 * This allows you to write your own efficient type-specific helpers.
 */
char *json_out_member_direct(struct json_out *jout,
			     const char *fieldname, size_t extra);

/**
 * json_out_direct - make room in output and access directly.
 * @jout: the json_out object to write into.
 * @len: the length to allocate.
 *
 * This lets you access the json_out stream directly, to save a copy,
 * if you know exactly how much you will write.
 *
 * Returns a pointer to @len bytes at the end of @jout, or NULL if
 * tal_resize() fails.
 *
 * This is dangerous, since it doesn't automatically prepend a ","
 * like the internal logic does, but can be used (carefully) to add
 * entire objects, or whitespace.
 */
char *json_out_direct(struct json_out *jout, size_t extra);

/**
 * json_out_add_splice - copy a field from another json_out.
 * @jout: the json_out object to write into.
 * @fieldname: optional fieldname to prepend.
 * @src: the json_out object to copy from.
 *
 * This asserts that @src is well-formed (as per json_out_finished()),
 * then places it into @jout with optional @fieldname prepended.  This
 * can be used to assemble sub-objects for your JSON and then copy
 * them in.
 *
 * Note that it will call json_out_contents(@src), so it expects that
 * object to be unconsumed.
 *
 * Returns false if tal_resize() fails.
 */
bool json_out_add_splice(struct json_out *jout,
			 const char *fieldname,
			 const struct json_out *src);

/**
 * json_out_finished - assert that the json buffer is finished.
 * @jout: the json_out object written to.
 *
 * This simply causes internal assertions that all arrays and objects are
 * finished. If CCAN_JSON_OUT_DEBUG is defined, it does sanity checks.
 *
 * This also resets the empty flag, so there will be no comma added if
 * another JSON object is written.
 */
void json_out_finished(struct json_out *jout);

/**
 * json_out_contents - read contents from json_out stream.
 * @jout: the json_out object we want to read from.
 * @len: set to the length of the buffer returned.
 *
 * This returns a pointer into the JSON written so far.  Returns NULL
 * and sets @len to 0 if there's nothing left in the buffer.
 */
const char *json_out_contents(const struct json_out *jout, size_t *len);

/**
 * json_out_consume - discard contents from json_out stream.
 * @jout: the json_out object we read from.
 * @len: the length to consume (must be <= @len from json_out_contents)
 */
void json_out_consume(struct json_out *jout, size_t len);
#endif /* CCAN_JSON_OUT_H */
