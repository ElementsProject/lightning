#ifndef LIGHTNING_PLUGINS_RENEPAY_DEBUG_H
#define LIGHTNING_PLUGINS_RENEPAY_DEBUG_H
#include "config.h"
#include <ccan/json_out/json_out.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/type_to_string.h>
#include <plugins/libplugin.h>
#include <plugins/renepay/pay.h>
#include <stdio.h>
#include <wire/peer_wire.h>

void _debug_outreq(const char *fname, const struct out_req *req);
void _debug_reply(const char* fname, const char* buf,const jsmntok_t *toks);
void _debug_info(const char* fname, const char *fmt, ...);
void _debug_call(const char* fname, const char* fun);
void _debug_exec_branch(const char* fname,const char* fun, int lineno);

#ifndef MYLOG
#define MYLOG "/tmp/debug.txt"
#endif


/* All debug information goes to a file. */
#ifdef RENEPAY_UNITTEST

#define debug_info(...) \
	_debug_info(MYLOG,__VA_ARGS__)

#define debug_err(...) \
	{_debug_info(MYLOG,__VA_ARGS__); abort();}

#define debug_paynote(p,...) \
	{payment_note(p,__VA_ARGS__);_debug_info(MYLOG,__VA_ARGS__);}

#else
/* Debugging information goes either to payment notes or to lightningd log. */

#define debug_info(...) \
	plugin_log(pay_plugin->plugin,LOG_DBG,__VA_ARGS__)

#define debug_err(...) \
	plugin_err(pay_plugin->plugin,__VA_ARGS__)

#define debug_paynote(p,...) \
	payment_note(p,__VA_ARGS__);

#endif

#define debug_assert(expr) \
	if(!(expr)) debug_err("Assertion failed %s, file: %s, line %d", #expr,__FILE__,__LINE__)


#endif /* LIGHTNING_PLUGINS_RENEPAY_DEBUG_H */
