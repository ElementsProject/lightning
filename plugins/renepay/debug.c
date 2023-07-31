#include "config.h"
#include <plugins/renepay/debug.h>

void _debug_exec_branch(const char* fname,const char* fun, int lineno)
{
	FILE *f = fopen(fname,"a");
	fprintf(f,"executing line: %d (%s)\n",lineno,fun);
	fclose(f);
}

void _debug_outreq(const char *fname, const struct out_req *req)
{
	FILE *f = fopen(fname,"a");
	size_t len;
	const char * str =  json_out_contents(req->js->jout,&len);
	fprintf(f,"%s",str);
	if (req->errcb)
		fprintf(f,"}");
	fprintf(f,"}\n");
	fclose(f);
}

void _debug_call(const char* fname, const char* fun)
{
	FILE *f = fopen(fname,"a");
	fprintf(f,"calling function: %s\n",fun);
	fclose(f);
}

void _debug_reply(const char* fname, const char* buf,const jsmntok_t *toks)
{
	FILE *f = fopen(fname,"a");
	fprintf(f,"%.*s\n\n",
		   json_tok_full_len(toks),
		   json_tok_full(buf, toks));
	fclose(f);
}

void _debug_info(const char* fname, const char *fmt, ...)
{
	FILE *f = fopen(fname,"a");

	va_list args;
	va_start(args, fmt);

	vfprintf(f,fmt,args);

	va_end(args);
	fclose(f);
}

