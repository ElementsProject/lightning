#include <arpa/inet.h>
#include <assert.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <wire/wire.h>

#define BASE32DATA "abcdefghijklmnopqrstuvwxyz234567"




static char *b32_encode(char *dst, u8 *src, u8 ver) {
  u16 byte = 0,  
          poff = 0; 
  for(; byte < 	((ver==2)?16:56); poff += 5) {
    if(poff > 7) {
      poff -= 8;
      src++;
    }
    dst[byte++] = BASE32DATA[ (htobe16(*(u16*)src) >> (11 -poff)) & (u16)0x001F];
  }
  dst[byte] = 0;
  return dst;
}



//FIXME quiknditry
//int b32_decode( u8 *dst,u8 *src,u8 ver);

static int b32_decode( u8 *dst,u8 *src,u8 ver) {
 
  int rem = 0;
 
  int i;
  u8 *p=src;
  int buf;
  u8 ch;
  
  
  for (i=0; i < ((ver==2)?16:56) ; p++) {
    ch = *p;
    buf <<= 5;

   if ( (ch >= 'a' && ch <= 'z')) {
      ch = (ch & 0x1F) - 1;
    } else

  if (ch >= '2' && ch <= '7') {
      ch -= '2' - 0x1A ;
    } else {
      return -1;
    }
  
  buf = buf | ch;
    rem = rem + 5;
    if (rem >= 8) {
      dst[i++] = buf >> (rem - 8);
      rem -= 8;
    }
  }
 
  return 0;
}



/* Returns false if we didn't parse it, and *cursor == NULL if malformed. */
bool fromwire_wireaddr(const u8 **cursor, size_t *max, struct wireaddr *addr)
{
	addr->type = fromwire_u8(cursor, max);

	switch (addr->type) {
	case ADDR_TYPE_IPV4:
		addr->addrlen = 4;
		break;
	case ADDR_TYPE_IPV6:
		addr->addrlen = 16;
		break;
	case ADDR_TYPE_TOR_V2:
		addr->addrlen = TOR_V2_ADDRLEN;
		break;
	case ADDR_TYPE_TOR_V3:
		addr->addrlen = TOR_V3_ADDRLEN;
		break;
	
	default:
		return false;
	}
	fromwire(cursor, max, addr->addr, addr->addrlen);
	addr->port = fromwire_u16(cursor, max);

	return *cursor != NULL;
}


void towire_wireaddr(u8 **pptr, const struct wireaddr *addr)
{
	if (!addr || addr->type == ADDR_TYPE_PADDING) {
		towire_u8(pptr, ADDR_TYPE_PADDING);
		return;
	}
	towire_u8(pptr, addr->type);
	towire(pptr, addr->addr, addr->addrlen);
	towire_u16(pptr, addr->port);
}

char *fmt_wireaddr(const tal_t *ctx, const struct wireaddr *a)
{
	char addrstr[INET6_ADDRSTRLEN];
	char *ret, *hex;

	switch (a->type) {
	case ADDR_TYPE_IPV4:
		if (!inet_ntop(AF_INET, a->addr, addrstr, INET_ADDRSTRLEN))
			return "Unprintable-ipv4-address";
		return tal_fmt(ctx, "%s:%u", addrstr, a->port);
	case ADDR_TYPE_IPV6:
		if (!inet_ntop(AF_INET6, a->addr, addrstr, INET6_ADDRSTRLEN))
			return "Unprintable-ipv6-address";
		return tal_fmt(ctx, "[%s]:%u", addrstr, a->port);
	case ADDR_TYPE_TOR_V2:
   		return tal_fmt(ctx, "%s.onion:%u", b32_encode(addrstr, (u8 *)a->addr,2) , a->port);  
	case ADDR_TYPE_TOR_V3:
		return tal_fmt(ctx, "%s.onion:%u", b32_encode(addrstr, (u8 *)a->addr,3) , a->port);
 	case ADDR_TYPE_PADDING:
		break;
	}

	hex = tal_hexstr(ctx, a->addr, a->addrlen);
	ret = tal_fmt(ctx, "Unknown type %u %s:%u", a->type, hex, a->port);
	tal_free(hex);
	return ret;
}
REGISTER_TYPE_TO_STRING(wireaddr, fmt_wireaddr);

/* Valid forms:
 *
 * [anything]:<number>
 * anything-without-colons-or-left-brace:<number>
 * anything-without-colons
 * string-with-multiple-colons
 *
 * Returns false if it wasn't one of these forms.  If it returns true,
 * it only overwrites *port if it was specified by <number> above.
 */
static bool separate_address_and_port(tal_t *ctx, const char *arg,
				      char **addr, u16 *port)
{
	char *portcolon;

	if (strstarts(arg, "[")) {
		char *end = strchr(arg, ']');
		if (!end)
			return false;
		/* Copy inside [] */
		*addr = tal_strndup(ctx, arg + 1, end - arg - 1);
		portcolon = strchr(end+1, ':');
	} else {
		portcolon = strchr(arg, ':');
		if (portcolon) {
			/* Disregard if there's more than one : or if it's at
			   the start or end */
			if (portcolon != strrchr(arg, ':')
			    || portcolon == arg
			    || portcolon[1] == '\0')
				portcolon = NULL;
		}
		if (portcolon)
			*addr = tal_strndup(ctx, arg, portcolon - arg);
		else
			*addr = tal_strdup(ctx, arg);
	}

	if (portcolon) {
		char *endp;
		*port = strtol(portcolon + 1, &endp, 10);
		return *port != 0 && *endp == '\0';
	}
	return true;
}

//FIXME: SAIBATO todo make c-lightning auto temp onion hidden service
/*
 * 
 * make sure torrc config ok ( service port 9051 enabled)
connect 127.0.0.1:9051 Tor Service api


PROTOCOLINFO CR LF
 
250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE="/var/run/tor/control.authcookie"

open /var/run/tor/control.authcookie
cook = hex(var/run/tor/control.authcookie) 
AUTHENTICATE cook CR LF

if return ok 
i.e.
ADD_ONION NEW:RSA1024 Port=1234,127.0.0.1:1234

if ok
new tmp hidden_service created
echo service addr.onion to user 
thats all
*/


bool parse_wireaddr(const char *arg, struct wireaddr *addr, u16 defport,
		    const char **err_msg)
{
	struct in6_addr v6;
	struct in_addr v4;
	struct sockaddr_in6 *sa6;
	struct sockaddr_in *sa4;
	struct addrinfo *addrinfo;
	struct addrinfo hints;
	int gai_err;

	u8 tor_dec_bytes[TOR_V3_ADDRLEN];
	u16 port;
	char *ip;

	bool res;
	tal_t *tmpctx = tal_tmpctx(NULL);

          
    res = false;
	port = defport;
	if (err_msg)
		*err_msg = NULL;

	if (!separate_address_and_port(tmpctx, arg, &ip, &port))
		goto finish;


	if (streq(ip, "localhost"))
		ip = "127.0.0.1";
	else if (streq(ip, "ip6-localhost"))
		ip = "::1";

    memset(&addr->addr, 0, sizeof(addr->addr)); 
	
	if (inet_pton(AF_INET, ip, &v4) == 1) {
		addr->type = ADDR_TYPE_IPV4;
		addr->addrlen = 4;
		addr->port = port;
		memcpy(&addr->addr, &v4, addr->addrlen);
		res = true;
	} else if (inet_pton(AF_INET6, ip, &v6) == 1) {
		addr->type = ADDR_TYPE_IPV6;
		addr->addrlen = 16;
		addr->port = port;
		memcpy(&addr->addr, &v6, addr->addrlen);
		res = true;
	}


    if (strends(ip, ".onion"))
	{
	 
      if (strlen(ip)<25) {//FIXME boole is_V2_or_V3_TOR(addr);
		//odpzvneidqdf5hdq.onion
		addr->type =   ADDR_TYPE_TOR_V2;
		addr->addrlen = TOR_V2_ADDRLEN;
		addr->port = port;
		b32_decode((u8 *)tor_dec_bytes,(u8 *)ip,2);
		memcpy(&addr->addr,tor_dec_bytes, addr->addrlen);
		res = true;
	  }    
	 else {
		//4ruvswpqec5i2gogopxl4vm5bruzknbvbylov2awbo4rxiq4cimdldad.onion
		addr->type = ADDR_TYPE_TOR_V3;
		addr->addrlen = TOR_V3_ADDRLEN;
		addr->port = port;
		b32_decode((u8 *)tor_dec_bytes,(u8 *)ip,3);
		memcpy(&addr->addr,tor_dec_bytes, addr->addrlen);
		res = true;
	     }

  goto finish;

    };
       
	/* Resolve with getaddrinfo */
	if (!res) {
		memset(&hints, 0, sizeof(hints));

		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = 0;
		hints.ai_flags = AI_ADDRCONFIG;
		gai_err = getaddrinfo(ip, tal_fmt(tmpctx, "%d", port),
				      &hints, &addrinfo);
		if (gai_err != 0) {
			if (err_msg)
				*err_msg = gai_strerror(gai_err);
			goto finish;
		}
		/* Use only the first found address */
		if (addrinfo->ai_family == AF_INET) {
			addr->type = ADDR_TYPE_IPV4;
			addr->addrlen = 4;
			addr->port = port;
			sa4 = (struct sockaddr_in *) addrinfo->ai_addr;
			memcpy(&addr->addr, &sa4->sin_addr, addr->addrlen);
			res = true;
		} else if (addrinfo->ai_family == AF_INET6) {
			addr->type = ADDR_TYPE_IPV6;
			addr->addrlen = 16;
			addr->port = port;
			sa6 = (struct sockaddr_in6 *) addrinfo->ai_addr;
			memcpy(&addr->addr, &sa6->sin6_addr, addr->addrlen);
			res = true;

		}	 
 
		
		/* Clean up */
		freeaddrinfo(addrinfo);
	}

finish:
	if (!res && err_msg && !*err_msg)
		*err_msg = "Error parsing hostname";

	tal_free(tmpctx);
	return res;
	 
}
