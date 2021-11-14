/* Simple speed tests using original critbit code (modified not to allocate).
 *
 * Results on my 32 bit Intel(R) Core(TM) i5 CPU M 560  @ 2.67GHz, gcc 4.5.2:
 * Run 100 times: Min-Max(Avg)
 #01: Initial insert:   237-257(239)
 #02: Initial lookup (match):   180-197(181)
 #03: Initial lookup (miss):   171-190(172)
 #04: Initial lookup (random):   441-455(446)
 #05: Initial delete all:   127-148(128)
 #06: Initial re-inserting:   219-298(221)
 #07: Deleting first half:   101-109(102)
 #08: Adding (a different) half:   159-165(160)
 #09: Lookup after half-change (match):   203-216(204)
 #10: Lookup after half-change (miss):   217-225(218)
 #11: Churn 1:   298-311(300)
 #12: Churn 2:   298-318(301)
 #13: Churn 3:   301-322(304)
 #14: Post-Churn lookup (match):   189-196(190)
 #15: Post-Churn lookup (miss):   189-197(191)
 #16: Post-Churn lookup (random):   500-531(506)
 */
#include <ccan/tal/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

/* CRITBIT source */
typedef struct {
  void *root;
} critbit0_tree;

int critbit0_contains(critbit0_tree *t, const char *u);
int critbit0_insert(critbit0_tree *t, const char *u);
int critbit0_delete(critbit0_tree *t, const char *u);
void critbit0_clear(critbit0_tree *t);
int critbit0_allprefixed(critbit0_tree *t, const char *prefix,
                         int (*handle) (const char *, void *), void *arg);

#define uint8 uint8_t
#define uint32 uint32_t

static size_t allocated;

/*2:*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <errno.h>

typedef struct{
void*child[2];
uint32 byte;
uint8 otherbits;
}critbit0_node;

/*:2*//*3:*/

int
critbit0_contains(critbit0_tree*t,const char*u){
const uint8*ubytes= (void*)u;
const size_t ulen= strlen(u);
uint8*p= t->root;

/*4:*/

if(!p)return 0;

/*:4*/

/*5:*/

while(1&(intptr_t)p){
critbit0_node*q= (void*)(p-1);
/*6:*/

uint8 c= 0;
if(q->byte<ulen)c= ubytes[q->byte];
const int direction= (1+(q->otherbits|c))>>8;

/*:6*/

p= q->child[direction];
}

/*:5*/

/*7:*/

return 0==strcmp(u,(const char*)p);

/*:7*/

}

/*:3*//*8:*/

int critbit0_insert(critbit0_tree*t,const char*u)
{
const uint8*const ubytes= (void*)u;
const size_t ulen= strlen(u);
uint8*p= t->root;

/*9:*/

if(!p){
#if 0
char*x;
int a= posix_memalign((void**)&x,sizeof(void*),ulen+1);
if(a)return 0;
memcpy(x,u,ulen+1);
t->root= x;
#else
t->root = (char *)u;
#endif
return 2;
}

/*:9*/

/*5:*/

while(1&(intptr_t)p){
critbit0_node*q= (void*)(p-1);
/*6:*/

uint8 c= 0;
if(q->byte<ulen)c= ubytes[q->byte];
const int direction= (1+(q->otherbits|c))>>8;

/*:6*/

p= q->child[direction];
}

/*:5*/

/*10:*/

/*11:*/

uint32 newbyte;
uint32 newotherbits;

for(newbyte= 0;newbyte<ulen;++newbyte){
if(p[newbyte]!=ubytes[newbyte]){
newotherbits= p[newbyte]^ubytes[newbyte];
goto different_byte_found;
}
}

if(p[newbyte]!=0){
newotherbits= p[newbyte];
goto different_byte_found;
}
return 1;

different_byte_found:

/*:11*/

/*12:*/

while(newotherbits&(newotherbits-1))newotherbits&= newotherbits-1;
newotherbits^= 255;
uint8 c= p[newbyte];
int newdirection= (1+(newotherbits|c))>>8;

/*:12*/


/*:10*/

/*13:*/

/*14:*/

critbit0_node*newnode;
if(posix_memalign((void**)&newnode,sizeof(void*),sizeof(critbit0_node)))return 0;
allocated++;
char*x;
#if 0
if(posix_memalign((void**)&x,sizeof(void*),ulen+1)){
free(newnode);
return 0;
}
memcpy(x,ubytes,ulen+1);
#else
x = (char *)u;
#endif
newnode->byte= newbyte;
newnode->otherbits= newotherbits;
newnode->child[1-newdirection]= x;

/*:14*/

/*15:*/

void**wherep= &t->root;
for(;;){
uint8*p= *wherep;
if(!(1&(intptr_t)p))break;
critbit0_node*q= (void*)(p-1);
if(q->byte> newbyte)break;
if(q->byte==newbyte&&q->otherbits> newotherbits)break;
uint8 c= 0;
if(q->byte<ulen)c= ubytes[q->byte];
const int direction= (1+(q->otherbits|c))>>8;
wherep= q->child+direction;
}

newnode->child[newdirection]= *wherep;
*wherep= (void*)(1+(char*)newnode);

/*:15*/


/*:13*/


return 2;
}

/*:8*//*16:*/

int critbit0_delete(critbit0_tree*t,const char*u){
const uint8*ubytes= (void*)u;
const size_t ulen= strlen(u);
uint8*p= t->root;
void**wherep= &t->root;
void**whereq= 0;
critbit0_node*q= 0;
int direction= 0;

/*17:*/

if(!p)return 0;

/*:17*/

/*18:*/

while(1&(intptr_t)p){
whereq= wherep;
q= (void*)(p-1);
uint8 c= 0;
if(q->byte<ulen)c= ubytes[q->byte];
direction= (1+(q->otherbits|c))>>8;
wherep= q->child+direction;
p= *wherep;
}

/*:18*/

/*19:*/

if(0!=strcmp(u,(const char*)p))return 0;
#if 0
free(p);
#endif

/*:19*/

/*20:*/

if(!whereq){
t->root= 0;
return 1;
}

*whereq= q->child[1-direction];
free(q);
allocated--;
/*:20*/


return 1;
}

/*:16*//*21:*/

static void
traverse(void*top){
/*22:*/

uint8*p= top;

if(1&(intptr_t)p){
critbit0_node*q= (void*)(p-1);
traverse(q->child[0]);
traverse(q->child[1]);
free(q);
allocated--;
}else{
#if 0
free(p);
#endif
}

/*:22*/

}

void critbit0_clear(critbit0_tree*t)
{
if(t->root)traverse(t->root);
t->root= NULL;
}

/*:21*//*23:*/

static int
allprefixed_traverse(uint8*top,
int(*handle)(const char*,void*),void*arg){
/*26:*/

if(1&(intptr_t)top){
critbit0_node*q= (void*)(top-1);
int direction;
for(direction= 0;direction<2;++direction)
switch(allprefixed_traverse(q->child[direction],handle,arg)){
case 1:break;
case 0:return 0;
default:return-1;
}
return 1;
}

/*:26*/

/*27:*/

return handle((const char*)top,arg);/*:27*/

}

int
critbit0_allprefixed(critbit0_tree*t,const char*prefix,
int(*handle)(const char*,void*),void*arg){
const uint8*ubytes= (void*)prefix;
const size_t ulen= strlen(prefix);
uint8*p= t->root;
uint8*top= p;
size_t i;

if(!p)return 1;
/*24:*/

while(1&(intptr_t)p){
critbit0_node*q= (void*)(p-1);
uint8 c= 0;
if(q->byte<ulen)c= ubytes[q->byte];
const int direction= (1+(q->otherbits|c))>>8;
p= q->child[direction];
if(q->byte<ulen)top= p;
}

/*:24*/

/*25:*/

for(i= 0;i<ulen;++i){
if(p[i]!=ubytes[i])return 1;
}

/*:25*/


return allprefixed_traverse(top,handle,arg);
}

/*:23*/
/* end critbit */

/* Nanoseconds per operation */
static size_t normalize(const struct timeabs *start,
			const struct timeabs *stop,
			unsigned int num)
{
	return time_to_nsec(time_divide(time_between(*stop, *start), num));
}

int main(int argc, char *argv[])
{
	size_t i, j, num;
	struct timeabs start, stop;
	critbit0_tree ct;
	char **words, **misswords;

	words = tal_strsplit(NULL, grab_file(NULL,
					 argv[1] ? argv[1] : "/usr/share/dict/words"), "\n", STR_NO_EMPTY);
	ct.root = NULL;
	num = tal_count(words) - 1;
	printf("%zu words\n", num);

	/* Append and prepend last char for miss testing. */
	misswords = tal_arr(words, char *, num);
	for (i = 0; i < num; i++) {
		char lastc;
		if (strlen(words[i]))
			lastc = words[i][strlen(words[i])-1];
		else
			lastc = 'z';
		misswords[i] = tal_fmt(misswords, "%c%s%c%c",
				       lastc, words[i], lastc, lastc);
	}

	printf("#01: Initial insert: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		critbit0_insert(&ct, words[i]);
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("Nodes allocated: %zu (%zu bytes)\n",
	       allocated, allocated * sizeof(critbit0_node));

	printf("#02: Initial lookup (match): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		if (!critbit0_contains(&ct, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#03: Initial lookup (miss): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++) {
		if (critbit0_contains(&ct, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Lookups in order are very cache-friendly for judy; try random */
	printf("#04: Initial lookup (random): ");
	fflush(stdout);
	start = time_now();
	for (i = 0, j = 0; i < num; i++, j = (j + 10007) % num)
		if (!critbit0_contains(&ct, words[j]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#05: Initial delete all: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		if (!critbit0_delete(&ct, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#06: Initial re-inserting: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		critbit0_insert(&ct, words[i]);
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#07: Deleting first half: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i+=2)
		if (!critbit0_delete(&ct, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#08: Adding (a different) half: ");
	fflush(stdout);

	start = time_now();
	for (i = 0; i < num; i+=2)
		critbit0_insert(&ct, misswords[i]);
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#09: Lookup after half-change (match): ");
	fflush(stdout);
	start = time_now();
	for (i = 1; i < num; i+=2)
		if (!critbit0_contains(&ct, words[i]))
			abort();
	for (i = 0; i < num; i+=2) {
		if (!critbit0_contains(&ct, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#10: Lookup after half-change (miss): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i+=2)
		if (critbit0_contains(&ct, words[i]))
			abort();
	for (i = 1; i < num; i+=2) {
		if (critbit0_contains(&ct, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Hashtables with delete markers can fill with markers over time.
	 * so do some changes to see how it operates in long-term. */
	printf("#11: Churn 1: ");
	start = time_now();
	for (j = 0; j < num; j+=2) {
		if (!critbit0_delete(&ct, misswords[j]))
			abort();
		if (critbit0_insert(&ct, words[j]) != 2)
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#12: Churn 2: ");
	start = time_now();
	for (j = 1; j < num; j+=2) {
		if (!critbit0_delete(&ct, words[j]))
			abort();
		if (critbit0_insert(&ct, misswords[j]) != 2)
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#13: Churn 3: ");
	start = time_now();
	for (j = 1; j < num; j+=2) {
		if (!critbit0_delete(&ct, misswords[j]))
			abort();
		if (critbit0_insert(&ct, words[j]) != 2)
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Now it's back to normal... */
	printf("#14: Post-Churn lookup (match): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		if (!critbit0_contains(&ct, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#15: Post-Churn lookup (miss): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++) {
		if (critbit0_contains(&ct, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Lookups in order are very cache-friendly for judy; try random */
	printf("#16: Post-Churn lookup (random): ");
	fflush(stdout);
	start = time_now();
	for (i = 0, j = 0; i < num; i++, j = (j + 10007) % num)
		if (!critbit0_contains(&ct, words[j]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	return 0;
}
