#ifndef LIGHTNING_COMMON_AUTODATA_H
#define LIGHTNING_COMMON_AUTODATA_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/cppmagic/cppmagic.h>
#include <stddef.h>

#define AUTODATA_TYPE(name, type)					\
	static inline void register_autotype_##name(const type *t) {	\
		autodata_register_(#name, t);				\
	}								\
	typedef type autodata_##name##_

/* This uses GCC's constructor attribute */
#define AUTODATA(name, ptr)						\
	static __attribute__((constructor)) NEEDED			\
	void CPPMAGIC_GLUE2(register_one_##name,__COUNTER__)(void) {	\
		register_autotype_##name(ptr);				\
	}

#define autodata_get(name, nump)					\
	((autodata_##name##_ **)autodata_get_(#name, (nump)))

void autodata_register_(const char *typename, const void *ptr);
void *autodata_get_(const char *typename, size_t *nump);

/* Call on shutdown to keep valgrind leak detection happy. */
void autodata_cleanup(void);
#endif /* LIGHTNING_COMMON_AUTODATA_H */
