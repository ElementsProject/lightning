#!/usr/bin/make

LIBHSMD_PY_GEN_FILES := contrib/libhsmd_python/swig_wrap.c \
	contrib/libhsmd_python/libhsmd.py

PYTHON_GENERATED += contrib/libhsmd_python/libhsmd.py
CPPCHECK_OPTS += --suppress=nullPointer:contrib/libhsmd_python/swig_wrap.c

# Swig by default generates stubs in the file's directory, which is
# what we want.
$(LIBHSMD_PY_GEN_FILES): contrib/libhsmd_python/swig.i $(HSMD_SRC)
	swig -python -builtin contrib/libhsmd_python/swig.i
