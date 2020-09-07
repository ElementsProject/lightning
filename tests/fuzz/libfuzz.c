#include <tests/fuzz/libfuzz.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	run(data, size);

	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	init(argc, argv);

	return 0;
}
