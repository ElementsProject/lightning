lsps-types-wrongdir:
	$(MAKE) -C .. lsps-types-all

LSPS_TYPES_SOURCES = $(shell find lsps-types -name "*.rs")

lsps-types-all: ${LSPS_TYPES_SOURCES}
	$(CARGO) build ${CARGO_OPTS} -p lsps-types
