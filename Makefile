CLANG ?= clang
LD_LLD ?= ld.lld
CC ?= cc
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
BUILD ?= build
SRC := src
LINK := link

IBSS_INPUT ?=
PATCHED_IBSS ?= $(BUILD)/ibss.yolodfu.bin
PONGO_INPUT ?=
PONGO_CONTAINER ?= $(BUILD)/pongo-container.bin

# Per-build yolo stub cave addresses — single source: tools/stub_addrs.py,
# derived from the iBSS input hash so the stubs are assembled for the exact
# cave they are installed at (patch_ibss cross-checks this too). Falls back to
# the 26.x caves when IBSS_INPUT is unset or unknown.
STUB_ADDRS := $(shell $(PYTHON) tools/stub_addrs.py "$(IBSS_INPUT)" 2>/dev/null)
WRAPPER_VA := $(patsubst WRAPPER_VA=%,%,$(filter WRAPPER_VA=%,$(STUB_ADDRS)))
RUNTIME_VA := $(patsubst RUNTIME_VA=%,%,$(filter RUNTIME_VA=%,$(STUB_ADDRS)))
WRAPPER_VA := $(if $(WRAPPER_VA),$(WRAPPER_VA),0x19c0ef318)
RUNTIME_VA := $(if $(RUNTIME_VA),$(RUNTIME_VA),0x19c17d7b8)

.PHONY: all runtime loader patch container audit clean

all: runtime loader $(BUILD)/build-container

runtime: $(BUILD)/hook.bin $(BUILD)/wrapper.bin $(BUILD)/runtime.bin

loader: $(BUILD)/loader.bin

$(BUILD):
	mkdir -p $@

$(BUILD)/vector.o: $(SRC)/vector.S | $(BUILD)
	$(CLANG) -target aarch64-none-elf -c $< -o $@

$(BUILD)/vector.elf: $(BUILD)/vector.o $(LINK)/vector.ld
	$(LD_LLD) -T $(LINK)/vector.ld $< -o $@

$(BUILD)/vector.bin: $(BUILD)/vector.elf
	$(LD_LLD) --oformat=binary -T $(LINK)/vector.ld $(BUILD)/vector.o -o $@

$(BUILD)/runtime.o: $(SRC)/runtime.S $(BUILD)/vector.bin | $(BUILD)
	$(CLANG) -target aarch64-none-elf -c $< -o $@

$(BUILD)/runtime.elf: $(BUILD)/runtime.o $(LINK)/runtime.ld
	$(LD_LLD) -T $(LINK)/runtime.ld $< -o $@

$(BUILD)/runtime.bin: $(BUILD)/runtime.elf
	$(LD_LLD) --oformat=binary -T $(LINK)/runtime.ld $(BUILD)/runtime.o -o $@

$(BUILD)/hook.o: $(SRC)/hook.S | $(BUILD)
	$(CLANG) -target aarch64-none-elf -DWRAPPER_VA=$(WRAPPER_VA) -c $< -o $@

$(BUILD)/hook.bin: $(BUILD)/hook.o
	$(LD_LLD) --oformat=binary -T $(LINK)/hook.ld $< -o $@

$(BUILD)/wrapper.o: $(SRC)/wrapper.S $(BUILD)/runtime.bin | $(BUILD)
	$(CLANG) -target aarch64-none-elf -DRUNTIME_VA=$(RUNTIME_VA) \
		-DYOLODFU_RUNTIME_SIZE=$$(wc -c < $(BUILD)/runtime.bin | tr -d ' ') -c $< -o $@

$(BUILD)/wrapper.bin: $(BUILD)/wrapper.o
	$(LD_LLD) --oformat=binary --defsym WRAPPER_VA=$(WRAPPER_VA) -T $(LINK)/wrapper.ld $< -o $@

$(BUILD)/loader.o: loader/loader_t8020.S | $(BUILD)
	$(CLANG) -target aarch64-none-elf -c $< -o $@

$(BUILD)/loader.bin: $(BUILD)/loader.o
	$(LD_LLD) --image-base=0 --oformat=binary -Ttext=0 $< -o $@
	@test "$$(wc -c < $@ | tr -d ' ')" = 512

$(BUILD)/build-container: loader/build_container.c | $(BUILD)
	$(CC) -O2 -Wall -Wextra $$($(PKG_CONFIG) --cflags liblz4) $< \
		-o $@ $$($(PKG_CONFIG) --libs liblz4)

patch: runtime
	@test -n "$(IBSS_INPUT)" || { echo "set IBSS_INPUT to the decrypted iBSS binary" >&2; exit 2; }
	$(PYTHON) tools/patch_ibss.py "$(IBSS_INPUT)" "$(PATCHED_IBSS)" --yolodfu
	$(PYTHON) tools/audit_artifact.py "$(PATCHED_IBSS)"

container: loader $(BUILD)/build-container
	@test -n "$(PONGO_INPUT)" || { echo "set PONGO_INPUT to Pongo.bin" >&2; exit 2; }
	$(BUILD)/build-container $(BUILD)/loader.bin "$(PONGO_INPUT)" "$(PONGO_CONTAINER)"

audit: runtime
	@test -n "$(PATCHED_IBSS)" || { echo "set PATCHED_IBSS to a patched iBSS" >&2; exit 2; }
	$(PYTHON) tools/audit_artifact.py "$(PATCHED_IBSS)"

clean:
	rm -rf $(BUILD)
