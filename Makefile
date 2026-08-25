# IPv69 - build
NASM    := nasm
LD      := ld
ASFLAGS := -f elf64 -Isrc/IPv69
BUILD   := build

BINS := ipv69 ipv69_send

all: $(BINS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: tests/%.asm | $(BUILD)
	$(NASM) $(ASFLAGS) -o $@ $<

$(BUILD)/ipv69.o: tests/ipv69.asm src/IPv69/header.asm src/IPv69/bigendian.asm src/IPv69/parse.asm
$(BUILD)/send.o: tests/send.asm src/IPv69/header.asm src/IPv69/bigendian.asm

ipv69: $(BUILD)/ipv69.o
	$(LD) -o build/$@ $^

ipv69_send: $(BUILD)/send.o
	$(LD) -o build/$@ $^


.PHONY: all
