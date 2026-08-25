# IPv69 - build
NASM    := nasm
LD      := ld
ASFLAGS := -f elf64 -Isrc
BUILD   := build

BINS := ipv69 ipv69_send

all: $(BINS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.asm | $(BUILD)
	$(NASM) $(ASFLAGS) -o $@ $<

$(BUILD)/ipv69.o: src/ipv69.asm src/header.asm src/bigendian.asm src/parse.asm
$(BUILD)/send.o: src/send.asm src/header.asm src/bigendian.asm

ipv69: $(BUILD)/ipv69.o
	$(LD) -o $@ $^

ipv69_send: $(BUILD)/send.o
	$(LD) -o $@ $^


.PHONY: all
