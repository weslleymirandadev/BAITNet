# IPv69 — top level.
#
#   c/       the C implementation (single static binary + examples + libs)
#   python/  the Python implementation (package ipv69, same wire formats)
#   docs/    specs and guides
#
# Every build/test target is forwarded to the C tree; nothing is built here.

TARGETS := all ipv69 chat hub bite win lib libwin libdemo crc caps clean

.PHONY: $(TARGETS)

$(TARGETS):
	$(MAKE) -C c $@
