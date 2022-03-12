AR     ?= ar
LLC    ?= llc
CLANG  ?= clang
CC     ?= gcc

LIBBPF_DIR := ./libbpf/src
OBJECT_LIBBPF := $(LIBBPF_DIR)/libbpf.a

override CFLAGS += -I$(LIBBPF_DIR)/build/usr/include/ -I./headers/ -I./src/ -O2

XSKNFV_DIR    := ./src
XSKNFV_H      := $(XSKNFV_DIR)/xsknfv.h
XSKNFV_C      := $(XSKNFV_DIR)/xsknfv.c
XSKNFV_O      := ${XSKNFV_C:.c=.o}
XSKNFV_TARGET := $(XSKNFV_DIR)/libxsknfv.a

EXAMPLES := drop_macswap/drop_macswap \
			firewall/firewall \
			redirect_macswap/redirect_macswap \
			load_balancer/load_balancer
EXAMPLES_DIR     := ./examples
EXAMPLES_TARGETS := $(addprefix $(EXAMPLES_DIR)/,$(EXAMPLES))
EXAMPLES_USER	 := $(addsuffix _user.o,$(EXAMPLES_TARGETS))
EXAMPLES_KERN    := $(addsuffix _kern.o,$(EXAMPLES_TARGETS))
EXAMPLES_LD      := -L./src/ -lxsknfv -L$(LIBBPF_DIR) -l:libbpf.a -lelf -lpthread -lz
EXAMPLES_COMMON  := $(EXAMPLES_DIR)/common/statistics.o $(EXAMPLES_DIR)/common/utils.o

.PHONY: clean $(CLANG) $(LLC)

all: llvm-check $(XSKNFV_TARGET) $(EXAMPLES_TARGETS)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	$(RM) $(XSKNFV_O)
	$(RM) $(XSKNFV_TARGET)
	$(RM) $(EXAMPLES_USER)
	$(RM) $(EXAMPLES_TARGETS)
	$(RM) $(EXAMPLES_KERN)
	$(RM) $(EXAMPLES_COMMON)

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

$(XSKNFV_O): $(XSKNFV_C) $(XSKNFV_H) $(OBJECT_LIBBPF)

$(XSKNFV_TARGET): $(XSKNFV_O) $(XSKNFV_H)
	$(AR) r -o $@ $(XSKNFV_O)

$(EXAMPLES_KERN): %_kern.o: %_kern.c %.h $(OBJECT_LIBBPF)
	$(CLANG) -S \
		-target bpf \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		$(CFLAGS) \
		-emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	$(RM) ${@:.o=.ll}

$(EXAMPLES_TARGETS): %: %_user.o %_kern.o %.h $(EXAMPLES_COMMON) $(XSKNFV_TARGET)
	$(CC) $@_user.o $(EXAMPLES_COMMON) -o $@ $(EXAMPLES_LD) $(CFLAGS)