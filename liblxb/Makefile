# SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
CC := gcc

# L4 Connection Tracing Support
# Full implementation when built with HAVE_L4_TRACE, stub functions otherwise
ifdef HAVE_L4_TRACE
CFLAGS_L4 := -DHAVE_L4_TRACE=1
else
CFLAGS_L4 :=
endif

CFLAGS := -g -Wall -I../common $(CFLAGS_L4)

all: lxb_l4_trace.o

lxb_l4_trace.o: lxb_l4_trace.c ../common/lxb_l4_trace_event.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o
