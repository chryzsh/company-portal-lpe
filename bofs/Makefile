CC64 = x86_64-w64-mingw32-gcc
CC32 = i686-w64-mingw32-gcc
CFLAGS = -I common -Wall -Wno-format

BOFS = exchange/exchange apps/apps race/race checkin/checkin

all: $(addsuffix .x64.o,$(BOFS)) $(addsuffix .x86.o,$(BOFS))

%.x64.o: %.c common/beacon.h common/bofdefs.h
	$(CC64) $(CFLAGS) -c -o $@ $<

%.x86.o: %.c common/beacon.h common/bofdefs.h
	$(CC32) $(CFLAGS) -c -o $@ $<

clean:
	rm -f exchange/*.o apps/*.o race/*.o checkin/*.o

.PHONY: all clean
