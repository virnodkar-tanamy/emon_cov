MAKE    :=  /usr/bin/make
CC=cc
CFLAGS=-march=x86-64 -O2 -I/usr/include/svos -I/usr/include/svos/sv -I/usr/include/svos/sv/rocket -lsv -lrocket

emon_cov:emon_cov.o
	$(CC) emon_cov.c -g -o $@ $(CFLAGS)
