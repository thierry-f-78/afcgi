CPPFLAGS = 
CFLAGS = -I../events/ -O0 -g -Wall
LDFLAGS = -L../events/ -levents

OBJS = btree32.o afcgi.o rotbuffer.o

test: test.o $(OBJS)
	$(CC) -o test test.o $(OBJS) $(LDFLAGS)

clean:
	rm -f test test.o $(OBJS)

doc:
	doxygen afcgi.doxygen
 
cleandoc:
	rm -rf html man

