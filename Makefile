CPPFLAGS = 
CFLAGS = -I../events/ -I../rotbuffer/ -O0 -g -Wall
LDFLAGS = -L../events/ -levents -L../rotbuffer/ -lrotbuffer

OBJS = afcgi.o

test: test.o $(OBJS)
	$(CC) -o test test.o $(OBJS) $(LDFLAGS)

clean:
	rm -f test test.o $(OBJS)

doc:
	doxygen afcgi.doxygen
 
cleandoc:
	rm -rf html man

