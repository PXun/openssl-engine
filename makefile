LIB_NAME ?= iwallcrypto
STATIC_NAME ?= lib$(LIB_NAME).a
#SHARE_NAME ?= lib$(LIB_NAME).so

#all: static_library shared_library
all: static_library
static_library:
	gcc -c *c;
	ar -cr $(STATIC_NAME) *.o;
#shared_library:
#	gcc -shared -fpic -o $(SHARE_NAME) *.c
clean:
	rm -fr *.o
cleanall:
	rm -fr *.o
	rm -fr *.a *.so
	rm -fr *.out
#gcc test_crypt.c -L. -liwallcrypto -lcrypto

