CC = gcc
# CC = clang
CFLAGS = -I./include -Wall -Wextra -Werror -std=c99 -lpthread
PRJ = my_secmalloc
OBJS = src/my_secmalloc.o
SLIB = lib${PRJ}.a
LIB = lib/lib${PRJ}.so

all: ${LIB}

${LIB} : CFLAGS += -fpic #-shared
${LIB} : ${OBJS}

${SLIB}: ${OBJS}

dynamic: CFLAGS += -DDYNAMIC
dynamic: ${LIB}

static: CFLAGS += -DTEST
static: ${SLIB}

dyn_debug: CFLAGS += -DDEBUG
dyn_debug: dynamic

clean:
	${RM} src/.*.swp src/*~ src/*.o test/*.o

fclean: clean
	${RM} ${SLIB} ${LIB} test/test

build_test: CFLAGS += -DTEST
build_test: $(SLIB) test/test.o
	$(CC) -o test/test $^ -lmy_secmalloc -lcriterion -L. -ldl

test: build_test
	test/test


.PHONY: all clean build_test dynamic test static fclean dyn_debug

%.so:
	$(LINK.c) -shared $^ $(LDLIBS) -o $@

%.a:
	${AR} ${ARFLAGS} $@ $^
