#To add a main file, put it in "TARGETS"
#This assumes it will have a respective cpp file
#copy an existing main rule and replace its trail with the appropriate object file

#All headers must be in DEPS because they will require full compiling if they redefine function

#To add a header template / implementation pair, add the header to _DEPS and the
#implementation to _OBJ

INSTALLDIR :=/usr/local/bin
SRCDIR     :=${CURDIR}
IDIR       :=${CURDIR}/../include
ODIR       :=${CURDIR}/../obj
CXX        :=g++
CXXFLAGS   :=-std=c++17 -O3 -flto -Wall -Werror -Wextra -I${IDIR}
LDFLAGS    :=-lcrypto -lssl

#macos brew puts openssl headers in a non default path
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	CXXFLAGS      += -I/usr/local/opt/openssl/include/
	LDFLAGS       += -L/usr/local/opt/openssl/lib
	MAN_DIRECTORY := /usr/local/share/man/man1
endif
ifeq ($(UNAME_S),Linux)
	MAN_DIRECTORY := /usr/local/man/man1
endif

TARGETS = jaySA

_DEPS  := crypto.h base64.h
DEPS   := $(patsubst %,${IDIR}/%,${_DEPS})

_MAINS := $(addsuffix .o, ${TARGETS})
MAINS  := $(patsubst %,${ODIR}/%,${_MAINS})

_OBJ   := $(patsubst %.h, %.o, ${_DEPS}) ${_MAINS}
OBJ    := $(patsubst %,${ODIR}/%,${_OBJ})

.PHONY: all install uninstall remove clean

all: ${TARGETS}

install: all
	@if [ ! -d ${MAN_DIRECTORY} ]; then mkdir ${MAN_DIRECTORY}; fi
	for i in ${TARGETS}; do cp -f $$i ${INSTALLDIR}/$$i; cp -f $$i.man ${MAN_DIRECTORY}/$$i.1; gzip -f ${MAN_DIRECTORY}/$$i.1; done

uninstall:
	for i in ${TARGETS}; do rm -f ${INSTALLDIR}/$$i; rm -f ${MAN_DIRECTORY}/$$i.1.gz; done


remove:
	rm -f ${TARGETS}

clean:
	rm -f ${ODIR}/*.o

${OBJ}: ${ODIR}/%.o : ${SRCDIR}/%.cpp ${DEPS}
	${CXX} -c -o $@ $< ${CXXFLAGS}

${TARGETS}: % : $(filter-out ${MAINS}, ${OBJ}) ${ODIR}/%.o
	${CXX} -o $@ $^ ${CXXFLAGS} ${LDFLAGS}
