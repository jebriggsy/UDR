CXX = g++

ifndef os
	os = LINUX
endif

ifndef arch
	arch = AMD64
endif

CXXFLAGS = -Wall -finline-functions -g
CPPFLAGS = -D$(os) -I../udtproject/udt4/src 

ifeq ($(arch), IA32)
	CPPFLAGS += -DIA32 
	# CXXFLAGS += -mcpu=pentiumpro -march=pentiumpro -mmmx -msse
endif

ifeq ($(arch), POWERPC)
	CXXFLAGS += -mcpu=powerpc
endif

ifeq ($(arch), IA64)
	CPPFLAGS += -DIA64
endif

ifeq ($(arch), SPARC)
	CPPFLAGS += -DSPARC
endif

LDFLAGS = -L../src
LDLIBS = ../udtproject/udt4/src/libudt.a -lstdc++ -lpthread -lm -lssl -lcrypto

ifeq ($(os), UNIX)
	LDLIBS += -lsocket
endif

ifeq ($(os), OSX)
	LDLIBS += --L/usr/local/opt/openssl/lib
	CPPFLAGS += -I/usr/local/opt/openssl/include
endif

ifeq ($(os), SUNOS)
	LDFLAGS += -lrt -lsocket
endif




DIR = $(shell pwd)

APP = udr


all: $(APP)

udr.cpp udr_log.cpp: version.h
version.h:
	./version.sh

udr: udr.o udr_threads.o udr_util.o udr_options.o udr_rsh.o udr_crypt.o
	$(LINK.o) $^ $(LDLIBS) -o $@ 

clean:
	rm -f *.o $(APP)
	rm -rf $(DEPDIR)
	rm -f version.h

install:
	export PATH=$(DIR):$$PATH

# needed for auto dependency generation
SRCS := $(wildcard *.cpp)
# gnu auto dependency generation for cpp
DEPDIR := .deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.d
COMPILE.cc = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c

%.o : %.cpp
%.o : %.cpp $(DEPDIR)/%.d | $(DEPDIR)
	$(COMPILE.cpp) $(OUTPUT_OPTION) $<

$(DEPDIR): ; @mkdir -p $@

DEPFILES := $(SRCS:%.cpp=$(DEPDIR)/%.d)
$(DEPFILES):

include $(wildcard $(DEPFILES))

#end of gnu auto dependency generation