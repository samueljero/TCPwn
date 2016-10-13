
CXX 	= g++
INCLUDES = -I../include -I.
CFLAGS 	= -g -Wall

TARGET 	= searcher
SRCS = ../lib/graph.cpp ../lib/searcher.cpp main.cpp

ifndef BINDIR
  BINDIR := bin
endif
#=============================================

all: $(TARGET)

$(BINDIR):
	mkdir -p $@


$(TARGET): $(BINDIR)
	$(CXX) $(CFLAGS) $(INCLUDES) $(SRCS) -o $(BINDIR)/$@

clean: 
	rm -rf $(BINDIR)

