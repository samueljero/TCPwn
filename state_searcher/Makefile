#=======================================
# Build the project
#===================================

BINDIR 	:= bin
TOOLDIR	:= tool
CC	:= gcc
CXX	:= g++

#====================================

all: prep build

prep:
	mkdir -p $(BINDIR)

build:
	make -C $(TOOLDIR)/ BINDIR=../$(BINDIR)

	
clean:
	rm -rf $(BINDIR)/
	make -C $(TOOLDIR) clean
