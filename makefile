CC = g++
FLAGS = -std=c++11 -O2 -Wall -DDEBUG_OUT=0
LDFLAGS = -std=c++11 -Wall -lntl -lpthread
SRCDIR  = .
INCLUDEDIRS = ./include

SOURCES  = utils.cpp aes.cpp gf.cpp wbaes_tables.cpp wbaes.cpp
SOURCES += main.cpp

OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = main

.PHONY: all clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: $(SRCDIR)/%.cpp
	$(CC) $(FLAGS) $(foreach dir,$(INCLUDEDIRS),-I$(dir)) -c -o $@ $<

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)
