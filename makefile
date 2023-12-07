CC = g++
FLAGS = -std=c++11 -O2 -Wall -DDEBUG_OUT=1
LDFLAGS = -std=c++11 -Wall -lntl -lpthread
SRCDIR  = .
INCLUDEDIRS = .

SOURCES  = debug.cpp aes.cpp gf2_mat.cpp wbaes_tables.cpp wbaes.cpp
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
