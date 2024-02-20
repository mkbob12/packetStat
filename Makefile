CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic -std=c++11
LDLIBS = -lpcap

all: packet-stat

packet-stat: packet-stat.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f packet-stat *.o
