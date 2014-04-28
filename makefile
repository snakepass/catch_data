CC := g++
SRCS := $(wildcard src/*.cpp)
LDLIBS += -lpcap -ltcmalloc -lpthread
LDFLAGS += -L ./lib/pcap/1.4/ -L ./lib/gperf/2.1/
CPPFLAGS += -Wall -Werror -g -O2 -I include -I include/pcap
TARGET := sniffer

release: CPPFLAGS += -D NDEBUG

release: $(SRCS)
	$(CC) $(CPPFLAGS) -o $(TARGET) $+ $(LDFLAGS) $(LDLIBS)

debug: $(SRCS)
	$(CC) $(CPPFLAGS) -o $(TARGET) $+ $(LDFLAGS) $(LDLIBS)

clean:  
	$(RM) *.o $(TARGET)
