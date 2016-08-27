BITS := 64

Targets := echo_server

echo_server_OBJS := echo_server.o

CXX := g++
CFLAGS := -I../../kernel_module

ifeq ($(BITS),32) 
CFLAGS += -DBINDER_IPC_32BIT
endif

all: $(Targets)

echo_server : $(echo_server_OBJS)
	$(CXX) $(CFLAGS) -o $@ $^

	
%.o : %.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<