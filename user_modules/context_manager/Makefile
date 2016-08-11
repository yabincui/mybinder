
OBJS := context_manager.o

CXX := g++
CFLAGS :=

context_manager: $(OBJS)
	$(CXX) $(CFLAGS) -o $@ $^	

	
%.o : %.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<