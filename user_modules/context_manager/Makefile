
OBJS := context_manager.o

CXX := g++
CFLAGS := -I../../kernel_module

context_manager: $(OBJS)
	$(CXX) $(CFLAGS) -o $@ $^	

	
%.o : %.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<