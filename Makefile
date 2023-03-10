#compiler name
cc := gcc

#remove command
RM := rm -rf

#source files
SOURCES := mutation-interface.c mutation.c

#object files
OBJS := $(SOURCES:.c=.o)



#main target
main: $(OBJS)
	$(CC) -shared -g -o libmutation-interface.so $^

%.o: %.c
	$(CC) -c -g -Wall -Werror -fPIC $< -o $@
 

.PHONY: clean
clean:
	$(RM) *.o *.so