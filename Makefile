# Compiler name
cc := gcc

# Remove command
RM := rm -rf

# Source files
SOURCES := lib/mutation.c lib/log.c mutation-interface.c

# Object files
OBJS := $(SOURCES:.c=.o)



# Main target
main: $(OBJS)
	$(CC) -shared -g -o libmutation-interface.so $^

%.o: %.c
	$(CC) -c -g -Wall -Werror -fPIC -Ilib/ $< -o $@
 

.PHONY: clean
clean:
	$(RM) *.o *.so
	$(RM) lib/*.o lib/*.so