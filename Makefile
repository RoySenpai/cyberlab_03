#################################################################################
# 	Cyber Laboratory Course Assignment 3 Makefile				#
# 	Authors: Roy Simanovich and Lidor Keren Yehushua (c) 2023			#
# 	Description: This Makefile compiles the programs and libraries 		#
# 				Date: 2023-05					#
# 			Course: Cyber Laboratory				#
# 				Assignment: 3					#
# 				Compiler: gcc					#
# 				OS: Linux					#
# 			IDE: Visual Studio Code					#
#################################################################################

# Flags for the compiler and linker.
CC = gcc
CFLAGS = -std=c11 -g
RM = rm -f

# Phony targets - targets that are not files but commands to be executed by make.
.PHONY: all clean

# Default target - compile everything and create the executables and libraries.
all: Attacker Ping


############
# Programs #
############
Attacker: Attacker.o
	$(CC) $(CFLAGS) -o $@ $^

Ping: Ping.o Ping_lib.o
	$(CC) $(CFLAGS) -o $@ $^

################
# Object files #
################
%.o: %.c
	$(CC) $(CFLAGS) -c $^
	
#################
# Cleanup files #
#################
clean:
	$(RM) *.gch *.o *.a *.so *.dll *.dylib stnc