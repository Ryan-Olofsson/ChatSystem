# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -I$(PROJECT_ROOT)/external_libs/boost -I$(PROJECT_ROOT)/external_libs/websocketpp -I$(PROJECT_ROOT)/external_libs/openssl/include

# Libraries
LIBS = -L$(PROJECT_ROOT)/external_libs/openssl/lib -lssl -lcrypto -lboost_system

# Project root directory
PROJECT_ROOT = .

# Source files
SRCS = $(wildcard src/*.cpp)

# Object files
OBJS = $(SRCS:.cpp=.o)

# Executable name
TARGET = onp

# Default target
all: $(TARGET)

# Linking the executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

# Compiling source files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(TARGET) $(OBJS)

# Phony targets
.PHONY: all clean
