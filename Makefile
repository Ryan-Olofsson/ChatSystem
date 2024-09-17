# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11 -Wall

# Libraries
LIBS = -lssl -lcrypto -lwebsocketpp -lboost_system

# Source files
SRCS = main.cpp User.cpp Server.cpp Neighbourhood.cpp

# Executable name
TARGET = onp

# Default target
all: $(TARGET)

# Linking the executable
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

# Clean up
clean:
	rm -f $(TARGET)

# Phony targets
.PHONY: all clean


