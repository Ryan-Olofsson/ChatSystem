# compiler
CXX = g++

# compiler flags
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -I$(PROJECT_ROOT)/external_libs/boost -I$(PROJECT_ROOT)/external_libs/websocketpp -I$(PROJECT_ROOT)/external_libs/openssl/include

# libraries
LIBS = -L$(PROJECT_ROOT)/external_libs/openssl/lib -lssl -lcrypto -lboost_system

# project root directory
PROJECT_ROOT = .

# source files
SRCS = $(wildcard src/*.cpp)

# object files
OBJS = $(SRCS:.cpp=.o)

# executable name
TARGET = onp

# default target
all: $(TARGET)

# linking the executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

# compiling source files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# clean up
clean:
	rm -f $(TARGET) $(OBJS)

# install dependencies
install_deps:
	@while true; do \
		echo "You are about to install the dependencies for this application (WebSocket++ & OpenSSL). Proceed? (y/n)"; \
		read answer; \
		if [ "$$answer" = "y" ]; then \
			echo ""; \
			echo ""; \
			git clone https://github.com/zaphoyd/websocketpp.git $(PROJECT_ROOT)/external_libs/websocketpp; \
			echo ""; \
			echo ""; \
			git clone https://github.com/openssl/openssl.git $(PROJECT_ROOT)/external_libs/openssl; \
			echo ""; \
			echo ""; \
			cd $(PROJECT_ROOT)/external_libs/openssl && ./config && make && make install; \
			echo ""; \
			echo ""; \
			echo "Dependencies installed successfully."; \
			echo ""; \
			echo ""; \
			break; \
		elif [ "$$answer" = "n" ]; then \
			echo ""; \
			echo ""; \
			echo "Installation cancelled."; \
			echo ""; \
			echo ""; \
			break; \
		else \
			echo ""; \
			echo ""; \
			echo "Incorrect input. Please enter 'y' or 'n'."; \
			echo ""; \
			echo ""; \
		fi; \
	done

# phony targets
.PHONY: all clean install_deps
