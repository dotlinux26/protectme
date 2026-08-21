CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -Werror -I.
LDFLAGS = 

SRC = main.cpp \
      cli/cli.cpp cli/commands.cpp \
      daemon/daemon.cpp daemon/enforcer.cpp \
      policy/policy.cpp \
      audit/audit.cpp

OBJ = $(SRC:.cpp=.o)
TARGET = protectme

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo mkdir -p /etc/protectme
	sudo mkdir -p /var/log/protectme
	sudo touch /etc/protectme/protected

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall