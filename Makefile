CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
LDFLAGS ?= -static-libstdc++ -static-libgcc
CPPFLAGS ?= -Iinclude

BUILD := build
BIN := bin
LIB_SOURCES := src/aes128.cpp src/signature.cpp src/analysis.cpp src/experiment.cpp
TEST_SOURCE := tests/test_main.cpp
HYBRID_TEST_SOURCE := tests/test_hybrid.cpp

.PHONY: all test test_hybrid clean

all: $(BIN)/subround_experiment

test: $(BIN)/tests
	./$(BIN)/tests

test_hybrid: $(BIN)/test_hybrid
	./$(BIN)/test_hybrid

$(BIN)/tests: $(LIB_SOURCES) $(TEST_SOURCE)
	mkdir -p $(BUILD) $(BIN)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LIB_SOURCES) $(TEST_SOURCE) $(LDFLAGS) -o $@

$(BIN)/test_hybrid: $(LIB_SOURCES) $(HYBRID_TEST_SOURCE)
	mkdir -p $(BUILD) $(BIN)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LIB_SOURCES) $(HYBRID_TEST_SOURCE) $(LDFLAGS) -o $@

$(BIN)/subround_experiment: $(LIB_SOURCES) src/main.cpp
	mkdir -p $(BUILD) $(BIN)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LIB_SOURCES) src/main.cpp $(LDFLAGS) -o $@

clean:
	rm -rf $(BUILD) $(BIN)
