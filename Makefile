# SecureKeygen -- portable, dependency-free build.
#   make            build the library, CLI and test binary
#   make test       build and run the unit / known-answer tests
#   make selftest   build the CLI and run the embedded NIST/FIPS/RFC KATs
#   make asan       rebuild and run tests under AddressSanitizer + UBSan
#   make clean

CXX      ?= c++
CXXSTD   ?= -std=c++17
OPT      ?= -O2
WARN     := -Wall -Wextra -Wpedantic
INC      := -Iinclude
EXTRA    ?=
CXXFLAGS := $(CXXSTD) $(OPT) $(WARN) $(INC) $(EXTRA)

BUILD   := build
SRCS    := $(shell find src -name '*.cpp')
OBJS    := $(patsubst src/%.cpp,$(BUILD)/%.o,$(SRCS))
LIB     := $(BUILD)/libsecurekg.a
BIN     := $(BUILD)/securekg
TESTBIN := $(BUILD)/securekg_tests

# Link the OS entropy backend (bcrypt) on Windows builds only.
LDLIBS  :=
ifeq ($(OS),Windows_NT)
  LDLIBS += -lbcrypt
endif

.PHONY: all lib cli test selftest asan clean format
all: $(BIN) $(TESTBIN)
lib: $(LIB)
cli: $(BIN)

$(BUILD)/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

$(BIN): tools/securekg_main.cpp $(LIB)
	$(CXX) $(CXXFLAGS) $< $(LIB) $(LDLIBS) -o $@

$(TESTBIN): tests/test_main.cpp $(LIB)
	$(CXX) $(CXXFLAGS) $< $(LIB) $(LDLIBS) -o $@

test: $(TESTBIN)
	./$(TESTBIN)

selftest: $(BIN)
	./$(BIN) selftest

asan:
	$(MAKE) clean
	$(MAKE) test OPT=-O1 EXTRA="-g -fsanitize=address,undefined -fno-omit-frame-pointer"

format:
	@command -v clang-format >/dev/null 2>&1 \
	  && find src include tools tests fuzz \( -name '*.cpp' -o -name '*.h' \) -print0 \
	     | xargs -0 clang-format -i \
	  || echo "clang-format not found; skipping"

clean:
	rm -rf $(BUILD)
