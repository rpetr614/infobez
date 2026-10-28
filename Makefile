# Сборка: make         Самопроверка: make selftest
# На macOS нужна GMP:  brew install gmp   (libcurl уже есть в системе)
# На Ubuntu/Debian:    sudo apt install libgmp-dev libcurl4-openssl-dev

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
LDLIBS   := -lcurl -lgmp -pthread

# На некоторых старых версиях GCC std::filesystem требует отдельной библиотеки.
ifeq ($(shell uname -s),Linux)
  LDLIBS += -lstdc++fs
endif

# Homebrew ставит GMP в /opt/homebrew (Apple Silicon) или /usr/local (Intel) —
# находим префикс автоматически.
BREW_GMP := $(shell brew --prefix gmp 2>/dev/null)
ifneq ($(BREW_GMP),)
  CPPFLAGS += -I$(BREW_GMP)/include
  LDFLAGS  += -L$(BREW_GMP)/lib
endif

HEADERS := kuznyechik.hpp rsa_gmp.hpp pdf_writer.hpp secure_random.hpp gost3410.hpp asn1.hpp pdf_signature.hpp

auth3fa: auth3fa.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ auth3fa.cpp $(LDFLAGS) $(LDLIBS)

selftest: auth3fa
	./auth3fa --selftest

clean:
	rm -f auth3fa

.PHONY: selftest clean
