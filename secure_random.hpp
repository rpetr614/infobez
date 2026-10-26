// secure_random.hpp
// Криптографически стойкий генератор случайных чисел операционной системы.
// Для ключей, IV и солей НЕЛЬЗЯ использовать std::mt19937 — его состояние
// восстанавливается по 624 выходам. Здесь используется:
//   - macOS / Linux: /dev/urandom (ядерный CSPRNG);
//   - Windows: BCryptGenRandom.
#pragma once

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <cstdio>
#endif

namespace securerand {

inline void fill(uint8_t* buf, size_t len) {
    if (len == 0) return;
#ifdef _WIN32
    if (BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("BCryptGenRandom failed");
#else
    FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) throw std::runtime_error("cannot open /dev/urandom");
    size_t got = std::fread(buf, 1, len, f);
    std::fclose(f);
    if (got != len) throw std::runtime_error("short read from /dev/urandom");
#endif
}

inline std::vector<uint8_t> bytes(size_t len) {
    std::vector<uint8_t> v(len);
    fill(v.data(), len);
    return v;
}

} // namespace securerand
