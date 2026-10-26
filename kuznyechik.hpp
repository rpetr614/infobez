// kuznyechik.hpp
// Блочный шифр «Кузнечик» (ГОСТ Р 34.12-2015, RFC 7801) и режимы
// ГОСТ Р 34.13-2015: гаммирование (CTR) и выработка имитовставки (OMAC/MAC).
// Реализация с нуля, без внешних крипто-библиотек.
//
// Оптимизация: преобразования S (нелинейная подстановка) и L (линейное
// преобразование над GF(2^8)) объединены в 16 предвычисленных таблиц
// по 256 128-битных значений (64 КБ). Один раунд шифрования = 16 обращений
// к таблицам + XOR, вместо 16x16 умножений в поле. Это стандартный приём
// быстрых реализаций (так сделано в OpenSSL-gost-engine, ядре Linux и т.п.).
//
// Режим CTR выбран для сообщений потому, что он не требует дополнения
// (длина шифртекста = длина открытого текста) и использует только
// прямое преобразование блока. Целостность обеспечивается имитовставкой
// OMAC по схеме Encrypt-then-MAC на отдельном ключе.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

namespace kuz {

using Block = std::array<uint8_t, 16>;

// Нелинейная биекция pi (та же таблица, что и в Стрибоге, ГОСТ Р 34.12-2015 п.4.1.1)
constexpr int PI_LINE = __LINE__ + 1;      // для отчёта самопроверки: где задана таблица
static const uint8_t PI[256] = {
    252,238,221,17,207,110,49,22,251,196,250,218,35,197,4,77,
    233,119,240,219,147,46,153,186,23,54,241,187,20,205,95,193,
    249,24,101,90,226,92,239,33,129,28,60,66,139,1,142,79,
    5,132,2,174,227,106,143,160,6,11,237,152,127,212,211,31,
    235,52,44,81,234,200,72,171,242,42,104,162,253,58,206,204,
    181,112,14,86,8,12,118,18,191,114,19,71,156,183,93,135,
    21,161,150,41,16,123,154,199,243,145,120,111,157,158,178,177,
    50,117,25,61,255,53,138,126,109,84,198,128,195,189,13,87,
    223,245,36,169,62,168,67,201,215,121,214,246,124,34,185,3,
    224,15,236,222,122,148,176,188,220,232,40,80,78,51,10,74,
    167,151,96,115,30,0,98,68,26,184,56,130,100,159,38,65,
    173,69,70,146,39,94,85,47,140,163,165,125,105,213,149,59,
    7,88,179,64,134,172,29,247,48,55,107,228,136,217,231,137,
    225,27,131,73,76,63,248,254,141,83,170,144,202,216,133,97,
    32,113,103,164,45,43,9,91,203,155,37,208,190,229,108,82,
    89,166,116,210,230,244,180,192,209,102,175,194,57,75,99,182
};

// Коэффициенты линейного преобразования l (ГОСТ Р 34.12-2015 п.4.1.2),
// в порядке байтов a15..a0 (байт 0 массива = старший байт a15).
constexpr int LC_LINE = __LINE__ + 1;
static const uint8_t LC[16] = {148,32,133,16,194,192,1,251,1,192,194,16,133,32,148,1};

// Умножение в GF(2^8) по модулю p(x) = x^8 + x^7 + x^6 + x + 1
constexpr int GFMUL_LINE = __LINE__ + 1;
inline uint8_t gfMul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0xC3;
        b >>= 1;
    }
    return r;
}

// Медленные «эталонные» преобразования — используются только для
// построения таблиц, развёртки ключа и обратного преобразования блока.
inline Block opR(const Block& a) {
    uint8_t x = 0;
    for (int i = 0; i < 16; i++) x ^= gfMul(LC[i], a[i]);
    Block r{};
    r[0] = x;
    for (int i = 1; i < 16; i++) r[i] = a[i - 1];
    return r;
}
inline Block opRinv(const Block& c) {
    Block a{};
    for (int i = 0; i < 15; i++) a[i] = c[i + 1];
    uint8_t x = c[0];
    for (int i = 0; i < 15; i++) x ^= gfMul(LC[i], a[i]);
    a[15] = x; // LC[15] == 1
    return a;
}
inline Block opL(Block a)    { for (int i = 0; i < 16; i++) a = opR(a);    return a; }
inline Block opLinv(Block a) { for (int i = 0; i < 16; i++) a = opRinv(a); return a; }

constexpr int TABLES_LINE = __LINE__ + 1;
struct Tables {
    uint64_t ls[16][256][2];   // LS-таблицы для прямого преобразования
    uint8_t  piInv[256];
    Tables() {
        for (int i = 0; i < 256; i++) piInv[PI[i]] = static_cast<uint8_t>(i);
        for (int pos = 0; pos < 16; pos++) {
            for (int v = 0; v < 256; v++) {
                Block b{};
                b[pos] = PI[v];
                Block l = opL(b);
                std::memcpy(ls[pos][v], l.data(), 16);
            }
        }
    }
};
inline const Tables& tables() { static const Tables t; return t; }

// Быстрое LS через таблицы: x — 16 байт, результат — 16 байт
inline void fastLS(const uint8_t in[16], uint8_t out[16]) {
    const Tables& T = tables();
    uint64_t y0 = 0, y1 = 0;
    for (int i = 0; i < 16; i++) {
        y0 ^= T.ls[i][in[i]][0];
        y1 ^= T.ls[i][in[i]][1];
    }
    std::memcpy(out, &y0, 8);
    std::memcpy(out + 8, &y1, 8);
}

class Cipher {
public:
    explicit Cipher(const uint8_t key[32]) { expandKey(key); }
    ~Cipher() { secureZero(); }
    Cipher(const Cipher&) = delete;
    Cipher& operator=(const Cipher&) = delete;

    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        const Tables& T = tables();
        uint64_t x0, x1;
        std::memcpy(&x0, in, 8);
        std::memcpy(&x1, in + 8, 8);
        for (int r = 0; r < 9; r++) {
            x0 ^= rk_[r][0];
            x1 ^= rk_[r][1];
            uint8_t b[16];
            std::memcpy(b, &x0, 8);
            std::memcpy(b + 8, &x1, 8);
            uint64_t y0 = 0, y1 = 0;
            for (int i = 0; i < 16; i++) {
                y0 ^= T.ls[i][b[i]][0];
                y1 ^= T.ls[i][b[i]][1];
            }
            x0 = y0; x1 = y1;
        }
        x0 ^= rk_[9][0];
        x1 ^= rk_[9][1];
        std::memcpy(out, &x0, 8);
        std::memcpy(out + 8, &x1, 8);
    }

    // Раундовый ключ K_{i+1}, i = 0..9 (для проверки развёртки ключа по ГОСТ)
    Block roundKey(int i) const { Block b; std::memcpy(b.data(), rk_[i], 16); return b; }

    // Обратное преобразование блока (в CTR/OMAC не нужно, оставлено для
    // полноты реализации стандарта и самопроверки).
    void decryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        const Tables& T = tables();
        Block a;
        std::memcpy(a.data(), in, 16);
        Block k9; std::memcpy(k9.data(), rk_[9], 16);
        for (int i = 0; i < 16; i++) a[i] ^= k9[i];
        for (int r = 8; r >= 0; r--) {
            a = opLinv(a);
            for (int i = 0; i < 16; i++) a[i] = T.piInv[a[i]];
            Block k; std::memcpy(k.data(), rk_[r], 16);
            for (int i = 0; i < 16; i++) a[i] ^= k[i];
        }
        std::memcpy(out, a.data(), 16);
    }

private:
    uint64_t rk_[10][2];

public:  static constexpr int EXPANDKEY_LINE = __LINE__ + 2;   // строка expandKey (для отчёта)
private:
    void expandKey(const uint8_t key[32]) {
        uint8_t a1[16], a0[16];
        std::memcpy(a1, key, 16);
        std::memcpy(a0, key + 16, 16);
        std::memcpy(rk_[0], a1, 16);
        std::memcpy(rk_[1], a0, 16);
        for (int i = 0; i < 4; i++) {
            for (int j = 1; j <= 8; j++) {
                Block c{};
                c[15] = static_cast<uint8_t>(8 * i + j);
                c = opL(c);
                uint8_t t[16], ls[16];
                for (int k = 0; k < 16; k++) t[k] = a1[k] ^ c[k];
                fastLS(t, ls);
                for (int k = 0; k < 16; k++) ls[k] ^= a0[k];
                std::memcpy(a0, a1, 16);
                std::memcpy(a1, ls, 16);
            }
            std::memcpy(rk_[2 * i + 2], a1, 16);
            std::memcpy(rk_[2 * i + 3], a0, 16);
        }
        volatile uint8_t* p1 = a1; volatile uint8_t* p0 = a0;
        for (int k = 0; k < 16; k++) { p1[k] = 0; p0[k] = 0; }
    }
    void secureZero() {
        volatile uint64_t* p = &rk_[0][0];
        for (int i = 0; i < 20; i++) p[i] = 0;
    }
};

// ------------------------------------------------------------
// Режим гаммирования CTR (ГОСТ Р 34.13-2015 п.5.2):
// IV — 64 бита, CTR_1 = IV || 0^64, CTR_{i+1} = CTR_i + 1 (mod 2^128).
// Шифрование и расшифрование — одна и та же операция.
// ------------------------------------------------------------
constexpr int CTR_LINE = __LINE__ + 1;
inline std::vector<uint8_t> ctrXcrypt(const Cipher& c, const uint8_t iv[8],
                                      const uint8_t* data, size_t len) {
    std::vector<uint8_t> out(len);
    uint8_t ctr[16] = {0};
    std::memcpy(ctr, iv, 8);
    uint8_t gamma[16];
    for (size_t off = 0; off < len; off += 16) {
        c.encryptBlock(ctr, gamma);
        size_t n = std::min<size_t>(16, len - off);
        for (size_t i = 0; i < n; i++) out[off + i] = data[off + i] ^ gamma[i];
        for (int i = 15; i >= 0; i--) { if (++ctr[i] != 0) break; }
    }
    return out;
}

// ------------------------------------------------------------
// Имитовставка OMAC (ГОСТ Р 34.13-2015 п.5.6), B_128 = 0^120 || 10000111.
// Возвращает полные 128 бит; при необходимости усекается до старших s бит.
// ------------------------------------------------------------
constexpr int OMAC_LINE = __LINE__ + 1;
inline void omacShift(const uint8_t in[16], uint8_t out[16]) {
    uint8_t msb = in[0] & 0x80;
    for (int i = 0; i < 15; i++) out[i] = static_cast<uint8_t>((in[i] << 1) | (in[i + 1] >> 7));
    out[15] = static_cast<uint8_t>(in[15] << 1);
    if (msb) out[15] ^= 0x87;
}

inline std::array<uint8_t, 16> omac(const Cipher& c, const uint8_t* data, size_t len) {
    uint8_t zero[16] = {0}, R[16], K1[16], K2[16];
    c.encryptBlock(zero, R);
    omacShift(R, K1);
    omacShift(K1, K2);

    uint8_t state[16] = {0};
    size_t nBlocks = (len + 15) / 16;
    if (nBlocks == 0) nBlocks = 1;
    for (size_t b = 0; b + 1 < nBlocks; b++) {
        for (int i = 0; i < 16; i++) state[i] ^= data[b * 16 + i];
        c.encryptBlock(state, state);
    }
    size_t lastOff = (nBlocks - 1) * 16;
    size_t lastLen = len - lastOff;
    uint8_t last[16] = {0};
    if (lastLen == 16) {
        std::memcpy(last, data + lastOff, 16);
        for (int i = 0; i < 16; i++) last[i] ^= K1[i];
    } else {
        if (lastLen) std::memcpy(last, data + lastOff, lastLen);
        last[lastLen] = 0x80;
        for (int i = 0; i < 16; i++) last[i] ^= K2[i];
    }
    for (int i = 0; i < 16; i++) state[i] ^= last[i];
    std::array<uint8_t, 16> mac;
    c.encryptBlock(state, mac.data());
    return mac;
}

// Сравнение за постоянное время (не даёт атакующему подбирать MAC по времени ответа)
inline bool constTimeEq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= static_cast<uint8_t>(a[i] ^ b[i]);
    return d == 0;
}

} // namespace kuz
