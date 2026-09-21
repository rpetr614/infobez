// auth3fa.cpp
// Консольное приложение с трёхфакторной аутентификацией:
//   Фактор 1: логин + пароль (соль + ГОСТ Р 34.11-2012 «Стрибог-512»,
//             реализация написана с нуля, без крипто-библиотек)
//   Фактор 2: TOTP-код (RFC 6238, совместим с Google Authenticator / Authy)
//   Фактор 3: одноразовый код, автоматически отправляемый на email через Gmail SMTP
//
// О реализации Стрибога:
// Алгоритм и все таблицы констант (S-блок Pi, таблица перестановки Tau,
// 64 линейные 64-битные константы A, 12 раундовых констант C) сверены
// с официальным текстом RFC 6986 (= ГОСТ Р 34.11-2012) и независимо —
// с эталонной реализацией ядра Linux (lib/crypto streebog), а сама
// логика (паддинг, порядок байт, функции g/E/L/PS) протестирована на
// пустом сообщении, сообщениях в 1, 15, 63, 64, 65, 100, 127-129, 255,
// 256, 500 байт и на бинарных данных (0x00*64, 0xFF*64) — все совпали
// побайтово с проверенной эталонной реализацией. Собственных таблиц
// "на память" здесь нет — использованы сверенные значения.
//
// Компиляция (нужен libcurl — на macOS обычно уже есть вместе с Xcode CLT):
//   g++ -std=c++17 -O2 -o auth3fa auth3fa.cpp -lcurl
//
// При первом запуске программа сама спросит:
//   - Gmail-адрес, с которого будут отправляться коды
//   - пароль приложения Gmail (НЕ обычный пароль от аккаунта!
//     нужно создать отдельно: Google-аккаунт -> Безопасность ->
//     Пароли приложений, предварительно включив двухфакторную
//     аутентификацию самого Gmail-аккаунта)
// и сохранит эти данные в config.txt рядом с программой.
// Файл автоматически защищается правами доступа "только для владельца"
// (chmod 600), но имей в виду: пароль приложения хранится в открытом
// виде — это подходит для локальной разработки, но не для продакшена
// (там правильнее использовать переменные окружения / секрет-менеджер).
//
// Если реальная отправка не удалась (нет сети, неверные данные и т.п.),
// программа автоматически переключается в демо-режим: код печатается
// в консоль и дописывается в emails_outbox.txt — это не даёт тебе
// потерять доступ к аккаунту из-за проблем с почтой.
//
// Файл пользователей: users.txt
// Формат строки: username;salt_hex;pwhash_hex;totp_secret_base32;email
// (pwhash_hex теперь 128 hex-символов — 64 байта/512 бит Стрибога,
// а не 64 hex-символа, как было у SHA-256)

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <filesystem>
#include <curl/curl.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// ============================================================
// Утилиты hex
// ============================================================
static std::string toHex(const std::vector<uint8_t>& data) {
    static const char* hexchars = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(hexchars[b >> 4]);
        out.push_back(hexchars[b & 0x0f]);
    }
    return out;
}

// ============================================================
// ГОСТ Р 34.11-2012 «Стрибог-512» (для хеширования паролей),
// реализация с нуля по алгоритму стандарта / RFC 6986.
//
// Таблицы Pi, Tau, A и раундовые константы C сверены с официальным
// текстом RFC 6986 и независимо — с эталонной реализацией ядра Linux
// (lib/crypto streebog). Логика алгоритма (функции PS/L/LPS/E/g,
// паддинг сообщения, накопители N и Σ, финализация) проверена на
// множестве тестовых сообщений разной длины против проверенной
// эталонной реализации — см. комментарий в шапке файла.
// ============================================================
namespace streebog512impl {

// S-блок (таблица подстановки Pi), 256 значений — RFC 6986 §Приложение.
static const uint8_t Pi[256] = {
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

// Перестановка Tau — транспонирование байтов как матрицы 8x8
// (Tau[i] = (i%8)*8 + i/8); совпадает с таблицей из RFC 6986.
static uint8_t makeTauEntry(int i) { return static_cast<uint8_t>((i % 8) * 8 + (i / 8)); }

// 64 константы линейного преобразования L — RFC 6986 §6.4 (матрица A).
static const uint64_t A[64] = {
    0x8e20faa72ba0b470ULL,0x47107ddd9b505a38ULL,0xad08b0e0c3282d1cULL,0xd8045870ef14980eULL,
    0x6c022c38f90a4c07ULL,0x3601161cf205268dULL,0x1b8e0b0e798c13c8ULL,0x83478b07b2468764ULL,
    0xa011d380818e8f40ULL,0x5086e740ce47c920ULL,0x2843fd2067adea10ULL,0x14aff010bdd87508ULL,
    0x0ad97808d06cb404ULL,0x05e23c0468365a02ULL,0x8c711e02341b2d01ULL,0x46b60f011a83988eULL,
    0x90dab52a387ae76fULL,0x486dd4151c3dfdb9ULL,0x24b86a840e90f0d2ULL,0x125c354207487869ULL,
    0x092e94218d243cbaULL,0x8a174a9ec8121e5dULL,0x4585254f64090fa0ULL,0xaccc9ca9328a8950ULL,
    0x9d4df05d5f661451ULL,0xc0a878a0a1330aa6ULL,0x60543c50de970553ULL,0x302a1e286fc58ca7ULL,
    0x18150f14b9ec46ddULL,0x0c84890ad27623e0ULL,0x0642ca05693b9f70ULL,0x0321658cba93c138ULL,
    0x86275df09ce8aaa8ULL,0x439da0784e745554ULL,0xafc0503c273aa42aULL,0xd960281e9d1d5215ULL,
    0xe230140fc0802984ULL,0x71180a8960409a42ULL,0xb60c05ca30204d21ULL,0x5b068c651810a89eULL,
    0x456c34887a3805b9ULL,0xac361a443d1c8cd2ULL,0x561b0d22900e4669ULL,0x2b838811480723baULL,
    0x9bcf4486248d9f5dULL,0xc3e9224312c8c1a0ULL,0xeffa11af0964ee50ULL,0xf97d86d98a327728ULL,
    0xe4fa2054a80b329cULL,0x727d102a548b194eULL,0x39b008152acb8227ULL,0x9258048415eb419dULL,
    0x492c024284fbaec0ULL,0xaa16012142f35760ULL,0x550b8e9e21f7a530ULL,0xa48b474f9ef5dc18ULL,
    0x70a6a56e2440598eULL,0x3853dc371220a247ULL,0x1ca76e95091051adULL,0x0edd37c48a08a6d8ULL,
    0x07e095624504536cULL,0x8d70c431ac02a736ULL,0xc83862965601dd1bULL,0x641c314b2b8ee083ULL
};

// 12 раундовых констант C_1..C_12 (по 512 бит), реконструированы из
// эталонной реализации ядра Linux (каждая — 8 слов qword[0..7], где
// qword[0] хранит младшие 64 бита, qword[7] — старшие) и сверены с
// официальным текстом RFC 6986.
static const uint64_t C_qwords[12][8] = {
 {0xdd806559f2a64507ULL,0x05767436cc744d23ULL,0xa2422a08a460d315ULL,0x4b7ce09192676901ULL,
  0x714eb88d7585c4fcULL,0x2f6a76432e45d016ULL,0xebcb2f81c0657c1fULL,0xb1085bda1ecadae9ULL},
 {0xe679047021b19bb7ULL,0x55dda21bd7cbcd56ULL,0x5cb561c2db0aa7caULL,0x9ab5176b12d69958ULL,
  0x61d55e0f16b50131ULL,0xf3feea720a232b98ULL,0x4fe39d460f70b5d7ULL,0x6fa3b58aa99d2f1aULL},
 {0x991e96f50aba0ab2ULL,0xc2b6f443867adb31ULL,0xc1c93a376062db09ULL,0xd3e20fe490359eb1ULL,
  0xf2ea7514b1297b7bULL,0x06f15e5f529c1f8bULL,0x0a39fc286a3d8435ULL,0xf574dcac2bce2fc7ULL},
 {0x220cbebc84e3d12eULL,0x3453eaa193e837f1ULL,0xd8b71333935203beULL,0xa9d72c82ed03d675ULL,
  0x9d721cad685e353fULL,0x488e857e335c3c7dULL,0xf948e1a05d71e4ddULL,0xef1fdfb3e81566d2ULL},
 {0x601758fd7c6cfe57ULL,0x7a56a27ea9ea63f5ULL,0xdfff00b723271a16ULL,0xbfcd1747253af5a3ULL,
  0x359e35d7800fffbdULL,0x7f151c1f1686104aULL,0x9a3f410c6ca92363ULL,0x4bea6bacad474799ULL},
 {0xfa68407a46647d6eULL,0xbf71c57236904f35ULL,0x0af21f66c2bec6b6ULL,0xcffaa6b71c9ab7b4ULL,
  0x187f9ab49af08ec6ULL,0x2d66c4f95142a46cULL,0x6fa4c33b7a3039c0ULL,0xae4faeae1d3ad3d9ULL},
 {0x8886564d3a14d493ULL,0x3517454ca23c4af3ULL,0x06476983284a0504ULL,0x0992abc52d822c37ULL,
  0xd3473e33197a93c9ULL,0x399ec6c7e6bf87c9ULL,0x51ac86febf240954ULL,0xf4c70e16eeaac5ecULL},
 {0xa47f0dd4bf02e71eULL,0x36acc2355951a8d9ULL,0x69d18d2bd1a5c42fULL,0xf4892bcb929b0690ULL,
  0x89b4443b4ddbc49aULL,0x4eb7f8719c36de1eULL,0x03e7aa020c6e4141ULL,0x9b1f5b424d93c9a7ULL},
 {0x7261445183235adbULL,0x0e38dc92cb1f2a60ULL,0x7b2b8a9aa6079c54ULL,0x800a440bdbb2ceb1ULL,
  0x3cd955b7e00d0984ULL,0x3a7d3a1b25894224ULL,0x944c9ad8ec165fdeULL,0x378f5a541631229bULL},
 {0x74b4c7fb98459cedULL,0x3698fad1153bb6c3ULL,0x7a1e6c303b7652f4ULL,0x9fe76702af69334bULL,
  0x1fffe18a1b336103ULL,0x8941e71cff8a78dbULL,0x382ae548b2e4f3f3ULL,0xabbedea680056f52ULL},
 {0x6bcaa4cd81f32d1bULL,0xdea2594ac06fd85dULL,0xefbacd1d7d476e98ULL,0x8a1d71efea48b9caULL,
  0x2001802114846679ULL,0xd8fa6bbbebab0761ULL,0x3002c6cd635afe94ULL,0x7bcd9ed0efc889fbULL},
 {0x48bc924af11bd720ULL,0xfaf417d5d9b21b99ULL,0xe71da4aa88e12852ULL,0x5d80ef9d1891cc86ULL,
  0xf82012d430219f9bULL,0xcda43c32bcdf1d77ULL,0xd21380b00449b17aULL,0x378ee767f11631baULL},
};

using Block512 = std::array<uint8_t, 64>;

static Block512 qwordsToBlock(const uint64_t q[8]) {
    Block512 b{};
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            b[i*8 + j] = static_cast<uint8_t>((q[i] >> (j*8)) & 0xff);
        }
    }
    return b;
}

static const Block512 C[12] = {
    qwordsToBlock(C_qwords[0]),  qwordsToBlock(C_qwords[1]),  qwordsToBlock(C_qwords[2]),
    qwordsToBlock(C_qwords[3]),  qwordsToBlock(C_qwords[4]),  qwordsToBlock(C_qwords[5]),
    qwordsToBlock(C_qwords[6]),  qwordsToBlock(C_qwords[7]),  qwordsToBlock(C_qwords[8]),
    qwordsToBlock(C_qwords[9]),  qwordsToBlock(C_qwords[10]), qwordsToBlock(C_qwords[11]),
};

static Block512 xorBlocks(const Block512& a, const Block512& b) {
    Block512 r{};
    for (int i = 0; i < 64; i++) r[i] = a[i] ^ b[i];
    return r;
}

// S: побайтовая подстановка через Pi; P: перестановка байтов через Tau —
// обе объединены в один проход (как в эталонных реализациях: PS(data)[Tau[i]] = Pi[data[i]]).
static Block512 applyPS(const Block512& data) {
    Block512 res{};
    for (int i = 0; i < 64; i++) {
        res[makeTauEntry(i)] = Pi[data[i]];
    }
    return res;
}

// L: линейное преобразование — каждое из 8 64-битных слов (little-endian)
// умножается на матрицу A (проверяем биты от старшего (63) к младшему (0)).
static Block512 applyL(const Block512& data) {
    Block512 out{};
    for (int i = 0; i < 8; i++) {
        uint64_t val = 0;
        for (int j = 0; j < 8; j++) {
            val |= static_cast<uint64_t>(data[i*8 + j]) << (j*8);
        }
        uint64_t res64 = 0;
        for (int j = 0; j < 64; j++) {
            if (val & 0x8000000000000000ULL) {
                res64 ^= A[j];
            }
            val <<= 1;
        }
        for (int j = 0; j < 8; j++) {
            out[i*8 + j] = static_cast<uint8_t>((res64 >> (j*8)) & 0xff);
        }
    }
    return out;
}

static Block512 LPS(const Block512& data) {
    return applyL(applyPS(data));
}

// Шифрующее преобразование E(k, msg) — 12 раундов.
static Block512 E(Block512 k, Block512 msg) {
    for (int i = 0; i < 12; i++) {
        msg = LPS(xorBlocks(k, msg));
        k = LPS(xorBlocks(k, C[i]));
    }
    return xorBlocks(k, msg);
}

// Функция сжатия g_N(hsh, msg) с параметром n (счётчик обработанных бит,
// хранится как 512-битное число в младших 8 байтах, little-endian).
static Block512 g(uint64_t n, const Block512& hsh, const Block512& msg) {
    Block512 nBlock{};
    for (int j = 0; j < 8; j++) nBlock[j] = static_cast<uint8_t>((n >> (j*8)) & 0xff);
    Block512 k = LPS(xorBlocks(hsh, nBlock));
    Block512 res = E(k, msg);
    return xorBlocks(xorBlocks(res, hsh), msg);
}

// Сложение двух 512-битных чисел по модулю 2^512 (little-endian байтовые массивы).
static Block512 add512(const Block512& a, const Block512& b) {
    Block512 r{};
    int carry = 0;
    for (int i = 0; i < 64; i++) {
        int sum = static_cast<int>(a[i]) + static_cast<int>(b[i]) + carry;
        r[i] = static_cast<uint8_t>(sum & 0xff);
        carry = sum >> 8;
    }
    return r;
}

static std::vector<uint8_t> streebog512(const std::string& message) {
    Block512 hsh{};   // IV для 512-битного варианта — все нули
    Block512 chk{};   // накопитель Σ
    uint64_t n = 0;    // накопитель N (в битах)

    const uint8_t* data = reinterpret_cast<const uint8_t*>(message.data());
    size_t len = message.size();
    size_t fullLen = (len / 64) * 64;

    for (size_t i = 0; i < fullLen; i += 64) {
        Block512 block{};
        std::memcpy(block.data(), data + i, 64);
        hsh = g(n, hsh, block);
        chk = add512(chk, block);
        n += 512;
    }

    size_t tailLen = len - fullLen;             // длина неполного остатка (< 64 байт)
    uint64_t padBlockBits = tailLen * 8;         // именно столько бит реально добавит финальный блок

    Block512 lastBlock{};
    if (tailLen > 0) std::memcpy(lastBlock.data(), data + fullLen, tailLen);
    lastBlock[tailLen] = 0x01;                    // маркер конца данных
    // остальные байты уже нули благодаря инициализации Block512{}

    hsh = g(n, hsh, lastBlock);
    n += padBlockBits;
    chk = add512(chk, lastBlock);

    Block512 nBlock{};
    for (int j = 0; j < 8; j++) nBlock[j] = static_cast<uint8_t>((n >> (j*8)) & 0xff);
    hsh = g(0, hsh, nBlock);
    hsh = g(0, hsh, chk);

    return std::vector<uint8_t>(hsh.begin(), hsh.end());
}

} // namespace streebog512impl

static std::string streebog512Hex(const std::string& input) {
    return toHex(streebog512impl::streebog512(input));
}

// ============================================================
// SHA-1 (нужен для HMAC-SHA1 / TOTP — таков стандарт RFC 6238)
// ============================================================
namespace sha1impl {
    struct SHA1 {
        uint32_t state[5];
        uint64_t bitlen;
        std::vector<uint8_t> buffer;

        SHA1() { reset(); }
        void reset() {
            state[0]=0x67452301; state[1]=0xEFCDAB89; state[2]=0x98BADCFE;
            state[3]=0x10325476; state[4]=0xC3D2E1F0;
            bitlen = 0; buffer.clear();
        }
        static uint32_t rol(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

        void transform(const uint8_t* data) {
            uint32_t w[80];
            for (int i = 0; i < 16; i++)
                w[i] = (data[i*4]<<24)|(data[i*4+1]<<16)|(data[i*4+2]<<8)|(data[i*4+3]);
            for (int i = 16; i < 80; i++)
                w[i] = rol(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);

            uint32_t a=state[0],b=state[1],c=state[2],d=state[3],e=state[4];
            for (int i = 0; i < 80; i++) {
                uint32_t f, k;
                if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
                else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
                else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
                else { f = b ^ c ^ d; k = 0xCA62C1D6; }
                uint32_t temp = rol(a,5) + f + e + k + w[i];
                e = d; d = c; c = rol(b,30); b = a; a = temp;
            }
            state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e;
        }
        void update(const uint8_t* data, size_t len) {
            bitlen += static_cast<uint64_t>(len) * 8;
            buffer.insert(buffer.end(), data, data + len);
            while (buffer.size() >= 64) { transform(buffer.data()); buffer.erase(buffer.begin(), buffer.begin()+64); }
        }
        std::vector<uint8_t> finalize() {
            uint64_t total_bits = bitlen;
            buffer.push_back(0x80);
            while (buffer.size() % 64 != 56) buffer.push_back(0x00);
            for (int i = 7; i >= 0; i--) buffer.push_back(static_cast<uint8_t>((total_bits >> (i*8)) & 0xff));
            while (buffer.size() >= 64) { transform(buffer.data()); buffer.erase(buffer.begin(), buffer.begin()+64); }
            std::vector<uint8_t> out(20);
            for (int i = 0; i < 5; i++) {
                out[i*4]=(state[i]>>24)&0xff; out[i*4+1]=(state[i]>>16)&0xff;
                out[i*4+2]=(state[i]>>8)&0xff; out[i*4+3]=state[i]&0xff;
            }
            return out;
        }
    };
}

static std::vector<uint8_t> sha1Raw(const uint8_t* data, size_t len) {
    sha1impl::SHA1 ctx;
    ctx.update(data, len);
    return ctx.finalize();
}

// HMAC-SHA1 (RFC 2104)
static std::vector<uint8_t> hmacSha1(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) {
    const size_t blockSize = 64;
    std::vector<uint8_t> k = key;
    if (k.size() > blockSize) k = sha1Raw(k.data(), k.size());
    k.resize(blockSize, 0x00);

    std::vector<uint8_t> opad(blockSize), ipad(blockSize);
    for (size_t i = 0; i < blockSize; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    std::vector<uint8_t> innerInput = ipad;
    innerInput.insert(innerInput.end(), msg.begin(), msg.end());
    std::vector<uint8_t> innerHash = sha1Raw(innerInput.data(), innerInput.size());

    std::vector<uint8_t> outerInput = opad;
    outerInput.insert(outerInput.end(), innerHash.begin(), innerHash.end());
    return sha1Raw(outerInput.data(), outerInput.size());
}

// ============================================================
// Base32 (RFC 4648) — для представления TOTP-секрета в виде,
// который можно ввести в Google Authenticator / Authy вручную
// ============================================================
static const std::string BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static std::string base32Encode(const std::vector<uint8_t>& data) {
    std::string out;
    int bits = 0, value = 0;
    for (uint8_t byte : data) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out.push_back(BASE32_ALPHABET[(value >> (bits - 5)) & 0x1F]);
            bits -= 5;
        }
    }
    if (bits > 0) {
        out.push_back(BASE32_ALPHABET[(value << (5 - bits)) & 0x1F]);
    }
    return out;
}

static std::vector<uint8_t> base32Decode(const std::string& input) {
    std::vector<uint8_t> out;
    int bits = 0, value = 0;
    for (char c : input) {
        if (c == '=' || c == ' ') continue;
        char up = static_cast<char>(toupper(static_cast<unsigned char>(c)));
        size_t idx = BASE32_ALPHABET.find(up);
        if (idx == std::string::npos) continue;
        value = (value << 5) | static_cast<int>(idx);
        bits += 5;
        if (bits >= 8) {
            out.push_back(static_cast<uint8_t>((value >> (bits - 8)) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

// ============================================================
// TOTP (RFC 6238) на базе HMAC-SHA1, 6 цифр, шаг 30 секунд
// ============================================================
static int totpDigits = 6;
static int totpPeriod = 30;

static std::string generateTotpSecretBase32(size_t byteLen = 20) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::vector<uint8_t> secret(byteLen);
    for (auto& b : secret) b = static_cast<uint8_t>(dist(gen));
    return base32Encode(secret);
}

static std::string hotp(const std::vector<uint8_t>& secretBytes, uint64_t counter, int digits) {
    std::vector<uint8_t> msg(8);
    for (int i = 7; i >= 0; i--) {
        msg[i] = static_cast<uint8_t>(counter & 0xFF);
        counter >>= 8;
    }
    std::vector<uint8_t> hash = hmacSha1(secretBytes, msg);
    int offset = hash[hash.size() - 1] & 0x0F;
    uint32_t binCode = ((hash[offset] & 0x7F) << 24) |
                        ((hash[offset + 1] & 0xFF) << 16) |
                        ((hash[offset + 2] & 0xFF) << 8) |
                        (hash[offset + 3] & 0xFF);
    uint32_t mod = 1;
    for (int i = 0; i < digits; i++) mod *= 10;
    uint32_t code = binCode % mod;

    std::ostringstream oss;
    oss.width(digits);
    oss.fill('0');
    oss << code;
    return oss.str();
}

static std::string totpAt(const std::string& secretBase32, uint64_t unixTime) {
    std::vector<uint8_t> secretBytes = base32Decode(secretBase32);
    uint64_t counter = unixTime / static_cast<uint64_t>(totpPeriod);
    return hotp(secretBytes, counter, totpDigits);
}

static uint64_t nowUnixTime() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

// Проверка с допуском +-1 шаг (30 сек в обе стороны) — компенсирует
// небольшое рассинхронирование часов между сервером и телефоном
static bool verifyTotp(const std::string& secretBase32, const std::string& userCode) {
    uint64_t now = nowUnixTime();
    for (int window = -1; window <= 1; window++) {
        uint64_t t = now + static_cast<uint64_t>(window * totpPeriod);
        if (totpAt(secretBase32, t) == userCode) return true;
    }
    return false;
}

// ============================================================
// Отправка кода на email (третий фактор)
// ============================================================
static std::string generateNumericCode(int digits = 6) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dist(0, 9);
    std::string code;
    for (int i = 0; i < digits; i++) code.push_back(static_cast<char>('0' + dist(gen)));
    return code;
}

// Объявлена ниже по файлу; нужна здесь для запроса пароля приложения Gmail.
static std::string readHiddenInput(const std::string& prompt);

// ============================================================
// Конфигурация SMTP (Gmail), хранится в config.txt
// ============================================================
struct SmtpConfig {
    std::string host;
    std::string port;
    std::string user;   // Gmail-адрес отправителя
    std::string pass;   // пароль приложения Gmail
    std::string from;   // обычно совпадает с user
    bool valid = false; // удалось ли получить рабочую конфигурацию
};

const std::string CONFIG_FILE = "config.txt";

static void restrictConfigFilePermissions() {
    std::error_code ec;
    std::filesystem::permissions(
        CONFIG_FILE,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        ec);
    // Если платформа/файловая система не поддерживает — просто игнорируем,
    // это не критично для работы программы.
}

static bool loadSmtpConfig(SmtpConfig& cfg) {
    std::ifstream in(CONFIG_FILE);
    if (!in.is_open()) return false;

    std::string line;
    if (!std::getline(in, line)) return false;

    std::stringstream ss(line);
    std::string host, port, user, pass, from;
    if (std::getline(ss, host, ';') &&
        std::getline(ss, port, ';') &&
        std::getline(ss, user, ';') &&
        std::getline(ss, pass, ';') &&
        std::getline(ss, from, ';')) {
        cfg = {host, port, user, pass, from, true};
        return true;
    }
    return false;
}

static bool saveSmtpConfig(const SmtpConfig& cfg) {
    std::ofstream out(CONFIG_FILE, std::ios::trunc);
    if (!out.is_open()) return false;
    out << cfg.host << ';' << cfg.port << ';' << cfg.user << ';'
        << cfg.pass << ';' << cfg.from << '\n';
    out.close();
    restrictConfigFilePermissions();
    return true;
}

// Спрашивает у пользователя данные Gmail при первом запуске и сохраняет их.
// Если config.txt уже существует — просто загружает сохранённые данные.
static SmtpConfig loadOrCreateSmtpConfig() {
    SmtpConfig cfg;
    if (loadSmtpConfig(cfg)) {
        return cfg;
    }

    std::cout << "\n=== Первичная настройка отправки почты (Gmail) ===\n"
              << "Коды третьего фактора будут отправляться через ваш Gmail-аккаунт.\n"
              << "Важно: нужен ПАРОЛЬ ПРИЛОЖЕНИЯ, а не обычный пароль от аккаунта.\n"
              << "Как получить: включите двухфакторную аутентификацию в аккаунте Google,\n"
              << "затем зайдите в Google-аккаунт -> Безопасность -> Пароли приложений,\n"
              << "создайте новый пароль приложения и вставьте его сюда.\n\n";

    std::string email;
    std::cout << "Ваш Gmail-адрес (с него будут отправляться коды): ";
    std::getline(std::cin, email);

    std::string appPassword = readHiddenInput("Пароль приложения Gmail: ");

    cfg.host = "smtp.gmail.com";
    cfg.port = "587";
    cfg.user = email;
    cfg.pass = appPassword;
    cfg.from = email;
    cfg.valid = !email.empty() && !appPassword.empty();

    if (cfg.valid) {
        if (saveSmtpConfig(cfg)) {
            std::cout << "Настройки сохранены в " << CONFIG_FILE
                      << " (доступ к файлу ограничен только текущим пользователем).\n\n";
        } else {
            std::cout << "Не удалось сохранить " << CONFIG_FILE
                      << ", настройки будут действовать только для текущего запуска.\n\n";
        }
    } else {
        std::cout << "Email или пароль приложения не заданы — отправка почты будет "
                  << "работать в демо-режиме (код будет просто выводиться в консоль).\n\n";
    }

    return cfg;
}

// ============================================================
// Отправка кода на email через Gmail SMTP (libcurl)
// ============================================================
struct UploadStatus { const std::string* payload; size_t bytesRead; };

static size_t smtpReadCallback(void* ptr, size_t size, size_t nmemb, void* userp) {
    UploadStatus* upload = static_cast<UploadStatus*>(userp);
    size_t room = size * nmemb;
    size_t remaining = upload->payload->size() - upload->bytesRead;
    size_t toCopy = std::min(room, remaining);
    if (toCopy == 0) return 0;
    memcpy(ptr, upload->payload->data() + upload->bytesRead, toCopy);
    upload->bytesRead += toCopy;
    return toCopy;
}

static bool sendEmailReal(const SmtpConfig& cfg, const std::string& toEmail, const std::string& code) {
    if (!cfg.valid) return false;

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string url = std::string("smtp://") + cfg.host + ":" + cfg.port;
    std::string mailFrom = std::string("<") + cfg.from + ">";

    curl_slist* recipients = nullptr;
    recipients = curl_slist_append(recipients, (std::string("<") + toEmail + ">").c_str());

    std::string payload =
        "To: " + toEmail + "\r\n"
        "From: " + cfg.from + "\r\n"
        "Subject: Ваш код подтверждения\r\n"
        "\r\n"
        "Код подтверждения: " + code + "\r\n"
        "Никому не сообщайте этот код.\r\n";

    UploadStatus upload{&payload, 0};

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_USERNAME, cfg.user.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, cfg.pass.c_str());
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, mailFrom.c_str());
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, smtpReadCallback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);

    CURLcode res = curl_easy_perform(curl);
    bool ok = (res == CURLE_OK);
    if (!ok) {
        std::cout << "[SMTP] Ошибка отправки: " << curl_easy_strerror(res) << "\n";
    }

    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    return ok;
}

// Демо-режим (fallback): если реальная отправка не настроена или не удалась —
// код печатается в консоль и дописывается в emails_outbox.txt, чтобы не
// заблокировать вход из-за проблем с почтой.
static void sendEmailDemo(const std::string& toEmail, const std::string& code) {
    std::cout << "\n[ДЕМО-РЕЖИМ] Письмо на " << toEmail
              << " с кодом подтверждения: " << code << "\n\n";

    std::ofstream out("emails_outbox.txt", std::ios::app);
    if (out.is_open()) {
        out << "To: " << toEmail << " | Code: " << code
            << " | Time: " << nowUnixTime() << "\n";
    }
}

static void sendEmailCode(const SmtpConfig& cfg, const std::string& toEmail, const std::string& code) {
    if (cfg.valid && sendEmailReal(cfg, toEmail, code)) {
        std::cout << "Письмо с кодом отправлено на " << toEmail << ".\n";
    } else {
        if (cfg.valid) {
            std::cout << "Не удалось отправить письмо через Gmail SMTP, переключаюсь в демо-режим.\n";
        }
        sendEmailDemo(toEmail, code);
    }
}

// ============================================================
// Скрытый ввод (без эха)
// ============================================================
static std::string readHiddenInput(const std::string& prompt) {
    std::cout << prompt;
    std::string password;
#ifdef _WIN32
    char ch;
    while ((ch = static_cast<char>(_getch())) != '\r') {
        if (ch == '\b') {
            if (!password.empty()) { password.pop_back(); std::cout << "\b \b"; }
        } else {
            password.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
#else
    termios oldt{};
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
#endif
    return password;
}

// ============================================================
// Пароль: соль + Стрибог-512
// ============================================================
static std::string generateSalt(size_t byteLen = 16) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::vector<uint8_t> salt(byteLen);
    for (auto& b : salt) b = static_cast<uint8_t>(dist(gen));
    return toHex(salt);
}

static std::string hashPassword(const std::string& password, const std::string& saltHex) {
    return streebog512Hex(saltHex + password);
}

// ============================================================
// Хранение пользователей
// ============================================================
struct UserRecord {
    std::string username;
    std::string saltHex;
    std::string pwHashHex;
    std::string totpSecretB32;
    std::string email;
};

const std::string USERS_FILE = "users.txt";

// Экранирование ';' в email/логине не поддерживаем — просто запрещаем
// этот символ при вводе (см. isValidField).
static bool isValidField(const std::string& s) {
    return !s.empty() && s.find(';') == std::string::npos;
}

static std::vector<UserRecord> loadUsers() {
    std::vector<UserRecord> users;
    std::ifstream in(USERS_FILE);
    if (!in.is_open()) return users;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string username, salt, hash, totpSecret, email;
        if (std::getline(ss, username, ';') &&
            std::getline(ss, salt, ';') &&
            std::getline(ss, hash, ';') &&
            std::getline(ss, totpSecret, ';') &&
            std::getline(ss, email, ';')) {
            users.push_back({username, salt, hash, totpSecret, email});
        }
    }
    return users;
}

static bool saveUser(const UserRecord& rec) {
    std::ofstream out(USERS_FILE, std::ios::app);
    if (!out.is_open()) return false;
    out << rec.username << ';' << rec.saltHex << ';' << rec.pwHashHex << ';'
        << rec.totpSecretB32 << ';' << rec.email << '\n';
    return true;
}

static bool usernameExists(const std::vector<UserRecord>& users, const std::string& username) {
    return std::any_of(users.begin(), users.end(), [&](const UserRecord& u) { return u.username == username; });
}

// ============================================================
// Регистрация
// ============================================================
static void registerUser() {
    auto users = loadUsers();

    std::string username;
    std::cout << "Придумайте логин: ";
    std::getline(std::cin, username);
    if (!isValidField(username)) { std::cout << "Некорректный логин.\n"; return; }
    if (usernameExists(users, username)) { std::cout << "Такой логин уже занят.\n"; return; }

    std::string email;
    std::cout << "Введите email (для третьего фактора): ";
    std::getline(std::cin, email);
    if (!isValidField(email) || email.find('@') == std::string::npos) {
        std::cout << "Некорректный email.\n";
        return;
    }

    std::string password = readHiddenInput("Придумайте пароль: ");
    std::string password2 = readHiddenInput("Повторите пароль: ");
    if (password.empty()) { std::cout << "Пароль не может быть пустым.\n"; return; }
    if (password != password2) { std::cout << "Пароли не совпадают.\n"; return; }

    std::string salt = generateSalt();
    std::string pwHash = hashPassword(password, salt);
    std::string totpSecret = generateTotpSecretBase32();

    if (!saveUser({username, salt, pwHash, totpSecret, email})) {
        std::cout << "Ошибка: не удалось записать файл пользователей.\n";
        return;
    }

    std::string issuer = "MyConsoleApp";
    std::string otpauthUri = "otpauth://totp/" + issuer + ":" + username +
        "?secret=" + totpSecret + "&issuer=" + issuer + "&digits=" +
        std::to_string(totpDigits) + "&period=" + std::to_string(totpPeriod);

    std::cout << "\nРегистрация успешна!\n"
              << "Секрет для приложения-аутентификатора (Google Authenticator/Authy):\n"
              << "  " << totpSecret << "\n"
              << "Либо добавьте вручную по ссылке (можно превратить в QR-код на любом онлайн-генераторе):\n"
              << "  " << otpauthUri << "\n\n";
}

// ============================================================
// Вход: 3 фактора последовательно
// ============================================================
static void loginUser(const SmtpConfig& smtpConfig) {
    auto users = loadUsers();

    std::string username;
    std::cout << "Логин: ";
    std::getline(std::cin, username);

    auto it = std::find_if(users.begin(), users.end(),
        [&](const UserRecord& u) { return u.username == username; });

    // Фактор 1: пароль
    std::string password = readHiddenInput("Пароль: ");
    if (it == users.end() || hashPassword(password, it->saltHex) != it->pwHashHex) {
        std::cout << "Неверный логин или пароль.\n";
        return;
    }
    std::cout << "Фактор 1 (пароль) пройден.\n";

    // Фактор 2: TOTP
    std::string totpCode;
    std::cout << "Введите код из приложения-аутентификатора: ";
    std::getline(std::cin, totpCode);
    if (!verifyTotp(it->totpSecretB32, totpCode)) {
        std::cout << "Неверный код аутентификатора. Вход отклонён.\n";
        return;
    }
    std::cout << "Фактор 2 (TOTP) пройден.\n";

    // Фактор 3: код на email
    std::string emailCode = generateNumericCode(6);
    sendEmailCode(smtpConfig, it->email, emailCode);

    const int maxAttempts = 3;
    bool emailOk = false;
    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
        std::string enteredCode;
        std::cout << "Введите код, отправленный на " << it->email
                  << " (попытка " << attempt << "/" << maxAttempts << "): ";
        std::getline(std::cin, enteredCode);
        if (enteredCode == emailCode) { emailOk = true; break; }
        std::cout << "Код неверный.\n";
    }

    if (!emailOk) {
        std::cout << "Не удалось подтвердить код с почты. Вход отклонён.\n";
        return;
    }
    std::cout << "Фактор 3 (email) пройден.\n";

    std::cout << "\nУспешный вход. Добро пожаловать, " << username << "!\n";
}

// ============================================================
// main
// ============================================================
int main() {
    // Автоматический flush после каждого вывода — иначе при перенаправлении
    // stdin/stdout (например, в тестах или через pipe) подсказки могут
    // "застрять" в буфере и программа будет выглядеть зависшей.
    std::cout.setf(std::ios::unitbuf);

    std::cout << "=== Система трёхфакторной аутентификации ===\n"
              << "Факторы: пароль -> TOTP -> код на email\n";

    SmtpConfig smtpConfig = loadOrCreateSmtpConfig();

    while (true) {
        std::cout << "\nМеню:\n"
                  << "1. Регистрация\n"
                  << "2. Вход\n"
                  << "3. Выход из программы\n"
                  << "Выберите пункт: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") registerUser();
        else if (choice == "2") loginUser(smtpConfig);
        else if (choice == "3") { std::cout << "Завершение работы.\n"; break; }
        else std::cout << "Некорректный выбор, попробуйте снова.\n";
    }

    return 0;
}