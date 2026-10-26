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
// После входа (все 3 фактора) пользователь попадает в меню сообщений:
//   - шифрование сообщения «Кузнечиком» (ГОСТ Р 34.12-2015, CTR + OMAC)
//     или RSA-32768 (OAEP со Стрибогом-512, GMP, CRT, многопоточность);
//   - список, расшифрование, PDF-отчёт со всеми сообщениями и их
//     расшифровкой. См. kuznyechik.hpp, rsa_gmp.hpp, pdf_writer.hpp.
//
// Компиляция (нужны libcurl и GMP; на macOS: brew install gmp):
//   make
// или вручную (macOS + Homebrew):
//   g++ -std=c++17 -O2 -I$(brew --prefix gmp)/include -o auth3fa auth3fa.cpp
//       -L$(brew --prefix gmp)/lib -lcurl -lgmp -pthread      (одной строкой)
//
// Проверка по контрольным примерам ГОСТ (Стрибог-256/512, HMAC, Кузнечик,
// режимы ГОСТ Р 34.13) и RSA-OAEP; примеры ГОСТ проверяются и при каждом запуске:
//   ./auth3fa --selftest
// Замеры производительности и статистика (Стрибог, Кузнечик, RSA-32768):
//   ./auth3fa --bench
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
// У записей, созданных администратором, totp_secret_base32 и email
// изначально пустые — владелец заполняет их сам при первом входе.
//
// Роли пользователей:
//   - Обычный пользователь: регистрируется сам, сразу проходит
//     все 3 фактора.
//   - Admin: служебная учётная запись (см. ADMIN_USERNAME/ADMIN_PASSWORD
//     в начале файла). Вход только по паролю (без TOTP/почты), открывает
//     панель управления учётными записями: просмотр всех записей,
//     создание новых (только логин+пароль — почту и TOTP пользователь
//     привязывает сам при первом входе) и удаление существующих.

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <cstdint>
#include <cstring>
#include <random>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <ctime>
#include <iomanip>
#include <cmath>
#include <curl/curl.h>

#include "secure_random.hpp"   // CSPRNG ОС (/dev/urandom / BCryptGenRandom)
#include "kuznyechik.hpp"      // ГОСТ Р 34.12-2015 «Кузнечик» + режимы ГОСТ Р 34.13-2015
#include "rsa_gmp.hpp"         // RSA-32768 на GMP: параллельная генерация, OAEP, CRT
#include "pdf_writer.hpp"      // PDF с кириллицей без внешних библиотек
#include "gost3410.hpp"        // ЭЦП ГОСТ Р 34.10-2012 на эллиптических кривых
#include "pdf_signature.hpp"   // подпись PDF: сертификат X.509 + CMS, проверка

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// ============================================================
// НАСТРОЙКИ (меняются здесь, в одном месте)
// ============================================================
// Включает/выключает требования к сложности пароля при регистрации
// (строчные+заглавные буквы, цифра, спецсимвол, минимальная длина).
// Поставьте false, если нужно быстро тестировать программу без
// ограничений на пароль.
static const bool ENFORCE_PASSWORD_REQUIREMENTS = true;

// Минимальная длина пароля (используется только пока
// ENFORCE_PASSWORD_REQUIREMENTS == true).
static const int MIN_PASSWORD_LENGTH = 12;

// Имя служебной учётной записи администратора. Зарезервировано —
// обычный пользователь не может зарегистрироваться под этим именем.
static const std::string ADMIN_USERNAME = "Admin";

// ВРЕМЕННО: пароль администратора лежит здесь открытым текстом,
// чтобы его было легко найти и изменить и чтобы он не "потерялся".
// Это временное решение — для реального использования нужно вынести
// его из исходного кода (переменная окружения, отдельный защищённый
// файл, ввод при первом запуске и т.п.). Не забудь заменить значение
// по умолчанию перед тем, как давать доступ к программе кому-то ещё.
static const std::string ADMIN_PASSWORD = "ChangeMe_Admin123!";

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
// Вывод таблиц с автоматической шириной колонок
// ============================================================
// Обычный std::setw считает ширину по количеству БАЙТ в std::string,
// а не по количеству отображаемых символов — для строк с кириллицей
// в UTF-8 (2 байта на символ) это даёт неверное выравнивание. Поэтому
// здесь считаем видимую ширину строки вручную (по числу UTF-8
// кодовых точек), а не полагаемся на setw.
static size_t utf8DisplayWidth(const std::string& s) {
    size_t width = 0;
    for (size_t i = 0; i < s.size(); ) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if ((c & 0x80) == 0) i += 1;        // ASCII, 1 байт
        else if ((c & 0xE0) == 0xC0) i += 2; // 2-байтовая последовательность (напр. кириллица)
        else if ((c & 0xF0) == 0xE0) i += 3; // 3-байтовая
        else if ((c & 0xF8) == 0xF0) i += 4; // 4-байтовая
        else i += 1;                          // некорректный байт — пропускаем как есть
        width++;
    }
    return width;
}

static std::string padToWidth(const std::string& s, size_t width) {
    size_t w = utf8DisplayWidth(s);
    if (w >= width) return s;
    return s + std::string(width - w, ' ');
}

// Печатает таблицу с колонками, ширина каждой из которых равна
// максимальной видимой ширине среди заголовка и всех значений этой
// колонки (плюс отступ между колонками) — подходит для вывода
// произвольного размера, а не только для конкретного списка полей.
static void printAlignedTable(const std::vector<std::string>& headers,
                               const std::vector<std::vector<std::string>>& rows) {
    size_t colCount = headers.size();
    std::vector<size_t> colWidth(colCount);
    for (size_t c = 0; c < colCount; c++) {
        colWidth[c] = utf8DisplayWidth(headers[c]);
        for (const auto& row : rows) {
            if (c < row.size()) {
                colWidth[c] = std::max(colWidth[c], utf8DisplayWidth(row[c]));
            }
        }
    }

    const std::string colGap = "  ";
    const std::string sep = " | ";

    auto printRow = [&](const std::vector<std::string>& cells) {
        std::cout << colGap;
        for (size_t c = 0; c < colCount; c++) {
            std::string cell = (c < cells.size()) ? cells[c] : "";
            bool isLast = (c + 1 == colCount);
            std::cout << (isLast ? cell : padToWidth(cell, colWidth[c]));
            if (!isLast) std::cout << sep;
        }
        std::cout << "\n";
    };

    printRow(headers);

    size_t totalWidth = colGap.size();
    for (size_t c = 0; c < colCount; c++) {
        totalWidth += colWidth[c];
        if (c + 1 != colCount) totalWidth += sep.size();
    }
    std::cout << colGap << std::string(totalWidth - colGap.size(), '-') << "\n";

    for (const auto& row : rows) printRow(row);
}

// ============================================================
// ASCII-таблицы с рамкой (консоль и PDF)
// ============================================================
//   +----+----------+
//   | №  | Значение |
//   +----+----------+
//   |  1 | ...      |
//   +----+----------+
// Строка из одного элемента "---" рисует разделитель внутри таблицы.
// Ширина считается по числу символов UTF-8 (кириллица = 1 символ).
enum class Align { Left, Right };

static std::vector<std::string> asciiTable(const std::vector<std::string>& headers,
                                           const std::vector<std::vector<std::string>>& rows,
                                           const std::vector<Align>& align = {}) {
    const size_t cols = headers.size();
    std::vector<size_t> w(cols);
    for (size_t c = 0; c < cols; c++) w[c] = utf8DisplayWidth(headers[c]);
    for (const auto& r : rows) {
        if (r.size() == 1 && r[0] == "---") continue;
        for (size_t c = 0; c < cols && c < r.size(); c++) w[c] = std::max(w[c], utf8DisplayWidth(r[c]));
    }
    std::string sep = "+";
    for (size_t c = 0; c < cols; c++) sep += std::string(w[c] + 2, '-') + "+";
    auto line = [&](const std::vector<std::string>& cells, bool header) {
        std::string s = "|";
        for (size_t c = 0; c < cols; c++) {
            std::string cell = c < cells.size() ? cells[c] : "";
            size_t pad = w[c] - utf8DisplayWidth(cell);
            bool right = !header && c < align.size() && align[c] == Align::Right;
            s += " " + (right ? std::string(pad, ' ') + cell : cell + std::string(pad, ' ')) + " |";
        }
        return s;
    };
    std::vector<std::string> out{sep, line(headers, true), sep};
    for (const auto& r : rows) out.push_back((r.size() == 1 && r[0] == "---") ? sep : line(r, false));
    out.push_back(sep);
    return out;
}

static void printAsciiTable(const std::vector<std::string>& headers,
                            const std::vector<std::vector<std::string>>& rows,
                            const std::vector<Align>& align = {}) {
    for (const auto& l : asciiTable(headers, rows, align)) std::cout << l << "\n";
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
constexpr int PI_LINE = __LINE__ + 1;      // для отчёта самопроверки: где задана таблица
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
constexpr int TAU_LINE = __LINE__ + 1;
static uint8_t makeTauEntry(int i) { return static_cast<uint8_t>((i % 8) * 8 + (i / 8)); }

// 64 константы линейного преобразования L — RFC 6986 §6.4 (матрица A).
constexpr int A_LINE = __LINE__ + 1;
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
constexpr int C_LINE = __LINE__ + 1;
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
// умножается на матрицу A. Бит номер b слова (0 — младший) соответствует
// строке A[63 - b].
//
// Оптимизация: L линейно над GF(2), поэтому результат для слова равен XOR
// вкладов его 8 байтов. Вклад каждого из 256 значений байта в каждой из
// 8 позиций предвычисляется один раз (таблица 8x256 слов = 16 КБ), и
// вместо 64 проверок битов делается 8 обращений к таблице. Это ускоряет
// хеш в десятки раз; корректность подтверждается --selftest.
constexpr int LTABLE_LINE = __LINE__ + 1;
struct LTable {
    uint64_t t[8][256];
    LTable() {
        for (int pos = 0; pos < 8; pos++) {
            for (int v = 0; v < 256; v++) {
                uint64_t acc = 0;
                for (int k = 0; k < 8; k++) {
                    if (v & (1 << k)) acc ^= A[63 - (pos * 8 + k)];
                }
                t[pos][v] = acc;
            }
        }
    }
};
static const LTable& lTable() { static const LTable tbl; return tbl; }

static Block512 applyL(const Block512& data) {
    Block512 out{};
    const LTable& T = lTable();
    for (int i = 0; i < 8; i++) {
        uint64_t res64 = 0;
        for (int j = 0; j < 8; j++) {
            res64 ^= T.t[j][data[i*8 + j]];
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

// Общее ядро для обоих вариантов стандарта. Варианты отличаются только
// начальным вектором: IV = 0^512 для 512 бит и IV = (00000001)^64 для
// 256 бит; результат 256-битного варианта — старшие 256 бит (в нашем
// little-endian представлении это байты [32..64)).
constexpr int CORE_LINE = __LINE__ + 1;
static std::vector<uint8_t> streebogCore(const std::string& message, bool variant256) {
    Block512 hsh{};   // IV
    if (variant256) hsh.fill(0x01);
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

    if (variant256) return std::vector<uint8_t>(hsh.begin() + 32, hsh.end());
    return std::vector<uint8_t>(hsh.begin(), hsh.end());
}

static std::vector<uint8_t> streebog512(const std::string& message) { return streebogCore(message, false); }
static std::vector<uint8_t> streebog256(const std::string& message) { return streebogCore(message, true); }

} // namespace streebog512impl

static std::string streebog512Hex(const std::string& input) {
    return toHex(streebog512impl::streebog512(input));
}
static std::string streebog256Hex(const std::string& input) {
    return toHex(streebog512impl::streebog256(input));
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
    // Только IPv4: если IPv6-маршрут до Gmail «висит», curl иначе может
    // ждать до таймаута, хотя по IPv4 всё работает.
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, (long)CURL_IPRESOLVE_V4);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    // Подробный текст ошибки от curl (на каком этапе остановились).
    char errbuf[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    CURLcode res = curl_easy_perform(curl);
    bool ok = (res == CURLE_OK);
    if (!ok) {
        std::cout << "[SMTP] Ошибка отправки: " << curl_easy_strerror(res) << "\n";
        if (errbuf[0] != '\0') std::cout << "[SMTP] Подробности: " << errbuf << "\n";
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
// Требования к сложности пароля и автогенерация
// ============================================================
static const std::string PASSWORD_SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:,.<>/?";

// Проверяет пароль на соответствие требованиям (строчные+заглавные буквы,
// цифра, спецсимвол, минимальная длина). Если требования выключены
// (ENFORCE_PASSWORD_REQUIREMENTS == false), всегда возвращает true.
// В errorMsg при неудаче записывается список того, чего не хватает.
static bool isPasswordStrongEnough(const std::string& password, std::string& errorMsg) {
    if (!ENFORCE_PASSWORD_REQUIREMENTS) return true;

    bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
    for (char c : password) {
        if (islower(static_cast<unsigned char>(c))) hasLower = true;
        else if (isupper(static_cast<unsigned char>(c))) hasUpper = true;
        else if (isdigit(static_cast<unsigned char>(c))) hasDigit = true;
        else if (PASSWORD_SPECIAL_CHARS.find(c) != std::string::npos) hasSpecial = true;
    }

    std::vector<std::string> missing;
    if (static_cast<int>(password.size()) < MIN_PASSWORD_LENGTH) {
        missing.push_back("минимум " + std::to_string(MIN_PASSWORD_LENGTH) + " символов");
    }
    if (!hasLower) missing.push_back("строчная буква");
    if (!hasUpper) missing.push_back("заглавная буква");
    if (!hasDigit) missing.push_back("цифра");
    if (!hasSpecial) missing.push_back("спецсимвол (" + PASSWORD_SPECIAL_CHARS + ")");

    if (missing.empty()) return true;

    errorMsg = "Пароль не соответствует требованиям. Не хватает: ";
    for (size_t i = 0; i < missing.size(); i++) {
        errorMsg += missing[i];
        if (i + 1 < missing.size()) errorMsg += ", ";
    }
    errorMsg += ".\n";
    return false;
}

// Генерирует надёжный случайный пароль, гарантированно удовлетворяющий
// требованиям (строчная, заглавная, цифра, спецсимвол, нужная длина) —
// независимо от того, включены требования или нет: раз пользователь
// просит сгенерировать пароль, он должен быть действительно надёжным.
static std::string generateStrongPassword(int length = 16) {
    static const std::string lower = "abcdefghijklmnopqrstuvwxyz";
    static const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const std::string digits = "0123456789";
    static const std::string& special = PASSWORD_SPECIAL_CHARS;

    if (length < MIN_PASSWORD_LENGTH) length = MIN_PASSWORD_LENGTH;

    std::random_device rd;
    std::mt19937_64 gen(rd());

    auto pick = [&](const std::string& set) {
        std::uniform_int_distribution<size_t> dist(0, set.size() - 1);
        return set[dist(gen)];
    };

    std::vector<char> pw;
    pw.reserve(length);
    // Гарантируем хотя бы по одному символу каждой категории.
    pw.push_back(pick(lower));
    pw.push_back(pick(upper));
    pw.push_back(pick(digits));
    pw.push_back(pick(special));

    std::string allChars = lower + upper + digits + special;
    while (static_cast<int>(pw.size()) < length) {
        pw.push_back(pick(allChars));
    }

    // Перемешиваем, чтобы гарантированные символы не оказались всегда в начале.
    std::shuffle(pw.begin(), pw.end(), gen);

    return std::string(pw.begin(), pw.end());
}

// Общий диалог выбора пароля — используется и при регистрации, и при
// восстановлении пароля: пользователь может сгенерировать надёжный
// пароль автоматически или ввести свой вручную (с проверкой требований,
// если ENFORCE_PASSWORD_REQUIREMENTS == true). Возвращает выбранный
// пароль, либо пустую строку, если операция отменена/не удалась.
static std::string choosePassword() {
    if (ENFORCE_PASSWORD_REQUIREMENTS) {
        std::cout << "Требования к паролю: минимум " << MIN_PASSWORD_LENGTH
                  << " символов, строчные и заглавные буквы, цифра, спецсимвол.\n";
    }
    std::cout << "Сгенерировать надёжный пароль автоматически? (д/н): ";
    std::string genChoice;
    std::getline(std::cin, genChoice);
    bool wantsGenerated = (genChoice == "д" || genChoice == "Д" ||
                           genChoice == "y" || genChoice == "Y" || genChoice == "yes");

    if (wantsGenerated) {
        std::string password = generateStrongPassword(16);
        std::cout << "\nСгенерированный пароль: " << password << "\n"
                  << "Сохраните его прямо сейчас в надёжном месте (менеджере паролей и т.п.) —\n"
                  << "после подтверждения он больше нигде не будет показан.\n\n";
        std::string confirm = readHiddenInput("Введите этот пароль ещё раз, чтобы подтвердить, что сохранили: ");
        if (confirm != password) {
            std::cout << "Подтверждение не совпадает со сгенерированным паролем.\n";
            return "";
        }
        return password;
    }

    const int maxAttempts = 3;
    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
        std::string p1 = readHiddenInput("Придумайте пароль: ");
        std::string p2 = readHiddenInput("Повторите пароль: ");
        if (p1.empty()) {
            std::cout << "Пароль не может быть пустым.\n";
            continue;
        }
        if (p1 != p2) {
            std::cout << "Пароли не совпадают.\n";
            continue;
        }
        std::string err;
        if (!isPasswordStrongEnough(p1, err)) {
            std::cout << err;
            continue;
        }
        return p1;
    }
    std::cout << "Не удалось задать пароль, соответствующий требованиям.\n";
    return "";
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

// Разбивает строку на поля по ';' вручную (без std::stringstream +
// std::getline), т.к. связка getline-по-';' некорректно обрабатывает
// случай, когда последнее поле пустое и после него нет ни одного
// символа (например, email у записи, созданной администратором,
// который сам ничего не вводит помимо логина и пароля) — в этом
// случае stream-парсинг просто "теряет" всю строку целиком.
static std::vector<std::string> splitByDelimiter(const std::string& line, char delim) {
    std::vector<std::string> fields;
    size_t start = 0;
    while (true) {
        size_t pos = line.find(delim, start);
        if (pos == std::string::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
    return fields;
}

static std::vector<UserRecord> loadUsers() {
    std::vector<UserRecord> users;
    std::ifstream in(USERS_FILE);
    if (!in.is_open()) return users;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto fields = splitByDelimiter(line, ';');
        if (fields.size() != 5) continue; // повреждённая/некорректная строка — пропускаем
        users.push_back({fields[0], fields[1], fields[2], fields[3], fields[4]});
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

// Полностью перезаписывает users.txt текущим содержимым списка —
// нужно для обновления пароля существующего пользователя (saveUser
// только дописывает новые записи в конец, для смены пароля этого
// недостаточно).
static bool rewriteAllUsers(const std::vector<UserRecord>& users) {
    std::ofstream out(USERS_FILE, std::ios::trunc);
    if (!out.is_open()) return false;
    for (const auto& u : users) {
        out << u.username << ';' << u.saltHex << ';' << u.pwHashHex << ';'
            << u.totpSecretB32 << ';' << u.email << '\n';
    }
    return true;
}

// Обновляет соль и хеш пароля конкретного пользователя, остальные поля
// (TOTP-секрет, email) не трогает. Возвращает false, если пользователь
// не найден или не удалось записать файл.
static bool updateUserPassword(const std::string& username, const std::string& newSaltHex, const std::string& newPwHash) {
    auto users = loadUsers();
    bool found = false;
    for (auto& u : users) {
        if (u.username == username) {
            u.saltHex = newSaltHex;
            u.pwHashHex = newPwHash;
            found = true;
            break;
        }
    }
    if (!found) return false;
    return rewriteAllUsers(users);
}

// Удаляет пользователя по логину. Возвращает false, если пользователь
// не найден или не удалось записать файл.
static bool deleteUserByUsername(const std::string& username) {
    auto users = loadUsers();
    size_t before = users.size();
    users.erase(std::remove_if(users.begin(), users.end(),
        [&](const UserRecord& u) { return u.username == username; }), users.end());
    if (users.size() == before) return false;
    return rewriteAllUsers(users);
}

// Создаёт учётную запись только с логином и паролем (без email и без
// TOTP-секрета) — используется администратором. Привязку почты и
// второго фактора владелец записи должен будет выполнить сам при
// первом входе (см. completeUserSetup / loginUser).
static bool addBasicUser(const std::string& username, const std::string& password) {
    std::string salt = generateSalt();
    std::string pwHash = hashPassword(password, salt);
    return saveUser({username, salt, pwHash, "", ""});
}

// Завершает настройку учётной записи, созданной администратором:
// записывает email и TOTP-секрет пользователю, у которого они ещё
// не заданы. Остальные поля (логин, соль, хеш пароля) не трогает.
static bool completeUserSetup(const std::string& username, const std::string& email, const std::string& totpSecretB32) {
    auto users = loadUsers();
    bool found = false;
    for (auto& u : users) {
        if (u.username == username) {
            u.email = email;
            u.totpSecretB32 = totpSecretB32;
            found = true;
            break;
        }
    }
    if (!found) return false;
    return rewriteAllUsers(users);
}

// ============================================================
// Криптографические примитивы для шифрования сообщений
// ============================================================
static bool hexDecode(const std::string& hex, std::vector<uint8_t>& out) {
    out.clear();
    if (hex.size() % 2 != 0) return false;
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return false; }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

static void secureWipe(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; i++) v[i] = 0;
}
static void secureWipe(std::string& s) { if (!s.empty()) secureWipe(&s[0], s.size()); s.clear(); }
static void secureWipe(std::vector<uint8_t>& v) { if (!v.empty()) secureWipe(v.data(), v.size()); v.clear(); }

// Стрибог-512 над произвольными байтами (для HMAC, PBKDF2, OAEP/MGF1)
static std::vector<uint8_t> streebog512Bytes(const uint8_t* data, size_t len) {
    std::string s;
    if (len) s.assign(reinterpret_cast<const char*>(data), len);
    return streebog512impl::streebog512(s);
}

static std::vector<uint8_t> streebog256Bytes(const uint8_t* data, size_t len) {
    std::string s;
    if (len) s.assign(reinterpret_cast<const char*>(data), len);
    return streebog512impl::streebog256(s);
}

// HMAC на основе Стрибога (Р 50.1.113-2016: HMAC_GOSTR3411_2012_256 / _512).
// Размер блока у обоих вариантов — 64 байта.
constexpr int HMAC_LINE = __LINE__ + 1;
static std::vector<uint8_t> hmacStreebog(const std::vector<uint8_t>& key, const uint8_t* msg, size_t len,
                                         bool variant256) {
    const size_t B = 64;
    auto H = variant256 ? streebog256Bytes : streebog512Bytes;
    const size_t L = variant256 ? 32 : 64;
    std::vector<uint8_t> k = key.size() > B ? H(key.data(), key.size()) : key;
    k.resize(B, 0x00);
    std::vector<uint8_t> inner(B + len), outer(B + L);
    for (size_t i = 0; i < B; i++) { inner[i] = k[i] ^ 0x36; outer[i] = k[i] ^ 0x5c; }
    if (len) std::memcpy(inner.data() + B, msg, len);
    std::vector<uint8_t> ih = H(inner.data(), inner.size());
    std::memcpy(outer.data() + B, ih.data(), L);
    std::vector<uint8_t> res = H(outer.data(), outer.size());
    secureWipe(k); secureWipe(inner); secureWipe(outer);
    return res;
}
static std::vector<uint8_t> hmacStreebog512(const std::vector<uint8_t>& key, const uint8_t* msg, size_t len) {
    return hmacStreebog(key, msg, len, false);
}

// PBKDF2 (RFC 8018) с HMAC-Стрибог-512 — по Р 50.1.111-2016.
// Делает подбор пароля по украденному хранилищу дорогим: каждая
// попытка стоит PBKDF2_ITERATIONS вычислений HMAC.
static const uint32_t PBKDF2_ITERATIONS = 20000;

static std::vector<uint8_t> pbkdf2Streebog512(const std::string& password, const std::vector<uint8_t>& salt,
                                              uint32_t iterations, size_t dkLen) {
    std::vector<uint8_t> pw(password.begin(), password.end());
    std::vector<uint8_t> dk;
    for (uint32_t block = 1; dk.size() < dkLen; block++) {
        std::vector<uint8_t> s = salt;
        s.push_back(static_cast<uint8_t>(block >> 24)); s.push_back(static_cast<uint8_t>(block >> 16));
        s.push_back(static_cast<uint8_t>(block >> 8));  s.push_back(static_cast<uint8_t>(block));
        std::vector<uint8_t> u = hmacStreebog512(pw, s.data(), s.size());
        std::vector<uint8_t> t = u;
        for (uint32_t i = 1; i < iterations; i++) {
            u = hmacStreebog512(pw, u.data(), u.size());
            for (size_t j = 0; j < t.size(); j++) t[j] ^= u[j];
        }
        dk.insert(dk.end(), t.begin(), t.end());
    }
    dk.resize(dkLen);
    secureWipe(pw);
    return dk;
}

// ------------------------------------------------------------
// «Запечатывание» данных: Кузнечик-CTR + имитовставка OMAC
// (Encrypt-then-MAC, отдельные ключи шифрования и имитозащиты).
// Ключ — 64 байта: [0..32) шифрование, [32..64) имитовставка.
// Формат: iv_hex:ciphertext_hex:mac_hex
// ------------------------------------------------------------
struct SealedData {
    std::vector<uint8_t> iv, ct, mac;
};

static SealedData kuzSeal(const std::vector<uint8_t>& key64, const std::string& plaintext) {
    SealedData s;
    s.iv = securerand::bytes(8);
    kuz::Cipher enc(key64.data());
    kuz::Cipher macC(key64.data() + 32);
    s.ct = kuz::ctrXcrypt(enc, s.iv.data(), reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    std::vector<uint8_t> authData = s.iv;
    authData.insert(authData.end(), s.ct.begin(), s.ct.end());
    auto m = kuz::omac(macC, authData.data(), authData.size());
    s.mac.assign(m.begin(), m.end());
    return s;
}

static bool kuzOpen(const std::vector<uint8_t>& key64, const SealedData& s, std::string& plaintext) {
    plaintext.clear();
    if (s.iv.size() != 8 || s.mac.size() != 16) return false;
    kuz::Cipher enc(key64.data());
    kuz::Cipher macC(key64.data() + 32);
    std::vector<uint8_t> authData = s.iv;
    authData.insert(authData.end(), s.ct.begin(), s.ct.end());
    auto m = kuz::omac(macC, authData.data(), authData.size());
    if (!kuz::constTimeEq(m.data(), s.mac.data(), 16)) return false;   // сначала проверка целостности
    auto pt = kuz::ctrXcrypt(enc, s.iv.data(), s.ct.data(), s.ct.size());
    plaintext.assign(pt.begin(), pt.end());
    secureWipe(pt);
    return true;
}

static std::string sealedToString(const SealedData& s) {
    return toHex(s.iv) + ":" + toHex(s.ct) + ":" + toHex(s.mac);
}

static bool sealedFromString(const std::string& str, SealedData& s) {
    size_t a = str.find(':');
    size_t b = (a == std::string::npos) ? std::string::npos : str.find(':', a + 1);
    if (b == std::string::npos) return false;
    return hexDecode(str.substr(0, a), s.iv) && hexDecode(str.substr(a + 1, b - a - 1), s.ct) &&
           hexDecode(str.substr(b + 1), s.mac);
}

// Обёртки для модуля RSA
static rsa::HashFn streebogHashFn() { return [](const uint8_t* d, size_t n) { return streebog512Bytes(d, n); }; }
static rsa::RandomFn cspRandomFn() { return [](uint8_t* b, size_t n) { securerand::fill(b, n); }; }
static const size_t RSA_MODULUS_BITS = 32768;
// Число простых в модуле RSA. 4 — многопростой RSA (RFC 8017): тот же
// 32768-битный модуль, но ключ генерируется в ~3-4 раза быстрее, а
// расшифровывается в ~4-7 раз быстрее. Поставьте 2 для классического RSA (n = p*q).
static const size_t RSA_PRIMES = 4;
static const size_t STREEBOG_LEN = 64;

// ============================================================
// Хранилище пользователя (vault/<hex(логин)>/)
// ============================================================
// keys.txt — строки key=value:
//   kdf_salt, kdf_iter   — параметры PBKDF2 для ключа из пароля (KEK)
//   msg_key              — случайный 512-битный ключ сообщений «Кузнечика»,
//                          запечатанный на KEK
//   rsa_n, rsa_e         — открытый ключ RSA-32768
//   rsa_priv             — закрытый ключ (p:q:d:dp:dq:qinv), запечатанный на KEK
//   rsa_created, rsa_gen_seconds — когда и за сколько сгенерирован ключ
// messages.txt — строки id;unix_time;алгоритм;данные
//   KUZ: iv:шифртекст:имитовставка (hex)
//   RSA: блок1:блок2:... (hex, по 4096 байт)
//
// Секреты на диске хранятся только в зашифрованном виде. Ключ к ним
// выводится из пароля, который знает только пользователь, поэтому без
// пароля (даже имея все файлы) прочитать сообщения нельзя.
const std::string VAULT_DIR = "vault";

static std::string vaultDirFor(const std::string& username) {
    return VAULT_DIR + "/" + toHex(std::vector<uint8_t>(username.begin(), username.end()));
}
static std::string vaultKeysFile(const std::string& u) { return vaultDirFor(u) + "/keys.txt"; }
static std::string vaultMessagesFile(const std::string& u) { return vaultDirFor(u) + "/messages.txt"; }

static bool vaultExists(const std::string& username) {
    std::error_code ec;
    return std::filesystem::exists(vaultKeysFile(username), ec);
}

static void deleteVault(const std::string& username) {
    std::error_code ec;
    std::filesystem::remove_all(vaultDirFor(username), ec);
}

static void restrictToOwner(const std::string& path, bool isDir) {
    std::error_code ec;
    auto perms = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    if (isDir) perms |= std::filesystem::perms::owner_exec;
    std::filesystem::permissions(path, perms, std::filesystem::perm_options::replace, ec);
}

static std::map<std::string, std::string> loadKeyValueFile(const std::string& path) {
    std::map<std::string, std::string> kv;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        kv[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return kv;
}

// Атомарная запись: пишем во временный файл и переименовываем —
// при сбое посреди записи старый файл ключей не будет испорчен.
static bool saveKeyValueFile(const std::string& path, const std::map<std::string, std::string>& kv) {
    std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out.is_open()) return false;
        for (const auto& p : kv) out << p.first << '=' << p.second << '\n';
        if (!out) return false;
    }
    restrictToOwner(tmp, false);
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    return !ec;
}

struct StoredMessage {
    uint64_t id = 0;
    uint64_t created = 0;
    std::string algo;      // "KUZ" или "RSA"
    std::string payload;
    double encSec = -1;    // время шифрования, с (-1 — неизвестно: сообщение старого формата)
};

static std::vector<StoredMessage> loadMessages(const std::string& username) {
    std::vector<StoredMessage> res;
    std::ifstream in(vaultMessagesFile(username));
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto f = splitByDelimiter(line, ';');
        if (f.size() != 4 && f.size() != 5) continue;
        StoredMessage m;
        try {
            m.id = std::stoull(f[0]);
            m.created = std::stoull(f[1]);
            if (f.size() == 5) m.encSec = std::stod(f[4]) / 1e6;   // хранится в микросекундах
        } catch (...) { continue; }
        m.algo = f[2];
        m.payload = f[3];
        res.push_back(std::move(m));
    }
    return res;
}

static bool appendMessage(const std::string& username, const StoredMessage& m) {
    std::string path = vaultMessagesFile(username);
    std::ofstream out(path, std::ios::app);
    if (!out.is_open()) return false;
    out << m.id << ';' << m.created << ';' << m.algo << ';' << m.payload;
    if (m.encSec >= 0) out << ';' << static_cast<long long>(m.encSec * 1e6 + 0.5);
    out << '\n';
    out.close();
    restrictToOwner(path, false);
    return true;
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
    if (username == ADMIN_USERNAME) {
        std::cout << "Это имя зарезервировано, выберите другой логин.\n";
        return;
    }
    if (usernameExists(users, username)) { std::cout << "Такой логин уже занят.\n"; return; }

    std::string email;
    std::cout << "Введите email (для третьего фактора): ";
    std::getline(std::cin, email);
    if (!isValidField(email) || email.find('@') == std::string::npos) {
        std::cout << "Некорректный email.\n";
        return;
    }

    // Выбор пароля: сгенерировать автоматически или ввести вручную.
    std::string password = choosePassword();
    if (password.empty()) {
        std::cout << "Регистрация отменена.\n";
        return;
    }

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
// Панель администратора
// ============================================================
// Доступна только под служебной учётной записью Admin (см. ADMIN_USERNAME
// / ADMIN_PASSWORD выше). Проверяется только пароль — без TOTP и без
// почты, т.к. это единая служебная запись, а не аккаунт с почтой.
static void runAdminPanel() {
    while (true) {
        auto users = loadUsers();

        std::cout << "\n--- Панель администратора ---\n"
                  << "1. Показать все учётные записи\n"
                  << "2. Добавить новую учётную запись (только логин+пароль)\n"
                  << "3. Удалить учётную запись\n"
                  << "4. Выйти из панели администратора\n"
                  << "Выберите пункт: ";
        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            if (users.empty()) {
                std::cout << "Учётных записей пока нет.\n";
                continue;
            }
            std::vector<std::vector<std::string>> rows;
            rows.reserve(users.size());
            for (const auto& u : users) {
                bool setupDone = !u.email.empty() && !u.totpSecretB32.empty();
                rows.push_back({
                    u.username,
                    u.email.empty() ? "(не задан)" : u.email,
                    setupDone ? "завершена" : "ожидает первого входа пользователя"
                });
            }
            std::cout << "\n";
            printAlignedTable({"Логин", "Email", "Настройка 2-го/3-го фактора"}, rows);
        } else if (choice == "2") {
            std::string newUsername;
            std::cout << "Логин новой учётной записи: ";
            std::getline(std::cin, newUsername);
            if (!isValidField(newUsername) || newUsername == ADMIN_USERNAME) {
                std::cout << "Некорректный или зарезервированный логин.\n";
                continue;
            }
            if (usernameExists(users, newUsername)) {
                std::cout << "Такой логин уже занят.\n";
                continue;
            }
            std::string newPassword = choosePassword();
            if (newPassword.empty()) {
                std::cout << "Создание учётной записи отменено.\n";
                continue;
            }
            if (!addBasicUser(newUsername, newPassword)) {
                std::cout << "Ошибка: не удалось создать учётную запись.\n";
                continue;
            }
            std::cout << "Учётная запись \"" << newUsername << "\" создана (только логин и пароль).\n"
                      << "Владелец должен будет привязать email и настроить TOTP при первом входе.\n";
        } else if (choice == "3") {
            std::string delUsername;
            std::cout << "Логин учётной записи для удаления: ";
            std::getline(std::cin, delUsername);
            if (delUsername == ADMIN_USERNAME) {
                std::cout << "Служебную запись Admin удалить нельзя.\n";
                continue;
            }
            std::string confirm;
            std::cout << "Точно удалить \"" << delUsername << "\"? Это необратимо (д/н): ";
            std::getline(std::cin, confirm);
            if (confirm != "д" && confirm != "Д" && confirm != "y" && confirm != "Y") {
                std::cout << "Удаление отменено.\n";
                continue;
            }
            if (!deleteUserByUsername(delUsername)) {
                std::cout << "Пользователь не найден.\n";
                continue;
            }
            deleteVault(delUsername);   // вместе с учёткой удаляем её ключи и сообщения
            std::cout << "Учётная запись \"" << delUsername << "\" удалена.\n";
        } else if (choice == "4") {
            std::cout << "Выход из панели администратора.\n";
            return;
        } else {
            std::cout << "Некорректный выбор, попробуйте снова.\n";
        }
    }
}

// Первый вход в учётную запись, созданную администратором (у неё ещё
// нет email и TOTP-секрета): просим владельца привязать почту и
// сгенерировать TOTP-секрет, прежде чем продолжать обычный вход.
// Возвращает true, если настройка успешно завершена (и users/it
// нужно перечитать), false — если пользователь прервал процесс.
static bool completeFirstLoginSetup(const std::string& username) {
    std::cout << "\nЭта учётная запись была создана администратором и ещё не имеет\n"
              << "привязанной почты и настроенного TOTP. Нужно завершить настройку,\n"
              << "прежде чем продолжить вход.\n";

    std::string email;
    std::cout << "Введите email (для третьего фактора): ";
    std::getline(std::cin, email);
    if (!isValidField(email) || email.find('@') == std::string::npos) {
        std::cout << "Некорректный email. Вход отменён.\n";
        return false;
    }

    std::string totpSecret = generateTotpSecretBase32();
    if (!completeUserSetup(username, email, totpSecret)) {
        std::cout << "Ошибка: не удалось сохранить настройки. Вход отменён.\n";
        return false;
    }

    std::string issuer = "MyConsoleApp";
    std::string otpauthUri = "otpauth://totp/" + issuer + ":" + username +
        "?secret=" + totpSecret + "&issuer=" + issuer + "&digits=" +
        std::to_string(totpDigits) + "&period=" + std::to_string(totpPeriod);

    std::cout << "\nНастройка завершена!\n"
              << "Секрет для приложения-аутентификатора (Google Authenticator/Authy):\n"
              << "  " << totpSecret << "\n"
              << "Либо добавьте вручную по ссылке (можно превратить в QR-код на любом онлайн-генераторе):\n"
              << "  " << otpauthUri << "\n\n"
              << "Продолжаем вход...\n\n";
    return true;
}

// ============================================================
// Проверка реализации по контрольным примерам ГОСТ
// ============================================================
// Значения взяты из текстов стандартов:
//   ГОСТ Р 34.11-2012 (Стрибог), прил. А — примеры 1 и 2 для 512 и 256 бит;
//   ГОСТ Р 34.12-2015 (Кузнечик), прил. А.1 — промежуточные значения
//     преобразований S, R, L, итерационные константы C_i, развёртка ключа
//     K_1..K_10, зашифрование и расшифрование блока;
//   ГОСТ Р 34.13-2015, прил. А.1 — режимы простой замены (ECB),
//     гаммирования (CTR) и выработки имитовставки (MAC);
//   Р 50.1.113-2016 — HMAC на Стрибоге-256/512.
// В ГОСТ Р 34.11-2012 числа записаны старшим байтом вперёд, а программа
// хранит байты в порядке следования в памяти, поэтому для Стрибога
// сравнивается развёрнутая запись — ровно в том виде, как в стандарте.
// Эти проверки выполняются при каждом запуске программы (самотестирование
// криптомодуля); при расхождении работа прекращается.
static std::string findFontPath(bool mono);   // определены ниже
static pdfsig::HashFn streebog256HashFn();

struct KatResult {
    std::string algo, name, source, expected, got;
    std::vector<std::string> params;   // какие константы ГОСТ участвуют и где они заданы в программе
    std::string input;                 // входные данные из приложения к стандарту
    std::string note;                  // пояснение (например, про порядок байтов)
    bool ok() const { return expected == got; }
};

static std::string reverseHex(const std::string& hex) {
    std::string r;
    for (size_t i = hex.size(); i >= 2; i -= 2) r += hex.substr(i - 2, 2);
    return r;
}

static std::vector<uint8_t> hexBytes(const std::string& hex) {
    std::vector<uint8_t> v;
    hexDecode(hex, v);
    return v;
}

static std::string blockHex(const kuz::Block& b) { return toHex(std::vector<uint8_t>(b.begin(), b.end())); }

static std::string where(const char* file, int line, const std::string& what) {
    return std::string(file) + ", строка " + std::to_string(line) + " (" + what + ")";
}

// ---- описания параметров ГОСТ и мест, где они заданы в программе ----
static std::vector<std::string> streebogParams(bool v256) {
    return {
        "π - нелинейная биекция, 256 байт: " + where("auth3fa.cpp", streebog512impl::PI_LINE, "массив Pi"),
        "τ - перестановка байтов: " + where("auth3fa.cpp", streebog512impl::TAU_LINE, "функция makeTauEntry"),
        "A - матрица линейного преобразования l, 64 строки по 64 бита: " +
            where("auth3fa.cpp", streebog512impl::A_LINE, "массив A[64]") + "; ускоряющая таблица строится из неё: " +
            where("auth3fa.cpp", streebog512impl::LTABLE_LINE, "структура LTable"),
        "C1..C12 - итерационные константы по 512 бит: " + where("auth3fa.cpp", streebog512impl::C_LINE, "массив C_qwords[12][8]"),
        std::string("IV = ") + (v256 ? "(00000001)^64 для варианта 256 бит" : "0^512 для варианта 512 бит") + ": " +
            where("auth3fa.cpp", streebog512impl::CORE_LINE, "функция streebogCore"),
    };
}
static std::vector<std::string> hmacParams(bool v256) {
    auto p = streebogParams(v256);
    p.push_back("ipad = 0x36, opad = 0x5c, блок 64 байта: " + where("auth3fa.cpp", HMAC_LINE, "функция hmacStreebog"));
    return p;
}
static std::string kuzPiParam() { return "π - нелинейная биекция, 256 байт: " + where("kuznyechik.hpp", kuz::PI_LINE, "массив kuz::PI"); }
static std::string kuzLcParam() {
    return "коэффициенты линейного преобразования l (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1): " +
           where("kuznyechik.hpp", kuz::LC_LINE, "массив kuz::LC");
}
static std::string kuzFieldParam() {
    return "поле GF(2^8), p(x) = x^8 + x^7 + x^6 + x + 1: " + where("kuznyechik.hpp", kuz::GFMUL_LINE, "функция kuz::gfMul");
}
static std::string kuzKeyParam() {
    return "развёртка ключа, C_i = L(Vec128(i)), 32 раунда сети Фейстеля: " +
           where("kuznyechik.hpp", kuz::Cipher::EXPANDKEY_LINE, "метод Cipher::expandKey");
}
static std::string kuzTablesParam() {
    return "таблицы LS 16x256 (строятся при запуске из π и l): " + where("kuznyechik.hpp", kuz::TABLES_LINE, "структура kuz::Tables");
}
static std::vector<std::string> kuzCipherParams() {
    return {kuzPiParam(), kuzLcParam(), kuzFieldParam(), kuzKeyParam(), kuzTablesParam()};
}

static std::vector<KatResult> gostKats() {
    std::vector<KatResult> r;

    // ---------- ГОСТ Р 34.11-2012 ----------
    const std::string src34112 = "ГОСТ Р 34.11-2012, прил. А";
    const std::string beNote = "в ГОСТ Р 34.11-2012 числа записаны старшим байтом вперёд; результат программы "
                               "переведён в эту же запись";
    const std::string M1 = "012345678901234567890123456789012345678901234567890123456789012";
    const std::string m1Gost = reverseHex(toHex(std::vector<uint8_t>(M1.begin(), M1.end())));
    const std::string m2Gost = "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5"
                               "e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1";
    const auto m2b = hexBytes(reverseHex(m2Gost));   // в памяти — обратный порядок
    const std::string M2(m2b.begin(), m2b.end());
    const std::string in1 = "M1 = " + m1Gost + " (63 байта: строка \"" + M1 + "\")";
    const std::string in2 = "M2 = " + m2Gost + " (72 байта в CP1251: \"Се ветри, Стрибожи внуци, веютъ с моря "
                            "стрелами на храбрыя плъкы Игоревы\")";
    r.push_back({"Стрибог-512", "Пример 1", src34112,
        "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00"
        "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b",
        reverseHex(streebog512Hex(M1)), streebogParams(false), in1, beNote});
    r.push_back({"Стрибог-512", "Пример 2", src34112,
        "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03"
        "7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e",
        reverseHex(streebog512Hex(M2)), streebogParams(false), in2, beNote});
    r.push_back({"Стрибог-256", "Пример 1", src34112,
        "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d",
        reverseHex(streebog256Hex(M1)), streebogParams(true), in1, beNote});
    r.push_back({"Стрибог-256", "Пример 2", src34112,
        "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d",
        reverseHex(streebog256Hex(M2)), streebogParams(true), in2, beNote});

    // ---------- Р 50.1.113-2016: HMAC ----------
    const std::string hkHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const std::string hmHex = "0126bdb87800af214341456563780100";
    const auto hk = hexBytes(hkHex), hm = hexBytes(hmHex);
    const std::string hin = "ключ K = " + hkHex + "\nданные T = " + hmHex;
    r.push_back({"HMAC-Стрибог-256", "HMAC_GOSTR3411_2012_256", "Р 50.1.113-2016",
        "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9",
        toHex(hmacStreebog(hk, hm.data(), hm.size(), true)), hmacParams(true), hin, ""});
    r.push_back({"HMAC-Стрибог-512", "HMAC_GOSTR3411_2012_512", "Р 50.1.113-2016",
        "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77"
        "3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6",
        toHex(hmacStreebog(hk, hm.data(), hm.size(), false)), hmacParams(false), hin, ""});

    // ---------- ГОСТ Р 34.12-2015: преобразования ----------
    const std::string src3412 = "ГОСТ Р 34.12-2015, прил. А.1";
    auto blk = [](const std::string& h) { kuz::Block b{}; auto v = hexBytes(h); std::copy(v.begin(), v.end(), b.begin()); return b; };
    auto opS = [](kuz::Block b) { for (auto& x : b) x = kuz::PI[x]; return b; };

    const char* sExp[4] = {"b66cd8887d38e8d77765aeea0c9a7efc", "559d8dd7bd06cbfe7e7b262523280d39",
                           "0c3322fed531e4630d80ef5c5a81c50b", "23ae65633f842d29c5df529c13f5acda"};
    kuz::Block s = blk("ffeeddccbbaa99881122334455667700");
    for (int i = 0; i < 4; i++) {
        std::string in = "S(" + blockHex(s) + ")";
        s = opS(s);
        r.push_back({"Кузнечик", "Преобразование S, шаг " + std::to_string(i + 1), src3412, sExp[i], blockHex(s),
                     {kuzPiParam()}, in, ""});
    }
    const char* rExp[4] = {"94000000000000000000000000000001", "a5940000000000000000000000000000",
                           "64a59400000000000000000000000000", "0d64a594000000000000000000000000"};
    kuz::Block rr = blk("00000000000000000000000000000100");
    for (int i = 0; i < 4; i++) {
        std::string in = "R(" + blockHex(rr) + ")";
        rr = kuz::opR(rr);
        r.push_back({"Кузнечик", "Преобразование R, шаг " + std::to_string(i + 1), src3412, rExp[i], blockHex(rr),
                     {kuzLcParam(), kuzFieldParam()}, in, ""});
    }
    const char* lExp[4] = {"d456584dd0e3e84cc3166e4b7fa2890d", "79d26221b87b584cd42fbc4ffea5de9a",
                           "0e93691a0cfc60408b7b68f66b513c13", "e6a8094fee0aa204fd97bcb0b44b8580"};
    kuz::Block ll = blk("64a59400000000000000000000000000");
    for (int i = 0; i < 4; i++) {
        std::string in = "L(" + blockHex(ll) + "), L = R^16";
        ll = kuz::opL(ll);
        r.push_back({"Кузнечик", "Преобразование L, шаг " + std::to_string(i + 1), src3412, lExp[i], blockHex(ll),
                     {kuzLcParam(), kuzFieldParam()}, in, ""});
    }
    const char* cExp[4] = {"6ea276726c487ab85d27bd10dd849401", "dc87ece4d890f4b3ba4eb92079cbeb02",
                           "b2259a96b4d88e0be7690430a44f7f03", "7bcd1b0b73e32ba5b79cb140f2551504"};
    for (int i = 0; i < 4; i++) {
        kuz::Block c{};
        c[15] = static_cast<uint8_t>(i + 1);
        r.push_back({"Кузнечик", "Константа C" + std::to_string(i + 1), src3412, cExp[i], blockHex(kuz::opL(c)),
                     {kuzLcParam(), kuzFieldParam(), kuzKeyParam()}, "C" + std::to_string(i + 1) + " = L(" + blockHex(c) + ")", ""});
    }

    // ---------- развёртка ключа и блок ----------
    const std::string keyHex = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";
    const auto key = hexBytes(keyHex);
    kuz::Cipher cipher(key.data());
    const std::string kin = "ключ K = " + keyHex;
    const char* kExp[10] = {
        "8899aabbccddeeff0011223344556677", "fedcba98765432100123456789abcdef",
        "db31485315694343228d6aef8cc78c44", "3d4553d8e9cfec6815ebadc40a9ffd04",
        "57646468c44a5e28d3e59246f429f1ac", "bd079435165c6432b532e82834da581b",
        "51e640757e8745de705727265a0098b1", "5a7925017b9fdd3ed72a91a22286f984",
        "bb44e25378c73123a5f32f73cdb6e517", "72e9dd7416bcf45b755dbaa88e4a4043"};
    for (int i = 0; i < 10; i++)
        r.push_back({"Кузнечик", "Раундовый ключ K" + std::to_string(i + 1), src3412, kExp[i], blockHex(cipher.roundKey(i)),
                     {kuzPiParam(), kuzLcParam(), kuzFieldParam(), kuzKeyParam()}, kin, ""});

    std::vector<uint8_t> out(16), back(16);
    const std::string p1Hex = "1122334455667700ffeeddccbbaa9988";
    const auto p1 = hexBytes(p1Hex);
    cipher.encryptBlock(p1.data(), out.data());
    cipher.decryptBlock(out.data(), back.data());
    r.push_back({"Кузнечик", "Зашифрование блока", src3412, "7f679d90bebc24305a468d42b9d4edcd", toHex(out),
                 kuzCipherParams(), kin + "\nоткрытый текст a = " + p1Hex, ""});
    r.push_back({"Кузнечик", "Расшифрование блока", src3412, p1Hex, toHex(back),
                 kuzCipherParams(), kin + "\nшифртекст b = 7f679d90bebc24305a468d42b9d4edcd", ""});

    // ---------- ГОСТ Р 34.13-2015: режимы ----------
    const std::string src3413 = "ГОСТ Р 34.13-2015, прил. А.1";
    const std::string ptHex = "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"
                              "112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011";
    const auto pt = hexBytes(ptHex);
    const char* ecbExp[4] = {"7f679d90bebc24305a468d42b9d4edcd", "b429912c6e0032f9285452d76718d08b",
                             "f0ca33549d247ceef3f5a5313bd4b157", "d0b09ccde830b9eb3a02c4c5aa8ada98"};
    for (int i = 0; i < 4; i++) {
        std::string pi = ptHex.substr(32 * i, 32);
        cipher.encryptBlock(pt.data() + 16 * i, out.data());
        cipher.decryptBlock(out.data(), back.data());
        r.push_back({"Кузнечик-ECB", "Блок " + std::to_string(i + 1) + ", зашифрование", src3413, ecbExp[i], toHex(out),
                     kuzCipherParams(), kin + "\nP" + std::to_string(i + 1) + " = " + pi, ""});
        r.push_back({"Кузнечик-ECB", "Блок " + std::to_string(i + 1) + ", расшифрование", src3413, pi, toHex(back),
                     kuzCipherParams(), kin + "\nC" + std::to_string(i + 1) + " = " + ecbExp[i], ""});
    }
    const std::string ivHex = "1234567890abcef0";
    const auto iv = hexBytes(ivHex);
    auto ctrParams = kuzCipherParams();
    ctrParams.push_back("CTR_1 = IV || 0^64, CTR_{i+1} = CTR_i + 1 mod 2^128: " +
                        where("kuznyechik.hpp", kuz::CTR_LINE, "функция kuz::ctrXcrypt"));
    auto ctr = kuz::ctrXcrypt(cipher, iv.data(), pt.data(), pt.size());
    const std::string ctrExp = "f195d8bec10ed1dbd57b5fa240bda1b885eee733f6a13e5df33ce4b33c45dee4"
                               "a5eae88be6356ed3d5e877f13564a3a5cb91fab1f20cbab6d1c6d15820bdba73";
    r.push_back({"Кузнечик-CTR", "Гаммирование, 4 блока", src3413, ctrExp, toHex(ctr), ctrParams,
                 kin + "\nIV = " + ivHex + "\nP = " + ptHex, ""});
    auto ctrBack = kuz::ctrXcrypt(cipher, iv.data(), ctr.data(), ctr.size());
    r.push_back({"Кузнечик-CTR", "Обратное гаммирование", src3413, ptHex, toHex(ctrBack), ctrParams,
                 kin + "\nIV = " + ivHex + "\nC = " + ctrExp, ""});
    auto macParams = kuzCipherParams();
    macParams.push_back("B_128 = 0^120 || 10000111 (0x87) для выработки K1, K2: " +
                        where("kuznyechik.hpp", kuz::OMAC_LINE, "функция kuz::omacShift"));
    auto mac = kuz::omac(cipher, pt.data(), pt.size());
    r.push_back({"Кузнечик-MAC", "Имитовставка, s = 64", src3413, "336f4d296059fbe3",
                 toHex(std::vector<uint8_t>(mac.begin(), mac.begin() + 8)), macParams,
                 kin + "\nP = " + ptHex, "s = 64: берутся старшие 64 бита имитовставки"});

    // ---------- ГОСТ Р 34.10-2012: контрольный пример 1 ----------
    const std::string src3410 = "ГОСТ Р 34.10-2012, прил. А, пример 1";
    const auto& tc = gost3410::testCurve();
    auto lc = [](const std::string& h) { std::string r = h; for (auto& ch : r) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch))); return r; };
    std::vector<std::string> p3410 = {
        "параметры тестовой кривой p, a, b, q, P = (xP, yP) из примера 1: " +
            where("gost3410.hpp", gost3410::CURVE_TEST_LINE, "функция testCurve"),
        "вычисление подписи (шаги 3-5 п. 6.1): " + where("gost3410.hpp", gost3410::SIGN_LINE, "функция signWithK"),
    };
    const std::string dHex = "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28";
    const std::string eHex = "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5";
    const std::string kHex = "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";
    gost3410::Mpz d = gost3410::hexMpz(dHex.c_str()), e = gost3410::hexMpz(eHex.c_str()), k = gost3410::hexMpz(kHex.c_str());
    gost3410::Point Qt = gost3410::publicFromPrivate(tc, d);
    auto pad64 = [](std::string h) { return std::string(h.size() < 64 ? 64 - h.size() : 0, '0') + h; };
    std::vector<std::string> pKey = {p3410[0]};
    r.push_back({"ГОСТ 34.10-2012", "Открытый ключ: xQ", src3410,
                 "7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b", pad64(Qt.x.toHex()), pKey,
                 "закрытый ключ d = " + lc(dHex) + "\nQ = d*P", ""});
    r.push_back({"ГОСТ 34.10-2012", "Открытый ключ: yQ", src3410,
                 "26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da", pad64(Qt.y.toHex()), pKey,
                 "закрытый ключ d = " + lc(dHex) + "\nQ = d*P", ""});
    gost3410::Signature sg;
    gost3410::signWithK(tc, d, e, k, sg);
    const std::string sIn = "d = " + lc(dHex) + "\ne = " + lc(eHex) + "\nk = " + lc(kHex);
    r.push_back({"ГОСТ 34.10-2012", "Подпись: r = xC mod q", src3410,
                 "41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493", pad64(sg.r.toHex()), p3410, sIn, ""});
    r.push_back({"ГОСТ 34.10-2012", "Подпись: s = (r*d + k*e) mod q", src3410,
                 "01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40", pad64(sg.s.toHex()), p3410, sIn, ""});
    std::vector<std::string> pVer = {p3410[0], "проверка подписи (п. 6.2): " +
                                     where("gost3410.hpp", gost3410::VERIFY_LINE, "функция verifyE")};
    r.push_back({"ГОСТ 34.10-2012", "Проверка подписи (r, s)", src3410, "подпись верна",
                 gost3410::verifyE(tc, Qt, e, sg) ? "подпись верна" : "подпись неверна", pVer,
                 "Q, e из примера, (r, s) - полученные выше", ""});
    return r;
}

// Подробный отчёт по каждой проверке: параметры ГОСТ и где они заданы,
// входные данные из приложения, полученное и ожидаемое значение, итог.
static void printWrappedHex(const std::string& label, const std::string& hex) {
    const size_t W = 64;
    std::string pad(utf8DisplayWidth(label), ' ');
    for (size_t i = 0; i < hex.size() || i == 0; i += W) {
        std::cout << (i == 0 ? label : pad) << hex.substr(i, W) << "\n";
        if (hex.empty()) break;
    }
}

static void printKatDetails(const std::vector<KatResult>& results) {
    for (size_t i = 0; i < results.size(); i++) {
        const auto& k = results[i];
        std::cout << "\n[" << (i + 1) << "/" << results.size() << "] " << k.algo << " - " << k.name << "\n"
                  << "  Эталон взят из: " << k.source << "\n"
                  << "  Использованы параметры ГОСТ:\n";
        for (const auto& p : k.params) std::cout << "    - " << p << "\n";
        std::cout << "  Входные данные из приложения:\n";
        size_t start = 0;
        while (true) {
            size_t nl = k.input.find('\n', start);
            std::cout << "    " << k.input.substr(start, nl == std::string::npos ? std::string::npos : nl - start) << "\n";
            if (nl == std::string::npos) break;
            start = nl + 1;
        }
        if (!k.note.empty()) std::cout << "  Примечание: " << k.note << "\n";
        printWrappedHex("  Получено программой: ", k.got);
        printWrappedHex("  Ожидается по ГОСТ:   ", k.expected);
        std::cout << "  Итог: " << (k.ok() ? "СОВПАЛО" : "НЕ СОВПАЛО") << "\n";
    }
}

// Дополнительные проверки (не из ГОСТ): границы блоков Стрибога по
// независимой эталонной реализации, целостность «запечатывания», RSA-OAEP.
static std::vector<KatResult> extraChecks() {
    std::vector<KatResult> r;
    const std::string src = "эталонная реализация";
    struct Vec { const char* name; std::string input; const char* expected; };
    const std::vector<Vec> vectors = {
        {"пустое сообщение", std::string(),
         "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a"},
        {"строка abc", std::string("abc"),
         "28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728"},
        {"'a' x 64 (ровно блок)", std::string(64, 'a'),
         "613852076ca11156cf7d00f4feef0d5e3198e638f8e20eb02da2f5f7dca5b62dd9fb88e22e825f727ed6f25e4145dc868d0ef41e3e451e34b780e5547ade0d43"},
        {"'a' x 65", std::string(65, 'a'),
         "42baf8f1711d47b6de63559743d09f5e11c9a348bea73b8bb3fe11be0ec0f6029856d70b936a00f7414b5f1ebd8e2bdaa74f3a893b90978da9cadcb72ae50338"},
        {"'a' x 128 (два блока)", std::string(128, 'a'),
         "24741e27419b5e5796383cc54a915c5a69322c758f4391f48f2f120d832f840a82c4a23528d15612febfd2647ce64a97ba6ead9686617876f2d197087b47280f"},
        {"'a' x 129", std::string(129, 'a'),
         "14ae98a06eedc746250d75a7c961ae7b058f5408f7c221df81b229935a3f6c134c704c6b431eb52b5ebcee51ea83d5f894415166c203ba3c740af1c43f610b5a"},
        {"0xFF x 64", std::string(64, '\xff'),
         "41629de677d7e8090c3cd70affe3300d1e1cfba2db97945ec37feb4e1375bc02a53f00370b7d715b07f37f93cac844efadbfd1b85f9ddae3de9656c0e95affc7"},
        {"0x00 x 64", std::string(64, '\0'),
         "b0fd29ac1b0df441769ff3fdb8dc564df67721d6ac06fb28ceffb7bbaa7948c6c014ac999235b58cb26fb60fb112a145d7b4ade9ae566bf2611402c552d20db7"},
    };
    for (const auto& v : vectors)
        r.push_back({"Стрибог-512", std::string("Граница блока: ") + v.name, src, v.expected, streebog512Hex(v.input), {}, "", ""});

    std::vector<uint8_t> k64 = securerand::bytes(64);
    SealedData sd = kuzSeal(k64, "Проверка целостности");
    std::string out;
    bool okOpen = kuzOpen(k64, sd, out) && out == "Проверка целостности";
    sd.ct[3] ^= 0x01;
    bool tamperCaught = !kuzOpen(k64, sd, out);
    r.push_back({"Кузнечик-CTR+OMAC", "Расшифрование и обнаружение подмены", "свойство схемы", "ok",
                 (okOpen && tamperCaught) ? "ok" : "fail", {}, "", ""});

    // ГОСТ Р 34.10-2012 на рабочей кривой и подпись PDF
    const auto& wc = gost3410::workCurve();
    r.push_back({"ГОСТ 34.10-2012", "Рабочая кривая: P на кривой, q*P = O, p и q простые", "RFC 4357 / Р 50.1.114-2016",
                 "ok", gost3410::curveSane(wc) ? "ok" : "fail", {}, "", ""});
    {
        auto kp = gost3410::generateKey(wc, cspRandomFn());
        pdfsig::CertInfo ci;
        ci.commonName = "selftest";
        ci.notBefore = static_cast<time_t>(nowUnixTime());
        ci.notAfter = ci.notBefore + 3600;
        auto cert = pdfsig::buildSelfSignedCert(wc, kp, ci, streebog256HashFn(), cspRandomFn());
        pdf::Document doc;
        std::string err, font = findFontPath(false);
        bool built = !font.empty() && doc.addFont(font, err) >= 0;
        std::string tmp = "selftest_signed.pdf";
        bool ok = false, tamper = false, append = false;
        if (built) {
            doc.paragraph("Проверка подписи", 12);
            pdf::Document::SignatureRequest req;
            req.name = "selftest";
            req.when = ci.notBefore;
            req.signer = [&](const std::string& part) {
                auto dg = streebog256Bytes(reinterpret_cast<const uint8_t*>(part.data()), part.size());
                return pdfsig::buildCms(wc, kp, cert, dg, ci.notBefore, streebog256HashFn(), cspRandomFn());
            };
            doc.setSignature(req);
            if (doc.save(tmp, err)) {
                std::ifstream in(tmp, std::ios::binary);
                std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                ok = pdfsig::verifyPdfBytes(data, streebog256HashFn()).valid();
                std::string t1 = data;
                t1[200] ^= 0x01;              // меняем один байт в подписанной части (до /Contents)
                tamper = !pdfsig::verifyPdfBytes(t1, streebog256HashFn()).valid();
                append = !pdfsig::verifyPdfBytes(data + "%extra\n", streebog256HashFn()).valid();   // дописали в конец
            }
            std::remove(tmp.c_str());
        }
        r.push_back({"Подпись PDF", built ? "Подпись, проверка, подмена байта, дописывание в конец" : "Шрифт не найден - пропуск",
                     "ISO 32000-1, RFC 5652", "ok", (ok && tamper && append) ? "ok" : "fail", {}, "", ""});
    }

    std::vector<size_t> primeCounts = {2};
    if (RSA_PRIMES != 2) primeCounts.push_back(RSA_PRIMES);
    for (size_t u : primeCounts) {
        rsa::PrivateKey sk = rsa::generateKey(2048, u, cspRandomFn(), nullptr);
        std::string msg;
        for (int i = 0; i < 20; i++) msg += "Тест RSA-OAEP " + std::to_string(i) + ". ";
        auto blocks = rsa::encryptMessage(sk.pub(), streebogHashFn(), STREEBOG_LEN, cspRandomFn(), msg);
        std::string dec, restored;
        bool rsaOk = rsa::decryptMessage(sk, streebogHashFn(), STREEBOG_LEN, blocks, dec) && dec == msg;
        rsa::PrivateKey sk2;
        bool serOk = sk2.deserializeSecret(sk.serializeSecret(), sk.n, sk.e) &&
                     rsa::decryptMessage(sk2, streebogHashFn(), STREEBOG_LEN, blocks, restored) && restored == msg;
        blocks[0][100] ^= 0x01;
        bool rsaTamper = !rsa::decryptMessage(sk, streebogHashFn(), STREEBOG_LEN, blocks, dec);
        r.push_back({"RSA-OAEP", "2048 бит, " + std::to_string(u) + " простых: " + std::to_string(blocks.size()) +
                     " блока, ключ, подмена", "RFC 8017", "ok", (rsaOk && serOk && rsaTamper) ? "ok" : "fail", {}, "", ""});
    }
    return r;
}

static std::string shortHex(const std::string& h) {
    bool ascii = std::all_of(h.begin(), h.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80; });
    return (ascii && h.size() > 16) ? h.substr(0, 16) + "..." : h;   // текст (не hex) не обрезаем
}

// Печатает таблицу результатов; возвращает true, если всё совпало
static bool printKatTable(const std::vector<KatResult>& results) {
    std::vector<std::vector<std::string>> rows;
    size_t passed = 0;
    std::string prevAlgo;
    for (size_t i = 0; i < results.size(); i++) {
        const auto& k = results[i];
        if (!prevAlgo.empty() && k.algo != prevAlgo) rows.push_back({"---"});
        prevAlgo = k.algo;
        if (k.ok()) passed++;
        rows.push_back({std::to_string(i + 1), k.algo, k.name, k.source, shortHex(k.expected), k.ok() ? "OK" : "ОШИБКА"});
    }
    printAsciiTable({"№", "Алгоритм", "Проверка", "Источник", "Эталон (начало)", "Итог"}, rows,
                    {Align::Right, Align::Left, Align::Left, Align::Left, Align::Left, Align::Left});
    for (size_t i = 0; i < results.size(); i++) {
        if (results[i].ok()) continue;
        std::cout << "Расхождение в проверке №" << (i + 1) << " (" << results[i].algo << ", " << results[i].name << "):\n"
                  << "  эталон:   " << results[i].expected << "\n  получено: " << results[i].got << "\n";
    }
    std::cout << "Пройдено " << passed << " из " << results.size() << ".\n";
    return passed == results.size();
}

// Самотестирование при запуске: только контрольные примеры ГОСТ (быстро)
static bool startupSelfTest() {
    auto results = gostKats();
    size_t passed = 0;
    for (const auto& k : results) passed += k.ok();
    if (passed == results.size()) {
        std::cout << "Самотестирование по контрольным примерам ГОСТ: " << passed << "/" << results.size() << " OK\n";
        return true;
    }
    std::cout << "\nСАМОТЕСТИРОВАНИЕ НЕ ПРОЙДЕНО — реализация шифров повреждена:\n";
    printKatTable(results);
    return false;
}

// ============================================================
// Производительность и статистика
// ============================================================
using BenchClock = std::chrono::steady_clock;
static double secondsSince(BenchClock::time_point t) {
    return std::chrono::duration<double>(BenchClock::now() - t).count();
}

struct TimingStat { size_t n = 0; double mean = 0, median = 0, min = 0, max = 0, sd = 0; };

static TimingStat summarize(std::vector<double> v) {
    TimingStat s;
    s.n = v.size();
    if (v.empty()) return s;
    std::sort(v.begin(), v.end());
    s.min = v.front();
    s.max = v.back();
    s.median = v.size() % 2 ? v[v.size() / 2] : (v[v.size() / 2 - 1] + v[v.size() / 2]) / 2;
    double sum = 0;
    for (double x : v) sum += x;
    s.mean = sum / v.size();
    double sq = 0;
    for (double x : v) sq += (x - s.mean) * (x - s.mean);
    s.sd = v.size() > 1 ? std::sqrt(sq / (v.size() - 1)) : 0;
    return s;
}

// Одно измерение = batch вызовов f (время делится на batch, чтобы мерить
// и наносекундные операции). Повторяем, пока не наберётся minRuns
// измерений и не пройдёт minSeconds, но не больше maxRuns.
template <class F>
static TimingStat measure(F&& f, size_t batch, size_t minRuns, double minSeconds, size_t maxRuns, bool warmup = true) {
    // Прогрев ~50 мс: прогружает таблицы в кэш и выводит частоту ядра из
    // режима энергосбережения, иначе первые замеры завышены.
    if (warmup) {
        auto w = BenchClock::now();
        do { f(); } while (secondsSince(w) < 0.05);
    }
    std::vector<double> samples;
    auto start = BenchClock::now();
    while (samples.size() < maxRuns && (samples.size() < minRuns || secondsSince(start) < minSeconds)) {
        auto t = BenchClock::now();
        for (size_t i = 0; i < batch; i++) f();
        samples.push_back(secondsSince(t) / static_cast<double>(batch));
    }
    return summarize(samples);
}

static std::string fmtNum(double v, int prec) {
    std::ostringstream os;
    os << std::fixed << std::setprecision(prec) << v;
    return os.str();
}
static std::string fmtTime(double sec) {
    if (sec < 1e-6) return fmtNum(sec * 1e9, 1) + " нс";
    if (sec < 1e-3) return fmtNum(sec * 1e6, 2) + " мкс";
    if (sec < 1)    return fmtNum(sec * 1e3, 2) + " мс";
    return fmtNum(sec, 2) + " с";
}
static std::string fmtRate(double bytesPerOp, double secPerOp) {
    if (secPerOp <= 0) return "-";
    if (bytesPerOp > 0) {
        double mbps = bytesPerOp / secPerOp / 1e6;
        return fmtNum(mbps, mbps < 10 ? 2 : 1) + " МБ/с";
    }
    double ops = 1.0 / secPerOp;
    if (ops >= 1e6) return fmtNum(ops / 1e6, 2) + " млн оп/с";
    if (ops >= 1e3) return fmtNum(ops / 1e3, 1) + " тыс. оп/с";
    return fmtNum(ops, 2) + " оп/с";
}
static std::string fmtBytes(size_t b) {
    if (b >= (1u << 20) && b % (1u << 20) == 0) return std::to_string(b >> 20) + " МБ";
    if (b >= 1024 && b % 1024 == 0) return std::to_string(b >> 10) + " КБ";
    return std::to_string(b) + " Б";
}

struct BenchRow {
    std::string op, data;
    TimingStat t;
    double bytes;   // байт за операцию (0 — выводим операции в секунду)
};

static void printBenchTable(const std::string& title, const std::vector<BenchRow>& rows) {
    std::cout << "\n" << title << "\n";
    std::vector<std::vector<std::string>> cells;
    for (const auto& r : rows) {
        double cv = r.t.mean > 0 ? r.t.sd / r.t.mean * 100.0 : 0;
        cells.push_back({r.op, r.data, std::to_string(r.t.n), fmtTime(r.t.mean), fmtTime(r.t.median),
                         fmtTime(r.t.min), fmtTime(r.t.max), fmtNum(cv, 1) + "%", fmtRate(r.bytes, r.t.median)});
    }
    printAsciiTable({"Операция", "Данные", "N", "Среднее", "Медиана", "Мин", "Макс", "σ/ср.", "Скорость (по медиане)"},
                    cells, {Align::Left, Align::Right, Align::Right, Align::Right, Align::Right, Align::Right,
                            Align::Right, Align::Right, Align::Right});
}

static volatile uint8_t g_benchSink = 0;   // не даёт компилятору выбросить вычисления

static void benchStreebog() {
    std::string m64(64, 'a'), m1k(1024, 'b'), m1m(1u << 20, 'c');
    std::vector<BenchRow> rows;
    rows.push_back({"Стрибог-512", fmtBytes(64),
        measure([&] { g_benchSink ^= streebog512impl::streebog512(m64)[0]; }, 200, 20, 0.3, 1000), 64});
    rows.push_back({"Стрибог-512", fmtBytes(1024),
        measure([&] { g_benchSink ^= streebog512impl::streebog512(m1k)[0]; }, 20, 20, 0.3, 1000), 1024});
    rows.push_back({"Стрибог-512", fmtBytes(1u << 20),
        measure([&] { g_benchSink ^= streebog512impl::streebog512(m1m)[0]; }, 1, 5, 1.0, 30), double(1u << 20)});
    rows.push_back({"Стрибог-256", fmtBytes(64),
        measure([&] { g_benchSink ^= streebog512impl::streebog256(m64)[0]; }, 200, 20, 0.3, 1000), 64});
    rows.push_back({"Стрибог-256", fmtBytes(1u << 20),
        measure([&] { g_benchSink ^= streebog512impl::streebog256(m1m)[0]; }, 1, 5, 1.0, 30), double(1u << 20)});
    std::vector<uint8_t> hkey(32, 0x42);
    rows.push_back({"HMAC-Стрибог-512", fmtBytes(64),
        measure([&] { g_benchSink ^= hmacStreebog512(hkey, reinterpret_cast<const uint8_t*>(m64.data()), 64)[0]; },
                100, 20, 0.3, 1000), 64});
    std::vector<uint8_t> salt(16, 0x07);
    rows.push_back({"PBKDF2-HMAC-Стрибог-512", std::to_string(PBKDF2_ITERATIONS) + " итер.",
        measure([&] { g_benchSink ^= pbkdf2Streebog512("password", salt, PBKDF2_ITERATIONS, 64)[0]; }, 1, 3, 0, 3), 0});
    printBenchTable("Стрибог (ГОСТ Р 34.11-2012), таблица L: 8x256 слов", rows);
}

static void benchKuznyechik() {
    auto key = securerand::bytes(32);
    kuz::Cipher c(key.data());
    std::vector<uint8_t> blockIn(16, 0x5a), blockOut(16);
    std::vector<uint8_t> mb(1u << 20, 0x33), kb(1024, 0x44);
    uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint8_t> k64 = securerand::bytes(64);
    std::string kbStr(1024, 'x');
    std::vector<BenchRow> rows;
    rows.push_back({"Развёртка ключа", fmtBytes(32),
        measure([&] { kuz::Cipher t(key.data()); uint8_t o[16]; t.encryptBlock(blockIn.data(), o); g_benchSink ^= o[0]; },
                100, 20, 0.3, 1000), 0});
    rows.push_back({"Зашифрование блока", fmtBytes(16),
        measure([&] { c.encryptBlock(blockIn.data(), blockOut.data()); blockIn[0] ^= blockOut[0]; }, 100000, 20, 0.3, 1000), 16});
    rows.push_back({"Расшифрование блока (эталонное)", fmtBytes(16),
        measure([&] { c.decryptBlock(blockIn.data(), blockOut.data()); blockIn[0] ^= blockOut[0]; }, 1000, 20, 0.3, 1000), 16});
    rows.push_back({"CTR (гаммирование)", fmtBytes(1u << 20),
        measure([&] { g_benchSink ^= kuz::ctrXcrypt(c, iv, mb.data(), mb.size())[7]; }, 1, 10, 0.5, 200), double(1u << 20)});
    rows.push_back({"OMAC (имитовставка)", fmtBytes(1u << 20),
        measure([&] { g_benchSink ^= kuz::omac(c, mb.data(), mb.size())[0]; }, 1, 10, 0.5, 200), double(1u << 20)});
    rows.push_back({"CTR + OMAC (сообщение)", fmtBytes(1024),
        measure([&] { g_benchSink ^= kuzSeal(k64, kbStr).mac[0]; }, 50, 20, 0.3, 1000), 1024});
    printBenchTable("Кузнечик (ГОСТ Р 34.12-2015 / 34.13-2015), таблицы LS: 16x256x128 бит = 64 КБ", rows);
}

// ---- статистика генерации ключа RSA (хранится в keys.txt) ----
static std::string serializeKeygenStats(const rsa::KeygenStats& ks) {
    std::ostringstream os;
    os << ks.threads << '|' << ks.sievePrimes << '|' << ks.restarts << '|' << fmtNum(ks.seconds, 3);
    for (const auto& p : ks.primes)
        os << '|' << p.bits << ',' << p.windows << ',' << p.sieveCandidates << ',' << p.sieveSurvivors << ','
           << p.fermatTests << ',' << p.strongTests << ',' << fmtNum(p.sieveSeconds, 3) << ',' << fmtNum(p.seconds, 3) << ',' << p.pseudoprimes;
    return os.str();
}

static bool parseKeygenStats(const std::string& s, rsa::KeygenStats& ks) {
    auto parts = splitByDelimiter(s, '|');
    if (parts.size() < 5) return false;
    try {
        ks.threads = static_cast<unsigned>(std::stoul(parts[0]));
        ks.sievePrimes = std::stoull(parts[1]);
        ks.restarts = std::stoull(parts[2]);
        ks.seconds = std::stod(parts[3]);
        ks.primes.clear();
        for (size_t i = 4; i < parts.size(); i++) {
            auto f = splitByDelimiter(parts[i], ',');
            if (f.size() != 8 && f.size() != 9) return false;
            rsa::PrimeStats p;
            p.bits = std::stoull(f[0]); p.windows = std::stoull(f[1]); p.sieveCandidates = std::stoull(f[2]);
            p.sieveSurvivors = std::stoull(f[3]); p.fermatTests = std::stoull(f[4]); p.strongTests = std::stoull(f[5]);
            p.sieveSeconds = std::stod(f[6]); p.seconds = std::stod(f[7]);
            p.pseudoprimes = f.size() == 9 ? std::stoull(f[8]) : 0;
            if (f.size() == 8) ks.pseudoKnown = false;
            ks.primes.push_back(p);
        }
    } catch (...) { return false; }
    return true;
}

static std::vector<std::string> keygenStatsTable(const rsa::KeygenStats& ks) {
    std::vector<std::vector<std::string>> rows;
    size_t totFermat = 0, totStrong = 0, totSurv = 0, totCand = 0;
    for (size_t i = 0; i < ks.primes.size(); i++) {
        const auto& p = ks.primes[i];
        double sieved = p.sieveCandidates ? 100.0 * (1.0 - double(p.sieveSurvivors) / p.sieveCandidates) : 0;
        rows.push_back({std::to_string(i + 1), std::to_string(p.bits), std::to_string(p.windows),
                        std::to_string(p.sieveSurvivors) + " / " + std::to_string(p.sieveCandidates),
                        fmtNum(sieved, 1) + "%", std::to_string(p.fermatTests), std::to_string(p.strongTests),
                        fmtTime(p.sieveSeconds), fmtTime(p.seconds),
                        p.fermatTests ? fmtTime(p.seconds / p.fermatTests) : "-"});
        totFermat += p.fermatTests; totStrong += p.strongTests; totSurv += p.sieveSurvivors; totCand += p.sieveCandidates;
    }
    rows.push_back({"---"});
    rows.push_back({"Итого", "", "", std::to_string(totSurv) + " / " + std::to_string(totCand), "",
                    std::to_string(totFermat), std::to_string(totStrong), "", fmtTime(ks.seconds), ""});
    return asciiTable({"Простое", "Бит", "Окон", "Прошли решето", "Отсеяно", "Тестов Ферма", "BPSW+MR",
                       "Решето", "Время", "На тест"}, rows,
                      {Align::Right, Align::Right, Align::Right, Align::Right, Align::Right, Align::Right,
                       Align::Right, Align::Right, Align::Right, Align::Right});
}

static void printKeygenStats(const rsa::KeygenStats& ks) {
    std::cout << "\nГенерация ключа RSA-" << RSA_MODULUS_BITS << ": статистика поиска простых\n";
    for (const auto& l : keygenStatsTable(ks)) std::cout << l << "\n";
    size_t totFermat = 0, totStrong = 0, totPseudo = 0;
    for (const auto& p : ks.primes) { totFermat += p.fermatTests; totStrong += p.strongTests; totPseudo += p.pseudoprimes; }
    // Сколько кандидатов прошли строгую проверку, но не понадобились: при
    // параллельном поиске два потока иногда находят простое почти одновременно.
    size_t extra = totStrong - totPseudo > ks.primes.size() ? totStrong - totPseudo - ks.primes.size() : 0;
    std::cout << "Потоков: " << ks.threads << "; малых простых в решете: " << ks.sievePrimes
              << "; перезапусков генерации: " << ks.restarts << ".\n"
              << "Тест Ферма отсеял " << (totFermat - totStrong) << " составных из " << totFermat
              << "; до строгой проверки BPSW + Миллер–Рабин дошли " << totStrong << " кандидат(ов) на "
              << ks.primes.size() << " простых";
    if (!ks.pseudoKnown && totStrong > ks.primes.size()) {
        std::cout << " (лишние — псевдопростые по Ферма или простые, найденные потоками одновременно;\n"
                  << "ключ создан старой версией, которая их не различала)";
    } else if (totPseudo || extra) {
        std::cout << " (";
        if (totPseudo) std::cout << "псевдопростых по Ферма, отсеянных строгой проверкой: " << totPseudo;
        if (totPseudo && extra) std::cout << "; ";
        if (extra) std::cout << "лишних простых, найденных параллельными потоками одновременно: " << extra;
        std::cout << ")";
    }
    std::cout << ".\n";
}

static void benchRsa(const rsa::PrivateKey& sk) {
    const size_t k = (sk.n.bits() + 7) / 8;
    const size_t u = sk.primes.size();
    rsa::PublicKey pub = sk.pub();
    std::vector<uint8_t> mb = securerand::bytes(rsa::oaepMaxMessage(k, STREEBOG_LEN));
    auto ct = rsa::oaepEncryptBlock(pub, streebogHashFn(), STREEBOG_LEN, cspRandomFn(), mb.data(), mb.size());
    rsa::Mpz c, m, mRaw;
    rsa::os2ip(c, ct.data(), ct.size());
    rsa::Mpz rnd;
    { auto rb = securerand::bytes(k - 1); rsa::os2ip(rnd, rb.data(), rb.size()); }
    std::vector<uint8_t> dec;

    std::cout << "\nRSA: замер операций (каждая операция RSADP занимает доли секунды — подождите)...\n";
    std::vector<BenchRow> rows;
    rows.push_back({"RSAEP: c = m^e mod n (e = 65537)", fmtBytes(k),
        measure([&] { rsa::rsaep(m, pub, rnd); g_benchSink ^= static_cast<uint8_t>(mpz_fdiv_ui(m, 251)); }, 10, 5, 0.5, 100), 0});
    rows.push_back({"OAEP-шифрование блока", fmtBytes(mb.size()),
        measure([&] { g_benchSink ^= rsa::oaepEncryptBlock(pub, streebogHashFn(), STREEBOG_LEN, cspRandomFn(),
                                                             mb.data(), mb.size())[5]; }, 1, 5, 0.5, 100), 0});
    TimingStat par = measure([&] { rsa::rsadp(m, sk, c, true); }, 1, 3, 1.0, 10);
    rows.push_back({"RSADP: CRT, потоков: " + std::to_string(u), fmtBytes(k), par, 0});
    TimingStat seq = measure([&] { rsa::rsadp(m, sk, c, false); }, 1, 3, 0, 3);
    rows.push_back({"RSADP: CRT, потоков: 1", fmtBytes(k), seq, 0});
    TimingStat noCrt = measure([&] { mpz_powm(mRaw, c, sk.d, sk.n); }, 1, 1, 0, 1, false);
    rows.push_back({"RSADP без CRT: c^d mod n", fmtBytes(k), noCrt, 0});
    rows.push_back({"OAEP-расшифрование блока", fmtBytes(mb.size()),
        measure([&] { rsa::oaepDecryptBlock(sk, streebogHashFn(), STREEBOG_LEN, ct, dec); }, 1, 3, 1.0, 10), 0});
    printBenchTable("RSA-" + std::to_string(sk.n.bits()) + " (" + std::to_string(u) +
                    " простых по " + std::to_string(sk.primes[0].bits()) + " бит, OAEP + Стрибог-512)", rows);

    bool same = mpz_cmp(m, mRaw) == 0;
    std::cout << "Проверка: результаты CRT и прямого c^d mod n " << (same ? "совпадают" : "НЕ СОВПАДАЮТ") << ".\n"
              << "Ускорение CRT относительно c^d mod n: x" << fmtNum(noCrt.median / par.median, 1)
              << " (из них за счёт параллельности: x" << fmtNum(seq.median / par.median, 2) << ").\n"
              << "Расшифрование дороже шифрования в x" << fmtNum(par.median / rows[0].t.median, 0)
              << " раз: показатель d длинный, e = 65537 — 17 бит.\n";
}

static void printSystemInfo() {
    std::vector<std::vector<std::string>> rows = {
        {"Потоков процессора", std::to_string(rsa::threadCount())},
        {"Версия GMP", gmp_version},
#if defined(__clang__)
        {"Компилятор", std::string("clang ") + __clang_version__},
#elif defined(__GNUC__)
        {"Компилятор", std::string("gcc ") + __VERSION__},
#endif
        {"Размер модуля RSA / число простых", std::to_string(RSA_MODULUS_BITS) + " бит / " + std::to_string(RSA_PRIMES)},
        {"Итераций PBKDF2", std::to_string(PBKDF2_ITERATIONS)},
    };
    std::cout << "\n";
    printAsciiTable({"Параметр", "Значение"}, rows);
}

// Полный замер из командной строки (./auth3fa --bench): Стрибог, Кузнечик
// и RSA-32768 с генерацией нового ключа и статистикой поиска простых.
static int runCommandLineBench() {
    std::cout << "=== Производительность: Стрибог, Кузнечик, RSA-" << RSA_MODULUS_BITS << " ===\n";
    printSystemInfo();
    benchStreebog();
    benchKuznyechik();
    std::cout << "\nГенерация ключа RSA-" << RSA_MODULUS_BITS << " для замера...\n";
    rsa::KeygenStats ks;
    auto t0 = BenchClock::now();
    rsa::PrivateKey sk = rsa::generateKey(RSA_MODULUS_BITS, RSA_PRIMES, cspRandomFn(), [&](const std::string& msg) {
        bool interim = msg.size() >= 3 && msg.compare(msg.size() - 3, 3, "...") == 0;
        std::cout << "\r  [" << static_cast<long>(secondsSince(t0)) << " с] " << msg << "          "
                  << (interim ? "" : "\n") << std::flush;
    }, &ks);
    printKeygenStats(ks);
    benchRsa(sk);
    return 0;
}

// ============================================================
// Сессия авторизованного пользователя:
// шифрование сообщений (Кузнечик / RSA-32768) и PDF-отчёт
// ============================================================
struct UserSession {
    std::string username;
    std::vector<uint8_t> kek;      // 64 байта, выведены из пароля (PBKDF2)
    std::vector<uint8_t> msgKey;   // 64 байта, ключ «Кузнечика» для сообщений
    std::map<std::string, std::string> keys;
    bool rsaLoaded = false;
    rsa::PrivateKey rsaKey;
    gost3410::KeyPair sigKey;      // ключ ЭЦП ГОСТ Р 34.10-2012
    asn1::Bytes sigCert;           // самоподписанный сертификат X.509 с этим ключом
    ~UserSession() { secureWipe(kek); secureWipe(msgKey); sigKey.d.wipe(); }
};

static std::string formatTime(uint64_t t) {
    std::time_t tt = static_cast<std::time_t>(t);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    char buf[64];
    std::strftime(buf, sizeof buf, "%d.%m.%Y %H:%M:%S", &tm);
    return buf;
}

static std::string algoTitle(const std::string& algo) {
    if (algo == "KUZ") return "Кузнечик (ГОСТ Р 34.12-2015), режим CTR + имитовставка OMAC";
    if (algo == "RSA") return "RSA-32768, дополнение OAEP со Стрибогом-512";
    return algo;
}
static std::string algoShort(const std::string& algo) {
    if (algo == "KUZ") return "Кузнечик";
    if (algo == "RSA") return "RSA-32768";
    return algo;
}

// Отпечаток открытого ключа: первые 20 байт Стрибога-512 от модуля n
static std::string rsaFingerprint(const rsa::Mpz& n) {
    auto bytes = rsa::i2osp(n, (n.bits() + 7) / 8);
    auto h = streebog512Bytes(bytes.data(), bytes.size());
    std::string hex = toHex(std::vector<uint8_t>(h.begin(), h.begin() + 20)), out;
    for (size_t i = 0; i < hex.size(); i += 4) { if (i) out += ' '; out += hex.substr(i, 4); }
    return out;
}

// ------------------------------------------------------------
// Ключ электронной подписи ГОСТ Р 34.10-2012 и сертификат
// ------------------------------------------------------------
static pdfsig::HashFn streebog256HashFn() {
    return [](const uint8_t* d, size_t n) { return streebog256Bytes(d, n); };
}

static std::string certFingerprint(const asn1::Bytes& der) {
    auto h = streebog256Bytes(der.data(), der.size());
    std::string hex = toHex(std::vector<uint8_t>(h.begin(), h.begin() + 16)), out;
    for (size_t i = 0; i < hex.size(); i += 4) { if (i) out += ' '; out += hex.substr(i, 4); }
    return out;
}

// Загружает ключ подписи из хранилища, при первом входе — создаёт ключ и
// самоподписанный сертификат. Закрытый ключ хранится запечатанным на KEK.
static bool ensureSigningKey(UserSession& s, std::string& err) {
    const auto& curve = gost3410::workCurve();
    if (!s.keys.count("sig_priv")) {
        gost3410::KeyPair kp = gost3410::generateKey(curve, cspRandomFn());
        pdfsig::CertInfo info;
        info.commonName = s.username;
        info.notBefore = static_cast<time_t>(nowUnixTime());
        info.notAfter = info.notBefore + 5LL * 365 * 24 * 3600;
        asn1::Bytes cert = pdfsig::buildSelfSignedCert(curve, kp, info, streebog256HashFn(), cspRandomFn());
        std::string dHex = kp.d.toHex();
        s.keys["sig_priv"] = sealedToString(kuzSeal(s.kek, dHex));
        s.keys["sig_pub"] = toHex(gost3410::encodePublicKey(kp.Q));
        s.keys["sig_cert"] = toHex(cert);
        s.keys["sig_created"] = std::to_string(nowUnixTime());
        secureWipe(dHex);
        if (!saveKeyValueFile(vaultKeysFile(s.username), s.keys)) { err = "не удалось сохранить ключ подписи"; return false; }
        std::cout << "Создан ключ электронной подписи ГОСТ Р 34.10-2012 и сертификат.\n";
    }
    SealedData sealed;
    std::string dHex;
    if (!sealedFromString(s.keys["sig_priv"], sealed) || !kuzOpen(s.kek, sealed, dHex)) {
        err = "закрытый ключ подписи повреждён (имитовставка не сошлась)"; return false;
    }
    bool ok = s.sigKey.d.fromHex(dHex);
    secureWipe(dHex);
    if (!ok) { err = "закрытый ключ подписи повреждён"; return false; }
    s.sigKey.Q = gost3410::publicFromPrivate(curve, s.sigKey.d);
    if (toHex(gost3410::encodePublicKey(s.sigKey.Q)) != s.keys["sig_pub"]) { err = "ключ подписи не совпадает с открытым"; return false; }
    if (!hexDecode(s.keys["sig_cert"], s.sigCert)) { err = "сертификат повреждён"; return false; }
    return true;
}

// Печать результата проверки подписи PDF (ASCII-таблица)
static void printVerifyReport(const pdfsig::VerifyReport& r, const UserSession* s) {
    auto yn = [](bool b) { return std::string(b ? "OK" : "ОШИБКА"); };
    if (!r.found) { std::cout << "Результат: " << r.error << ".\n"; return; }
    std::vector<std::vector<std::string>> rows = {
        {"Подписант (CN сертификата)", r.subjectCN.empty() ? "-" : r.subjectCN},
        {"Организация", r.organization.empty() ? "-" : r.organization},
        {"Время подписи", r.signingTime.empty() ? "-" : r.signingTime},
        {"Сертификат действителен", r.notBefore + " - " + r.notAfter},
        {"Отпечаток сертификата (Стрибог-256)", r.certDer.empty() ? "-" : certFingerprint(r.certDer)},
        {"Алгоритм подписи", "ГОСТ Р 34.10-2012, 256 бит (OID " + std::string(pdfsig::OID_GOST_KEY_256) + ")"},
        {"Хеш-функция", "ГОСТ Р 34.11-2012 Стрибог-256 (OID " + r.digestAlgOid + ")"},
        {"Параметры кривой", r.curveOid},
        {"Размер файла / подписано байт", std::to_string(r.fileSize) + " / " + std::to_string(r.signedBytes)},
        {"/ByteRange", "[" + std::to_string(r.range[0]) + " " + std::to_string(r.range[1]) + " " +
                       std::to_string(r.range[2]) + " " + std::to_string(r.range[3]) + "]"},
        {"Размер CMS", std::to_string(r.cmsSize) + " Б"},
        {"---"},
        {"Подпись охватывает весь файл", yn(r.coversWholeFile)},
        {"Хеш документа совпал с messageDigest", yn(r.digestOk)},
        {"Подпись ГОСТ Р 34.10-2012 верна", yn(r.signatureOk)},
        {"Самоподпись сертификата верна", yn(r.certSelfSigOk)},
    };
    if (s) {
        bool mine = !s->sigCert.empty() && r.certDer == s->sigCert;
        rows.push_back({"Подписано ключом пользователя " + s->username, mine ? "да" : "нет"});
    }
    printAsciiTable({"Параметр", "Значение"}, rows);
    if (!r.digestOk && r.parsed)
        std::cout << "  хеш в подписи:   " << toHex(r.messageDigest) << "\n  хеш документа:   " << toHex(r.computedDigest) << "\n";
    if (!r.error.empty()) std::cout << "Ошибка разбора: " << r.error << "\n";
    std::cout << "Результат: " << (r.valid() ? "ПОДПИСЬ ВЕРНА, документ не изменялся после подписания."
                                             : "ПОДПИСЬ НЕДЕЙСТВИТЕЛЬНА — документ изменён или подпись повреждена.") << "\n";
}

// Открывает (или при первом использовании создаёт) хранилище пользователя
static bool unlockVault(const std::string& username, const std::string& password,
                        UserSession& s, std::string& err) {
    std::error_code ec;
    std::filesystem::create_directories(vaultDirFor(username), ec);
    if (ec) { err = "не удалось создать каталог " + vaultDirFor(username); return false; }
    restrictToOwner(VAULT_DIR, true);
    restrictToOwner(vaultDirFor(username), true);

    s.username = username;
    std::string keysPath = vaultKeysFile(username);

    if (!vaultExists(username)) {
        std::vector<uint8_t> salt = securerand::bytes(16);
        s.kek = pbkdf2Streebog512(password, salt, PBKDF2_ITERATIONS, 64);
        s.msgKey = securerand::bytes(64);
        std::string mk(s.msgKey.begin(), s.msgKey.end());
        s.keys["kdf_salt"] = toHex(salt);
        s.keys["kdf_iter"] = std::to_string(PBKDF2_ITERATIONS);
        s.keys["msg_key"] = sealedToString(kuzSeal(s.kek, mk));
        s.keys["created"] = std::to_string(nowUnixTime());
        secureWipe(mk);
        if (!saveKeyValueFile(keysPath, s.keys)) { err = "не удалось записать " + keysPath; return false; }
        return true;
    }

    s.keys = loadKeyValueFile(keysPath);
    std::vector<uint8_t> salt;
    uint32_t iter = 0;
    try { iter = static_cast<uint32_t>(std::stoul(s.keys["kdf_iter"])); } catch (...) { iter = 0; }
    SealedData sealed;
    if (!hexDecode(s.keys["kdf_salt"], salt) || iter == 0 || !sealedFromString(s.keys["msg_key"], sealed)) {
        err = "файл ключей повреждён";
        return false;
    }
    s.kek = pbkdf2Streebog512(password, salt, iter, 64);
    std::string mk;
    if (!kuzOpen(s.kek, sealed, mk) || mk.size() != 64) {
        err = "ключ, выведенный из пароля, не подходит (имитовставка не сошлась) — хранилище повреждено или подменено";
        return false;
    }
    s.msgKey.assign(mk.begin(), mk.end());
    secureWipe(mk);
    return true;
}

static bool loadRsaKey(UserSession& s, std::string& err) {
    if (s.rsaLoaded) return true;
    if (!s.keys.count("rsa_priv")) { err = "ключ RSA ещё не создан"; return false; }
    rsa::Mpz n, e;
    SealedData sealed;
    if (!n.fromHex(s.keys["rsa_n"]) || !e.fromHex(s.keys["rsa_e"]) || !sealedFromString(s.keys["rsa_priv"], sealed)) {
        err = "запись ключа RSA повреждена"; return false;
    }
    std::string secret;
    if (!kuzOpen(s.kek, sealed, secret)) { err = "имитовставка закрытого ключа RSA не сошлась"; return false; }
    bool ok = s.rsaKey.deserializeSecret(secret, n, e);
    secureWipe(secret);
    if (!ok) { err = "закрытый ключ RSA не соответствует открытому"; return false; }
    s.rsaLoaded = true;
    return true;
}

// Генерирует ключ RSA-32768 при первом использовании (один раз на пользователя)
static bool ensureRsaKey(UserSession& s) {
    std::string err;
    if (s.keys.count("rsa_priv")) {
        if (loadRsaKey(s, err)) return true;
        std::cout << "Ошибка: " << err << ".\n";
        return false;
    }
    std::cout << "\nУ вас ещё нет ключа RSA-32768. Он создаётся один раз и дальше хранится\n"
              << "в зашифрованном виде. Нужно найти " << RSA_PRIMES << " случайных простых числа по "
              << RSA_MODULUS_BITS / RSA_PRIMES << " бит;\n"
              << "поиск идёт параллельно на всех ядрах процессора (" << rsa::threadCount() << " шт.)\n"
              << "и обычно занимает от полуминуты до нескольких минут.\n"
              << "Сгенерировать ключ сейчас? (д/н): ";
    std::string ans;
    std::getline(std::cin, ans);
    if (ans != "д" && ans != "Д" && ans != "y" && ans != "Y") { std::cout << "Отменено.\n"; return false; }

    auto t0 = std::chrono::steady_clock::now();
    // Промежуточный прогресс (оканчивается на "...") перерисовывает одну и ту же
    // строку через '\r', итоговые сообщения печатаются отдельными строками.
    rsa::KeygenStats ks;
    rsa::PrivateKey key = rsa::generateKey(RSA_MODULUS_BITS, RSA_PRIMES, cspRandomFn(), [&](const std::string& msg) {
        long el = static_cast<long>(std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
        bool interim = msg.size() >= 3 && msg.compare(msg.size() - 3, 3, "...") == 0;
        std::cout << "\r  [" << el << " с] " << msg << "          " << (interim ? "" : "\n") << std::flush;
    }, &ks);
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    std::string secret = key.serializeSecret();
    s.keys["rsa_n"] = key.n.toHex();
    s.keys["rsa_e"] = key.e.toHex();
    s.keys["rsa_priv"] = sealedToString(kuzSeal(s.kek, secret));
    s.keys["rsa_primes"] = std::to_string(key.primes.size());
    s.keys["rsa_created"] = std::to_string(nowUnixTime());
    s.keys["rsa_gen_seconds"] = std::to_string(static_cast<long>(secs + 0.5));
    s.keys["rsa_gen_stats"] = serializeKeygenStats(ks);
    secureWipe(secret);
    if (!saveKeyValueFile(vaultKeysFile(s.username), s.keys)) {
        std::cout << "Ошибка: не удалось сохранить ключ.\n";
        return false;
    }
    s.rsaKey = key;
    s.rsaLoaded = true;
    std::cout << "Ключ RSA-" << key.n.bits() << " создан за " << static_cast<long>(secs + 0.5) << " с.\n"
              << "Отпечаток открытого ключа: " << rsaFingerprint(key.n) << "\n";
    printKeygenStats(ks);
    return true;
}

static std::string readMultilineMessage() {
    std::cout << "Введите сообщение (можно в несколько строк; пустая строка — конец ввода):\n";
    std::string msg, line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) break;
        if (!msg.empty()) msg += '\n';
        msg += line;
    }
    return msg;
}

static void encryptNewMessage(UserSession& s) {
    std::cout << "\nВыберите алгоритм шифрования:\n"
              << "1. Кузнечик (ГОСТ Р 34.12-2015), 256-битный ключ\n"
              << "2. RSA-32768 (OAEP)\n"
              << "Выбор: ";
    std::string choice;
    std::getline(std::cin, choice);
    std::string algo;
    if (choice == "1") algo = "KUZ";
    else if (choice == "2") algo = "RSA";
    else { std::cout << "Некорректный выбор.\n"; return; }

    if (algo == "RSA" && !ensureRsaKey(s)) return;

    std::string msg = readMultilineMessage();
    if (msg.empty()) { std::cout << "Пустое сообщение — отменено.\n"; return; }

    auto t0 = std::chrono::steady_clock::now();
    StoredMessage m;
    m.algo = algo;
    m.created = nowUnixTime();
    size_t ctBytes = 0;
    std::string preview;
    if (algo == "KUZ") {
        SealedData sd = kuzSeal(s.msgKey, msg);
        m.payload = sealedToString(sd);
        ctBytes = sd.ct.size();
        preview = toHex(sd.ct);
    } else {
        auto blocks = rsa::encryptMessage(s.rsaKey.pub(), streebogHashFn(), STREEBOG_LEN, cspRandomFn(), msg);
        for (size_t i = 0; i < blocks.size(); i++) {
            if (i) m.payload += ':';
            m.payload += toHex(blocks[i]);
            ctBytes += blocks[i].size();
        }
        preview = toHex(blocks[0]);
    }
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    m.encSec = ms / 1000.0;

    auto msgs = loadMessages(s.username);
    uint64_t maxId = 0;
    for (const auto& x : msgs) maxId = std::max(maxId, x.id);
    m.id = maxId + 1;
    size_t ptBytes = msg.size();
    secureWipe(msg);

    if (!appendMessage(s.username, m)) { std::cout << "Ошибка: не удалось сохранить сообщение.\n"; return; }
    std::cout << "\nСообщение №" << m.id << " зашифровано: " << algoTitle(algo) << ".\n"
              << "Открытый текст: " << ptBytes << " байт, шифртекст: " << ctBytes << " байт, время: "
              << std::fixed << std::setprecision(1) << ms << " мс.\n";
    std::cout.unsetf(std::ios::fixed);
    std::cout << "Начало шифртекста: " << preview.substr(0, 64) << (preview.size() > 64 ? "..." : "") << "\n";
}

// Расшифровывает сохранённое сообщение. status — результат проверки целостности.
static bool decryptStored(UserSession& s, const StoredMessage& m, std::string& text, std::string& status) {
    text.clear();
    if (m.algo == "KUZ") {
        SealedData sd;
        if (!sealedFromString(m.payload, sd)) { status = "ОШИБКА: запись повреждена"; return false; }
        if (!kuzOpen(s.msgKey, sd, text)) { status = "ОШИБКА: имитовставка не совпала (данные изменены)"; return false; }
        status = "имитовставка OMAC верна, целостность подтверждена";
        return true;
    }
    if (m.algo == "RSA") {
        std::string err;
        if (!loadRsaKey(s, err)) { status = "ОШИБКА: " + err; return false; }
        std::vector<std::vector<uint8_t>> blocks;
        for (const auto& part : splitByDelimiter(m.payload, ':')) {
            std::vector<uint8_t> b;
            if (!hexDecode(part, b)) { status = "ОШИБКА: запись повреждена"; return false; }
            blocks.push_back(std::move(b));
        }
        if (!rsa::decryptMessage(s.rsaKey, streebogHashFn(), STREEBOG_LEN, blocks, text)) {
            status = "ОШИБКА: проверка OAEP не пройдена (данные изменены)"; return false;
        }
        status = "проверка OAEP пройдена, CRT-результат перепроверен";
        return true;
    }
    status = "ОШИБКА: неизвестный алгоритм " + m.algo;
    return false;
}

static size_t ciphertextBytes(const StoredMessage& m) {
    if (m.algo == "KUZ") { SealedData sd; return sealedFromString(m.payload, sd) ? sd.ct.size() : 0; }
    size_t hexChars = 0;
    for (const auto& p : splitByDelimiter(m.payload, ':')) hexChars += p.size();
    return hexChars / 2;
}

static void listMessages(UserSession& s) {
    auto msgs = loadMessages(s.username);
    if (msgs.empty()) { std::cout << "У вас пока нет зашифрованных сообщений.\n"; return; }
    std::vector<std::vector<std::string>> rows;
    for (const auto& m : msgs) {
        rows.push_back({std::to_string(m.id), formatTime(m.created), algoShort(m.algo),
                        std::to_string(ciphertextBytes(m))});
    }
    std::cout << "\n";
    printAsciiTable({"№", "Дата", "Алгоритм", "Шифртекст, Б"}, rows,
                    {Align::Right, Align::Left, Align::Left, Align::Right});
}

// ------------------------------------------------------------
// Анализ всех сообщений: расшифровка, размеры, время, целостность.
// Используется и для статистики в меню, и для PDF-отчёта.
// ------------------------------------------------------------
struct MessageReport {
    StoredMessage m;
    size_t ptBytes = 0, ctBytes = 0;
    double decryptSec = 0;
    bool ok = false;
    std::string status, text;
};

static std::vector<MessageReport> analyzeMessages(UserSession& s, const std::vector<StoredMessage>& msgs) {
    std::vector<MessageReport> res;
    size_t idx = 0;
    for (const auto& m : msgs) {
        idx++;
        std::cout << "\r  Расшифровка сообщений: " << idx << "/" << msgs.size() << std::flush;
        MessageReport r;
        r.m = m;
        r.ctBytes = ciphertextBytes(m);
        auto t0 = BenchClock::now();
        r.ok = decryptStored(s, m, r.text, r.status);
        r.decryptSec = secondsSince(t0);
        r.ptBytes = r.text.size();
        res.push_back(std::move(r));
    }
    if (!msgs.empty()) std::cout << "\n";
    return res;
}

// Сводка по алгоритмам: строки ASCII-таблицы
static std::vector<std::string> messageStatsTable(const std::vector<MessageReport>& reps) {
    struct Agg { size_t n = 0, pt = 0, ct = 0, ok = 0, encN = 0; double dec = 0, enc = 0; };
    std::map<std::string, Agg> by;
    Agg total;
    for (const auto& r : reps) {
        for (Agg* a : {&by[r.m.algo], &total}) {
            a->n++; a->pt += r.ptBytes; a->ct += r.ctBytes; a->ok += r.ok; a->dec += r.decryptSec;
            if (r.m.encSec >= 0) { a->encN++; a->enc += r.m.encSec; }
        }
    }
    auto row = [](const std::string& name, const Agg& a) {
        return std::vector<std::string>{
            name, std::to_string(a.n), std::to_string(a.pt), std::to_string(a.ct),
            a.pt ? "x" + fmtNum(double(a.ct) / a.pt, 2) : "-",
            a.encN ? fmtTime(a.enc / a.encN) : "-",
            a.n ? fmtTime(a.dec / a.n) : "-",
            std::to_string(a.ok) + "/" + std::to_string(a.n)};
    };
    std::vector<std::vector<std::string>> rows;
    for (const auto& kv : by) rows.push_back(row(algoShort(kv.first), kv.second));
    rows.push_back({"---"});
    rows.push_back(row("Всего", total));
    return asciiTable({"Алгоритм", "Сообщений", "Открытый текст, Б", "Шифртекст, Б", "Расширение",
                       "Ср. шифрование", "Ср. расшифровка", "Целостность"}, rows,
                      {Align::Left, Align::Right, Align::Right, Align::Right, Align::Right, Align::Right,
                       Align::Right, Align::Right});
}

// Таблица по каждому сообщению
static std::vector<std::string> messageListTable(const std::vector<MessageReport>& reps) {
    std::vector<std::vector<std::string>> rows;
    for (const auto& r : reps) {
        rows.push_back({std::to_string(r.m.id), formatTime(r.m.created), algoShort(r.m.algo),
                        std::to_string(r.ptBytes), std::to_string(r.ctBytes),
                        r.m.encSec >= 0 ? fmtTime(r.m.encSec) : "-", fmtTime(r.decryptSec),
                        r.ok ? "OK" : "ОШИБКА"});
    }
    return asciiTable({"№", "Дата", "Алгоритм", "Текст, Б", "Шифртекст, Б", "Шифрование", "Расшифровка",
                       "Целостность"}, rows,
                      {Align::Right, Align::Left, Align::Left, Align::Right, Align::Right, Align::Right,
                       Align::Right, Align::Left});
}

// Пункт меню «Статистика и производительность»
static void showStatsAndPerformance(UserSession& s) {
    auto msgs = loadMessages(s.username);
    if (msgs.empty()) {
        std::cout << "\nСообщений пока нет — статистика по ним пуста.\n";
    } else {
        std::cout << "\nСтатистика сообщений пользователя " << s.username << ":\n";
        auto reps = analyzeMessages(s, msgs);
        for (const auto& l : messageListTable(reps)) std::cout << l << "\n";
        for (const auto& l : messageStatsTable(reps)) std::cout << l << "\n";
        for (auto& r : reps) secureWipe(r.text);
    }

    rsa::KeygenStats ks;
    if (s.keys.count("rsa_gen_stats") && parseKeygenStats(s.keys["rsa_gen_stats"], ks)) printKeygenStats(ks);

    std::cout << "\nЗапустить замеры производительности Стрибога, Кузнечика и RSA? Займёт до минуты (д/н): ";
    std::string ans;
    std::getline(std::cin, ans);
    if (ans != "д" && ans != "Д" && ans != "y" && ans != "Y") return;
    printSystemInfo();
    benchStreebog();
    benchKuznyechik();
    std::string err;
    if (s.keys.count("rsa_priv") && loadRsaKey(s, err)) benchRsa(s.rsaKey);
    else std::cout << "\nRSA: ключ ещё не создан — зашифруйте сообщение через RSA, чтобы он появился,\n"
                   << "или запустите ./auth3fa --bench (сгенерирует отдельный ключ для замера).\n";
}

// Пункт меню «Проверка по контрольным примерам ГОСТ»
static void showGostSelfTest() {
    std::cout << "\nКонтрольные примеры ГОСТ Р 34.11-2012, 34.12-2015, 34.13-2015, Р 50.1.113-2016:\n";
    auto kats = gostKats();
    printKatDetails(kats);
    std::cout << "\nСводка:\n";
    printKatTable(kats);
}

static void showDecrypted(UserSession& s) {
    auto msgs = loadMessages(s.username);
    if (msgs.empty()) { std::cout << "У вас пока нет зашифрованных сообщений.\n"; return; }
    std::cout << "Номер сообщения: ";
    std::string in;
    std::getline(std::cin, in);
    auto it = std::find_if(msgs.begin(), msgs.end(), [&](const StoredMessage& m) { return std::to_string(m.id) == in; });
    if (it == msgs.end()) { std::cout << "Сообщение не найдено.\n"; return; }
    auto t0 = std::chrono::steady_clock::now();
    std::string text, status;
    bool ok = decryptStored(s, *it, text, status);
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    std::cout << "\nСообщение №" << it->id << " (" << algoTitle(it->algo) << ", " << formatTime(it->created) << ")\n"
              << "Статус: " << status << "; расшифровано за " << std::fixed << std::setprecision(1) << ms << " мс\n";
    std::cout.unsetf(std::ios::fixed);
    if (ok) std::cout << "----- текст -----\n" << text << "\n-----------------\n";
    secureWipe(text);
}

// Поиск TrueType-шрифта с кириллицей. Можно задать свой через переменную
// окружения PDF_FONT / PDF_FONT_MONO или положить font.ttf рядом с программой.
static std::string findFontPath(bool mono) {
    const char* env = std::getenv(mono ? "PDF_FONT_MONO" : "PDF_FONT");
    std::vector<std::string> candidates;
    if (env && *env) candidates.push_back(env);
    if (mono) {
        candidates.insert(candidates.end(), {
            "font_mono.ttf",
            "/System/Library/Fonts/Supplemental/Courier New.ttf",
            "/Library/Fonts/Courier New.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
            "C:\\Windows\\Fonts\\cour.ttf",
        });
    } else {
        candidates.insert(candidates.end(), {
            "font.ttf",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/Library/Fonts/Arial.ttf",
            "/System/Library/Fonts/Supplemental/Verdana.ttf",
            "/System/Library/Fonts/Supplemental/Times New Roman.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "C:\\Windows\\Fonts\\arial.ttf",
        });
    }
    for (const auto& c : candidates) {
        std::error_code ec;
        if (std::filesystem::exists(c, ec)) return c;
    }
    return "";
}

static std::string sanitizeForFilename(const std::string& s) {
    std::string out;
    for (unsigned char c : s) out += (std::isalnum(c) || c == '-' || c == '_') ? static_cast<char>(c) : '_';
    return out.empty() ? "user" : out;
}

// Итоги проверки по ГОСТ, сгруппированные по алгоритму (для PDF)
static std::vector<std::string> gostSummaryTable() {
    auto kats = gostKats();
    std::vector<std::string> order;
    std::map<std::string, std::pair<size_t, size_t>> agg;   // алгоритм -> (пройдено, всего)
    std::map<std::string, std::string> src;
    for (const auto& k : kats) {
        if (!agg.count(k.algo)) order.push_back(k.algo);
        agg[k.algo].first += k.ok();
        agg[k.algo].second++;
        src[k.algo] = k.source;
    }
    std::vector<std::vector<std::string>> rows;
    size_t ok = 0;
    for (const auto& a : order) {
        rows.push_back({a, src[a], std::to_string(agg[a].first) + "/" + std::to_string(agg[a].second),
                        agg[a].first == agg[a].second ? "OK" : "ОШИБКА"});
        ok += agg[a].first;
    }
    rows.push_back({"---"});
    rows.push_back({"Всего", "", std::to_string(ok) + "/" + std::to_string(kats.size()),
                    ok == kats.size() ? "OK" : "ОШИБКА"});
    return asciiTable({"Алгоритм", "Источник контрольных примеров", "Совпало", "Итог"}, rows,
                      {Align::Left, Align::Left, Align::Right, Align::Left});
}

static void generatePdfReport(UserSession& s) {
    auto msgs = loadMessages(s.username);
    if (msgs.empty()) { std::cout << "У вас пока нет зашифрованных сообщений — отчёт пуст.\n"; return; }

    pdf::Document doc;
    std::string err, fontPath = findFontPath(false), monoPath = findFontPath(true);
    if (fontPath.empty() || doc.addFont(fontPath, err) < 0) {
        std::cout << "Не найден TrueType-шрифт с кириллицей" << (err.empty() ? "" : " (" + err + ")")
                  << ". Укажите путь к .ttf в переменной окружения PDF_FONT или положите font.ttf рядом с программой.\n";
        return;
    }
    int mono = 0;
    if (!monoPath.empty()) { int f = doc.addFont(monoPath, err); if (f >= 0) mono = f; }
    if (mono == 0)
        std::cout << "Внимание: моноширинный шрифт не найден, ASCII-таблицы в PDF могут быть неровными\n"
                  << "(задайте путь к моноширинному .ttf в PDF_FONT_MONO).\n";

    auto reps = analyzeMessages(s, msgs);
    uint64_t now = nowUnixTime();
    size_t okCount = 0;
    for (const auto& r : reps) okCount += r.ok;

    doc.setTitle("Зашифрованные сообщения: " + s.username);
    doc.setFooterLeft("Пользователь " + s.username + " | сформировано " + formatTime(now));

    auto heading = [&](const std::string& t) { doc.space(10); doc.keepTogether(60); doc.paragraph(t, 13, 0, pdf::ACCENT); doc.space(2); };
    auto table = [&](const std::vector<std::string>& lines) { doc.preformatted(lines, 7.5, mono, pdf::BLACK); };

    doc.paragraph("Отчёт о зашифрованных сообщениях", 20, 0, pdf::ACCENT);
    doc.space(4);
    doc.paragraph("Пользователь: " + s.username, 11);
    doc.paragraph("Дата формирования: " + formatTime(now), 11);
    doc.paragraph("Сообщений: " + std::to_string(reps.size()) + ", успешно расшифровано и проверено: " +
                  std::to_string(okCount), 11);

    heading("1. Сводка по сообщениям");
    table(messageListTable(reps));

    heading("2. Статистика по алгоритмам");
    table(messageStatsTable(reps));
    doc.paragraph("Расширение - отношение размера шифртекста к открытому тексту. Кузнечик в режиме CTR не "
                  "увеличивает данные (плюс 8 байт IV и 16 байт имитовставки), RSA-OAEP превращает каждые "
                  "до 3966 байт текста в блок 4096 байт.", 8.5, 0, pdf::GRAY);

    heading("3. Параметры защиты");
    doc.paragraph("- Кузнечик: блочный шифр ГОСТ Р 34.12-2015, ключ 256 бит, режим гаммирования CTR "
                  "(ГОСТ Р 34.13-2015) со случайным 64-битным IV, имитовставка OMAC 128 бит на отдельном ключе "
                  "(Encrypt-then-MAC).", 9.5, 0, pdf::BLACK, 8);
    std::string rsaLine = "- RSA: модуль 32768 бит, e = 65537, дополнение RSAES-OAEP (RFC 8017) с хеш-функцией "
                          "Стрибог-512 (ГОСТ Р 34.11-2012) и MGF1; расшифрование по китайской теореме об остатках.";
    if (s.keys.count("rsa_n")) {
        rsa::Mpz n; n.fromHex(s.keys["rsa_n"]);
        rsaLine += " Модуль собран из " + s.keys["rsa_primes"] + " простых (многопростой RSA, RFC 8017)." +
                   " Отпечаток открытого ключа (Стрибог-512, 160 бит): " + rsaFingerprint(n) + ".";
    }
    doc.paragraph(rsaLine, 9.5, 0, pdf::BLACK, 8);
    doc.paragraph("- Ключи хранятся только в зашифрованном виде; ключ к ним выводится из пароля пользователя "
                  "функцией PBKDF2-HMAC-Стрибог-512 (" + s.keys["kdf_iter"] + " итераций).", 9.5, 0, pdf::BLACK, 8);

    heading("4. Проверка реализации по контрольным примерам ГОСТ");
    table(gostSummaryTable());

    rsa::KeygenStats ks;
    if (s.keys.count("rsa_gen_stats") && parseKeygenStats(s.keys["rsa_gen_stats"], ks)) {
        heading("5. Генерация ключа RSA-" + std::to_string(RSA_MODULUS_BITS));
        table(keygenStatsTable(ks));
        doc.paragraph("Потоков: " + std::to_string(ks.threads) + "; малых простых в решете: " +
                      std::to_string(ks.sievePrimes) + "; общее время: " + fmtTime(ks.seconds) + ".", 8.5, 0, pdf::GRAY);
    }

    heading("Сообщения");
    size_t emojiTotal = 0;
    for (auto& r : reps) {
        const auto& m = r.m;
        doc.keepTogether(120);
        doc.space(6);
        doc.paragraph("Сообщение №" + std::to_string(m.id) + " - " + algoShort(m.algo), 12, 0, pdf::ACCENT);
        doc.paragraph("Дата: " + formatTime(m.created) + "    Алгоритм: " + algoTitle(m.algo), 9, 0, pdf::GRAY);
        doc.space(3);

        if (m.algo == "KUZ") {
            SealedData sd;
            sealedFromString(m.payload, sd);
            doc.paragraph("IV (64 бита): " + toHex(sd.iv) + "    Имитовставка OMAC: " + toHex(sd.mac), 8.5, mono, pdf::BLACK);
            doc.paragraph("Шифртекст (" + std::to_string(sd.ct.size()) + " байт, hex):", 9.5, 0, pdf::BLACK);
            doc.paragraph(toHex(sd.ct), 7, mono, pdf::GRAY, 8, 1.25);
        } else {
            auto parts = splitByDelimiter(m.payload, ':');
            doc.paragraph("Шифртекст (блоков RSA по 4096 байт: " + std::to_string(parts.size()) + ", hex):",
                          9.5, 0, pdf::BLACK);
            for (size_t b = 0; b < parts.size(); b++) {
                if (parts.size() > 1) doc.paragraph("Блок " + std::to_string(b + 1) + ":", 8.5, 0, pdf::BLACK, 8);
                doc.paragraph(parts[b], 6, mono, pdf::GRAY, 8, 1.25);
            }
        }
        doc.space(4);
        doc.paragraph("Расшифрованный текст:", 9.5, 0, pdf::BLACK);
        if (r.ok) {
            size_t removed = 0;
            std::string clean = pdf::stripEmoji(r.text, removed);
            emojiTotal += removed;
            doc.paragraph(clean, 11, 0, pdf::BLACK, 8);
            if (removed)
                doc.paragraph("(из текста для PDF удалено эмодзи: " + std::to_string(removed) + ")", 8, 0, pdf::GRAY, 8);
            secureWipe(clean);
        }
        doc.paragraph("Проверка: " + r.status, 8.5, 0, r.ok ? pdf::GREEN : pdf::RED, 8);
        doc.paragraph("Размер: текст " + std::to_string(r.ptBytes) + " Б, шифртекст " + std::to_string(r.ctBytes) +
                      " Б; зашифровано за " + (m.encSec >= 0 ? fmtTime(m.encSec) : std::string("- (не замерялось)")) +
                      ", расшифровано за " + fmtTime(r.decryptSec), 8.5, 0, pdf::GRAY, 8);
        secureWipe(r.text);
    }

    if (s.keys.count("rsa_n")) {
        heading("Приложение: открытый ключ RSA-32768");
        doc.paragraph("e = 65537 (0x" + s.keys["rsa_e"] + ")", 9.5, mono);
        doc.paragraph("n (hex):", 9.5);
        doc.paragraph(s.keys["rsa_n"], 6, mono, pdf::GRAY, 8, 1.25);
    }

    char ts[32];
    std::time_t tt = static_cast<std::time_t>(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    std::strftime(ts, sizeof ts, "%Y%m%d_%H%M%S", &tm);
    std::string fileName = "report_" + sanitizeForFilename(s.username) + "_" + ts + ".pdf";

    // ---- электронная подпись ГОСТ Р 34.10-2012 ----
    const auto& curve = gost3410::workCurve();
    doc.keepTogether(230);   // заголовок и таблица подписи — на одной странице
    heading("Электронная подпись");
    {
        std::vector<std::vector<std::string>> rows = {
            {"Алгоритм подписи", "ГОСТ Р 34.10-2012, 256 бит"},
            {"Хеш-функция", "ГОСТ Р 34.11-2012 (Стрибог-256)"},
            {"Кривая", curve.name},
            {"Подписант", s.username},
            {"Отпечаток сертификата", certFingerprint(s.sigCert)},
            {"Время подписи", formatTime(now)},
            {"Формат", "CMS (PKCS#7 detached) внутри PDF"},
        };
        table(asciiTable({"Параметр", "Значение"}, rows));
    }
    doc.paragraph("Подпись охватывает весь файл, кроме самого значения подписи. Любое изменение документа после "
                  "подписания делает подпись недействительной. Проверка: пункт меню \"Проверить подпись PDF\" или "
                  "команда ./auth3fa --verify <файл.pdf>.", 8.5, 0, pdf::GRAY);
    doc.paragraph("Открытый ключ проверки подписи (x || y, little-endian, hex):", 8.5, 0, pdf::BLACK);
    doc.paragraph(s.keys["sig_pub"], 7, mono, pdf::GRAY, 8, 1.25);

    pdf::Document::SignatureRequest req;
    req.name = s.username;
    req.reason = "Отчёт о зашифрованных сообщениях";
    req.location = "infobez auth3fa";
    req.contact = "ГОСТ Р 34.10-2012 / ГОСТ Р 34.11-2012";
    req.when = static_cast<time_t>(now);
    double signSec = 0;
    req.signer = [&](const std::string& signedPart) {
        auto t0 = BenchClock::now();
        auto digest = streebog256Bytes(reinterpret_cast<const uint8_t*>(signedPart.data()), signedPart.size());
        auto cms = pdfsig::buildCms(curve, s.sigKey, s.sigCert, digest, static_cast<time_t>(now),
                                    streebog256HashFn(), cspRandomFn());
        signSec = secondsSince(t0);
        return cms;
    };
    doc.setSignature(req);

    if (!doc.save(fileName, err)) { std::cout << "Ошибка: " << err << "\n"; return; }
    std::error_code ec;
    auto abs = std::filesystem::absolute(fileName, ec);
    std::cout << "PDF-отчёт сохранён: " << (ec ? fileName : abs.string()) << "\n"
              << "Сообщений: " << reps.size() << ", успешно расшифровано: " << okCount << ".\n"
              << "Документ подписан ЭЦП ГОСТ Р 34.10-2012 за " << fmtTime(signSec) << " (подписано "
              << doc.signedBytes() << " байт). Контрольная проверка подписи:\n";
    printVerifyReport(pdfsig::verifyPdfFile(fileName, streebog256HashFn()), &s);
    if (emojiTotal) std::cout << "Из текста сообщений в PDF удалено эмодзи: " << emojiTotal << ".\n";
}

static void showKeyInfo(UserSession& s) {
    std::cout << "\n--- Ключи пользователя " << s.username << " ---\n"
              << "Ключ из пароля: PBKDF2-HMAC-Стрибог-512, " << s.keys["kdf_iter"] << " итераций, соль 128 бит\n"
              << "Ключ сообщений «Кузнечик»: 256 бит шифрование + 256 бит имитовставка (хранится зашифрованным)\n";
    if (s.keys.count("rsa_n")) {
        rsa::Mpz n; n.fromHex(s.keys["rsa_n"]);
        uint64_t created = 0;
        try { created = std::stoull(s.keys["rsa_created"]); } catch (...) {}
        std::cout << "RSA: модуль " << n.bits() << " бит из " << s.keys["rsa_primes"]
                  << " простых, e = 0x" << s.keys["rsa_e"] << "\n"
                  << "     создан " << formatTime(created) << " за " << s.keys["rsa_gen_seconds"] << " с\n"
                  << "     отпечаток: " << rsaFingerprint(n) << "\n";
    } else {
        std::cout << "RSA: ключ ещё не создан (будет создан при первом шифровании через RSA)\n";
    }
}

static void runUserSession(const std::string& username, const std::string& password) {
    UserSession s;
    std::string err;
    std::cout << "Открываем хранилище ключей (PBKDF2-HMAC-Стрибог-512)...\n";
    if (!unlockVault(username, password, s, err)) {
        std::cout << "Не удалось открыть хранилище: " << err << ".\n";
        return;
    }
    if (!ensureSigningKey(s, err)) {
        std::cout << "Не удалось открыть ключ электронной подписи: " << err << ".\n";
        return;
    }
    while (true) {
        std::cout << "\n--- Мои сообщения (" << username << ") ---\n"
                  << "1. Зашифровать новое сообщение\n"
                  << "2. Список моих сообщений\n"
                  << "3. Расшифровать сообщение\n"
                  << "4. Сформировать PDF-отчёт (все сообщения + расшифровка)\n"
                  << "5. Сведения о ключах\n"
                  << "6. Статистика и производительность (Стрибог, Кузнечик, RSA)\n"
                  << "7. Проверка по контрольным примерам ГОСТ\n"
                  << "8. Проверить подпись PDF-файла\n"
                  << "9. Выйти из аккаунта\n"
                  << "Выберите пункт: ";
        std::string choice;
        if (!std::getline(std::cin, choice)) return;
        try {
            if (choice == "1") encryptNewMessage(s);
            else if (choice == "2") listMessages(s);
            else if (choice == "3") showDecrypted(s);
            else if (choice == "4") generatePdfReport(s);
            else if (choice == "5") showKeyInfo(s);
            else if (choice == "6") showStatsAndPerformance(s);
            else if (choice == "7") showGostSelfTest();
            else if (choice == "8") {
                std::cout << "Путь к PDF-файлу: ";
                std::string path;
                std::getline(std::cin, path);
                printVerifyReport(pdfsig::verifyPdfFile(path, streebog256HashFn()), &s);
            }
            else if (choice == "9") { std::cout << "Вы вышли из аккаунта.\n"; return; }
            else std::cout << "Некорректный выбор, попробуйте снова.\n";
        } catch (const std::exception& ex) {
            std::cout << "Ошибка: " << ex.what() << "\n";
        }
    }
}

// ============================================================
// Вход: 3 фактора последовательно
// ============================================================
static void loginUser(const SmtpConfig& smtpConfig) {
    std::string username;
    std::cout << "Логин: ";
    std::getline(std::cin, username);

    // Служебная учётная запись администратора: только пароль,
    // без TOTP и без email — см. ADMIN_USERNAME/ADMIN_PASSWORD.
    if (username == ADMIN_USERNAME) {
        std::string adminPassword = readHiddenInput("Пароль администратора: ");
        if (adminPassword != ADMIN_PASSWORD) {
            std::cout << "Неверный логин или пароль.\n";
            return;
        }
        std::cout << "\nВход выполнен: администратор.\n";
        runAdminPanel();
        return;
    }

    auto users = loadUsers();

    auto it = std::find_if(users.begin(), users.end(),
        [&](const UserRecord& u) { return u.username == username; });

    // Фактор 1: пароль
    std::string password = readHiddenInput("Пароль: ");
    if (it == users.end() || hashPassword(password, it->saltHex) != it->pwHashHex) {
        std::cout << "Неверный логин или пароль.\n";
        return;
    }
    std::cout << "Фактор 1 (пароль) пройден.\n";

    // Учётная запись создана администратором и ещё не имеет email/TOTP —
    // сначала нужно завершить её настройку.
    if (it->email.empty() || it->totpSecretB32.empty()) {
        if (!completeFirstLoginSetup(username)) return;
        // Перечитываем пользователя с уже заполненными полями.
        users = loadUsers();
        it = std::find_if(users.begin(), users.end(),
            [&](const UserRecord& u) { return u.username == username; });
        if (it == users.end()) {
            std::cout << "Ошибка: учётная запись не найдена после настройки.\n";
            return;
        }
    }

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

    // Пароль нужен, чтобы вывести ключ хранилища (PBKDF2) — после этого
    // он сразу затирается в памяти.
    runUserSession(username, password);
    secureWipe(password);
}

// ============================================================
// Восстановление пароля через email
// ============================================================
// Пользователь подтверждает владение почтой, привязанной к аккаунту
// (код приходит туда же, куда и код третьего фактора при входе), и
// после этого задаёт новый пароль. TOTP-секрет и email при этом не
// меняются — обновляются только соль и хеш пароля.
static void recoverPassword(const SmtpConfig& smtpConfig) {
    auto users = loadUsers();

    std::string username;
    std::cout << "Логин, для которого восстанавливаем пароль: ";
    std::getline(std::cin, username);

    auto it = std::find_if(users.begin(), users.end(),
        [&](const UserRecord& u) { return u.username == username; });

    // Не подтверждаем и не опровергаем существование пользователя явно —
    // иначе по ответу программы можно было бы угадывать чужие логины.
    const std::string neutralMsg =
        "Если пользователь с таким именем существует, код восстановления "
        "отправлен на привязанную к нему почту.\n";

    if (it == users.end()) {
        std::cout << neutralMsg;
        return;
    }

    std::string code = generateNumericCode(6);
    sendEmailCode(smtpConfig, it->email, code);
    std::cout << neutralMsg;

    const int maxAttempts = 3;
    bool codeOk = false;
    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
        std::string entered;
        std::cout << "Введите код с почты (попытка " << attempt << "/" << maxAttempts << "): ";
        std::getline(std::cin, entered);
        if (entered == code) { codeOk = true; break; }
        std::cout << "Код неверный.\n";
    }

    if (!codeOk) {
        std::cout << "Не удалось подтвердить код. Восстановление пароля отменено.\n";
        return;
    }

    // Ключи шифрования сообщений защищены ключом, выведенным из СТАРОГО
    // пароля. Восстановление идёт без старого пароля, значит расшифровать
    // их будет невозможно — честно предупреждаем и удаляем хранилище.
    bool hadVault = vaultExists(username);
    if (hadVault) {
        std::cout << "\nВНИМАНИЕ: ваши зашифрованные сообщения и ключи (Кузнечик, RSA) защищены\n"
                  << "ключом, который выводится из старого пароля. Без старого пароля их\n"
                  << "невозможно расшифровать, поэтому после смены пароля они будут удалены.\n"
                  << "Продолжить восстановление? (д/н): ";
        std::string ans;
        std::getline(std::cin, ans);
        if (ans != "д" && ans != "Д" && ans != "y" && ans != "Y") {
            std::cout << "Восстановление пароля отменено.\n";
            return;
        }
    }

    std::cout << "Код подтверждён. Придумайте новый пароль.\n";
    std::string newPassword = choosePassword();
    if (newPassword.empty()) {
        std::cout << "Восстановление пароля отменено.\n";
        return;
    }

    std::string newSalt = generateSalt();
    std::string newHash = hashPassword(newPassword, newSalt);

    if (!updateUserPassword(username, newSalt, newHash)) {
        std::cout << "Ошибка: не удалось сохранить новый пароль.\n";
        return;
    }
    if (hadVault) {
        deleteVault(username);
        std::cout << "Старое хранилище сообщений удалено.\n";
    }

    std::cout << "Пароль успешно изменён. Теперь можно войти с новым паролем.\n";
}

// ============================================================
// main
// ============================================================
int main(int argc, char** argv) {
    std::string arg = argc > 1 ? argv[1] : "";
    if (arg == "--selftest") {
        std::cout << "=== Контрольные примеры ГОСТ: подробно ===\n";
        auto kats = gostKats();
        printKatDetails(kats);
        std::cout << "\n=== Контрольные примеры ГОСТ: сводка ===\n";
        bool ok = printKatTable(kats);
        std::cout << "\n=== Дополнительные проверки ===\n";
        ok = printKatTable(extraChecks()) && ok;
        std::cout << "\n" << (ok ? "Все проверки пройдены.\n" : "ЕСТЬ ОШИБКИ!\n");
        return ok ? 0 : 1;
    }
    if (arg == "--bench") return runCommandLineBench();
    if (arg == "--verify") {
        if (argc < 3) { std::cout << "Использование: ./auth3fa --verify <файл.pdf>\n"; return 2; }
        std::cout << "Проверка электронной подписи ГОСТ Р 34.10-2012: " << argv[2] << "\n";
        auto rep = pdfsig::verifyPdfFile(argv[2], streebog256HashFn());
        printVerifyReport(rep, nullptr);
        return rep.valid() ? 0 : 1;
    }
    if (!arg.empty()) {
        std::cout << "Использование: ./auth3fa [--selftest | --bench | --verify <файл.pdf>]\n";
        return 2;
    }

    // Самотестирование криптографии при каждом запуске (как в
    // сертифицированных криптомодулях): при расхождении с ГОСТ — стоп.
    if (!startupSelfTest()) return 3;
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
                  << "3. Восстановить пароль\n"
                  << "4. Выход из программы\n"
                  << "Выберите пункт: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") registerUser();
        else if (choice == "2") loginUser(smtpConfig);
        else if (choice == "3") recoverPassword(smtpConfig);
        else if (choice == "4") { std::cout << "Завершение работы.\n"; break; }
        else std::cout << "Некорректный выбор, попробуйте снова.\n";
    }

    return 0;
}
