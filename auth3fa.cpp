// auth3fa.cpp
// Консольное приложение с трёхфакторной аутентификацией:
//   Фактор 1: логин + пароль (соль + SHA-256)
//   Фактор 2: TOTP-код (RFC 6238, совместим с Google Authenticator / Authy)
//   Фактор 3: одноразовый код, автоматически отправляемый на email через Gmail SMTP
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

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
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
// SHA-256 (для хеширования паролей)
// ============================================================
namespace sha256impl {
    struct SHA256 {
        uint32_t state[8];
        uint64_t bitlen;
        std::vector<uint8_t> buffer;

        SHA256() { reset(); }
        void reset() {
            state[0]=0x6a09e667; state[1]=0xbb67ae85; state[2]=0x3c6ef372; state[3]=0xa54ff53a;
            state[4]=0x510e527f; state[5]=0x9b05688c; state[6]=0x1f83d9ab; state[7]=0x5be0cd19;
            bitlen = 0; buffer.clear();
        }
        static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
        static const uint32_t K[64];

        void transform(const uint8_t* data) {
            uint32_t w[64];
            for (int i = 0; i < 16; i++)
                w[i] = (data[i*4]<<24)|(data[i*4+1]<<16)|(data[i*4+2]<<8)|(data[i*4+3]);
            for (int i = 16; i < 64; i++) {
                uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
                uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }
            uint32_t a=state[0],b=state[1],c=state[2],d=state[3];
            uint32_t e=state[4],f=state[5],g=state[6],h=state[7];
            for (int i = 0; i < 64; i++) {
                uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = h + S1 + ch + K[i] + w[i];
                uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;
                h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
            }
            state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
            state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
        }
        void update(const uint8_t* data, size_t len) {
            bitlen += static_cast<uint64_t>(len) * 8;
            buffer.insert(buffer.end(), data, data + len);
            while (buffer.size() >= 64) { transform(buffer.data()); buffer.erase(buffer.begin(), buffer.begin()+64); }
        }
        void update(const std::string& s) { update(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }
        std::vector<uint8_t> finalize() {
            uint64_t total_bits = bitlen;
            buffer.push_back(0x80);
            while (buffer.size() % 64 != 56) buffer.push_back(0x00);
            for (int i = 7; i >= 0; i--) buffer.push_back(static_cast<uint8_t>((total_bits >> (i*8)) & 0xff));
            while (buffer.size() >= 64) { transform(buffer.data()); buffer.erase(buffer.begin(), buffer.begin()+64); }
            std::vector<uint8_t> out(32);
            for (int i = 0; i < 8; i++) {
                out[i*4]=(state[i]>>24)&0xff; out[i*4+1]=(state[i]>>16)&0xff;
                out[i*4+2]=(state[i]>>8)&0xff; out[i*4+3]=state[i]&0xff;
            }
            return out;
        }
    };
    const uint32_t SHA256::K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
}

static std::string sha256Hex(const std::string& input) {
    sha256impl::SHA256 ctx;
    ctx.update(input);
    return toHex(ctx.finalize());
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
// Пароль: соль + SHA-256
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
    return sha256Hex(saltHex + password);
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
