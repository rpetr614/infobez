// auth.cpp
// Консольное приложение аутентификации.
// Этап 1: логин + пароль (первый фактор).
// Пароли не хранятся в открытом виде: используется соль + SHA-256.
//
// Компиляция:
//   g++ -std=c++17 -O2 -o auth auth.cpp
//
// Файл с пользователями: users.txt (создаётся автоматически рядом с программой)
// Формат строки: username;salt_hex;hash_hex

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <random>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// ============================================================
// Минимальная реализация SHA-256 (без внешних зависимостей)
// ============================================================
namespace sha256impl {

    struct SHA256 {
        uint32_t state[8];
        uint64_t bitlen;
        std::vector<uint8_t> buffer;

        SHA256() { reset(); }

        void reset() {
            state[0] = 0x6a09e667; state[1] = 0xbb67ae85;
            state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
            state[4] = 0x510e527f; state[5] = 0x9b05688c;
            state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
            bitlen = 0;
            buffer.clear();
        }

        static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

        static const uint32_t K[64];

        void transform(const uint8_t* data) {
            uint32_t w[64];
            for (int i = 0; i < 16; i++) {
                w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
                       (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
            }
            for (int i = 16; i < 64; i++) {
                uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
                uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }

            uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
            uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

            for (int i = 0; i < 64; i++) {
                uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = h + S1 + ch + K[i] + w[i];
                uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;

                h = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }

            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
            state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        }

        void update(const uint8_t* data, size_t len) {
            bitlen += static_cast<uint64_t>(len) * 8;
            buffer.insert(buffer.end(), data, data + len);
            while (buffer.size() >= 64) {
                transform(buffer.data());
                buffer.erase(buffer.begin(), buffer.begin() + 64);
            }
        }

        void update(const std::string& s) {
            update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        }

        std::vector<uint8_t> finalize() {
            uint64_t total_bits = bitlen;
            buffer.push_back(0x80);
            while (buffer.size() % 64 != 56) buffer.push_back(0x00);
            for (int i = 7; i >= 0; i--) {
                buffer.push_back(static_cast<uint8_t>((total_bits >> (i * 8)) & 0xff));
            }
            while (buffer.size() >= 64) {
                transform(buffer.data());
                buffer.erase(buffer.begin(), buffer.begin() + 64);
            }
            std::vector<uint8_t> out(32);
            for (int i = 0; i < 8; i++) {
                out[i*4]   = (state[i] >> 24) & 0xff;
                out[i*4+1] = (state[i] >> 16) & 0xff;
                out[i*4+2] = (state[i] >> 8) & 0xff;
                out[i*4+3] = state[i] & 0xff;
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

static std::vector<uint8_t> fromHex(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        out.push_back(byte);
    }
    return out;
}

static std::string sha256Hex(const std::string& input) {
    sha256impl::SHA256 ctx;
    ctx.update(input);
    return toHex(ctx.finalize());
}

// ============================================================
// Генерация соли
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
    // соль + пароль -> SHA-256
    return sha256Hex(saltHex + password);
}

// ============================================================
// Скрытый ввод пароля (без эха в консоль)
// ============================================================
static std::string readHiddenInput(const std::string& prompt) {
    std::cout << prompt;
    std::string password;

#ifdef _WIN32
    char ch;
    while ((ch = static_cast<char>(_getch())) != '\r') {
        if (ch == '\b') {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
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
    newt.c_lflag &= ~(ECHO); // отключаем эхо, но оставляем построчный режим
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
#endif

    return password;
}

// ============================================================
// Работа с файлом пользователей
// ============================================================
struct UserRecord {
    std::string username;
    std::string saltHex;
    std::string hashHex;
};

const std::string USERS_FILE = "users.txt";

static std::vector<UserRecord> loadUsers() {
    std::vector<UserRecord> users;
    std::ifstream in(USERS_FILE);
    if (!in.is_open()) return users;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string username, salt, hash;
        if (std::getline(ss, username, ';') &&
            std::getline(ss, salt, ';') &&
            std::getline(ss, hash, ';')) {
            users.push_back({username, salt, hash});
        }
    }
    return users;
}

static bool saveUser(const UserRecord& rec) {
    std::ofstream out(USERS_FILE, std::ios::app);
    if (!out.is_open()) return false;
    out << rec.username << ';' << rec.saltHex << ';' << rec.hashHex << '\n';
    return true;
}

static bool usernameExists(const std::vector<UserRecord>& users, const std::string& username) {
    return std::any_of(users.begin(), users.end(), [&](const UserRecord& u) {
        return u.username == username;
    });
}

// ============================================================
// Валидация ввода
// ============================================================
static bool isValidUsername(const std::string& s) {
    if (s.empty() || s.find(';') != std::string::npos) return false;
    return true;
}

// ============================================================
// Сценарии: регистрация и вход
// ============================================================
static void registerUser() {
    auto users = loadUsers();

    std::string username;
    std::cout << "Придумайте логин: ";
    std::getline(std::cin, username);

    if (!isValidUsername(username)) {
        std::cout << "Некорректный логин (пустой или содержит ';').\n";
        return;
    }
    if (usernameExists(users, username)) {
        std::cout << "Пользователь с таким логином уже существует.\n";
        return;
    }

    std::string password = readHiddenInput("Придумайте пароль: ");
    std::string password2 = readHiddenInput("Повторите пароль: ");

    if (password.empty()) {
        std::cout << "Пароль не может быть пустым.\n";
        return;
    }
    if (password != password2) {
        std::cout << "Пароли не совпадают.\n";
        return;
    }

    std::string salt = generateSalt();
    std::string hash = hashPassword(password, salt);

    if (saveUser({username, salt, hash})) {
        std::cout << "Регистрация успешна. Пользователь \"" << username << "\" сохранён.\n";
    } else {
        std::cout << "Ошибка: не удалось записать файл пользователей.\n";
    }
}

static void loginUser() {
    auto users = loadUsers();

    std::string username;
    std::cout << "Логин: ";
    std::getline(std::cin, username);

    auto it = std::find_if(users.begin(), users.end(), [&](const UserRecord& u) {
        return u.username == username;
    });

    if (it == users.end()) {
        std::cout << "Неверный логин или пароль.\n"; // не уточняем, что именно неверно
        return;
    }

    std::string password = readHiddenInput("Пароль: ");
    std::string hash = hashPassword(password, it->saltHex);

    if (hash == it->hashHex) {
        std::cout << "Успешный вход. Добро пожаловать, " << username << "!\n";
        // Здесь в будущем будет переход ко второму фактору аутентификации.
    } else {
        std::cout << "Неверный логин или пароль.\n";
    }
}

// ============================================================
// main
// ============================================================
int main() {
    std::cout << "=== Система аутентификации (этап 1: логин/пароль) ===\n";

    while (true) {
        std::cout << "\nМеню:\n"
                  << "1. Регистрация\n"
                  << "2. Вход\n"
                  << "3. Выход из программы\n"
                  << "Выберите пункт: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            registerUser();
        } else if (choice == "2") {
            loginUser();
        } else if (choice == "3") {
            std::cout << "Завершение работы.\n";
            break;
        } else {
            std::cout << "Некорректный выбор, попробуйте снова.\n";
        }
    }

    return 0;
}
