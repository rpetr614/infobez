// rsa_gmp.hpp
// RSA с модулем 32768 бит на базе GNU MP (GMP).
//
// Почему GMP, а не своя длинная арифметика: для 16384-битных чисел GMP
// использует умножение Карацубы/Тоома-Кука на ассемблерных ядрах под
// конкретный процессор (ARM64 / x86-64), редукцию Монтгомери и оконное
// возведение в степень. Самописная «школьная» арифметика на таких размерах
// медленнее в десятки-сотни раз — генерация ключа заняла бы часы.
//
// Что сделано для скорости:
//  1. Генерация простых: случайная стартовая точка + решето по ~1,08 млн
//     малых простых (до 2^24) на окне из 65 536 нечётных кандидатов.
//     Решето отсеивает ~93% нечётных составных ещё до дорогих тестов.
//     В том же решете сразу отбрасываются кандидаты p ≡ 1 (mod e), чтобы
//     НОД(e, p-1) = 1 выполнялся автоматически.
//  2. Оставшиеся кандидаты проверяются ПАРАЛЛЕЛЬНО во всех ядрах
//     процессора: сначала тест Ферма по основанию 2 (одно возведение в
//     степень отсекает почти все составные), затем финальная проверка
//     mpz_probab_prime_p (в GMP ≥ 6.2 это тест BPSW + Миллер–Рабин).
//  3. Многопростой RSA (RFC 8017 §3, «multi-prime RSA»): модуль 32768 бит
//     собирается из u простых по 32768/u бит (по умолчанию u = 4, задаётся
//     в auth3fa.cpp). Стоимость возведения в степень растёт примерно как
//     b^2.6 на каждый из b бит показателя, поэтому:
//       - простые по 8192 бит проверяются ~4x быстрее, чем по 16384 бит,
//         а нужно их лишь вдвое больше => генерация ключа ~3-4x быстрее;
//       - расшифрование — u независимых возведений в степень по модулям
//         в u раз короче => ~4-7x быстрее классического CRT.
//     Стойкость определяется длиной модуля n (лучшая атака — решето
//     числового поля); метод эллиптических кривых для множителей по
//     8192 бит абсолютно непрактичен (рекорд ECM — множитель ~270 бит).
//  4. Шифрование: e = 65537 (17 умножений по модулю).
//  5. Расшифрование: Китайская теорема об остатках + обобщённая формула
//     Гарнера; возведения в степень по каждому простому выполняются
//     ПАРАЛЛЕЛЬНО, по потоку на простое.
//  6. Закрытый ключ возводится в степень через mpz_powm_sec (постоянное
//     время — защита от атак по времени), результат CRT проверяется
//     обратным возведением m^e (защита от атак сбоев, атака Белкора).
//
// Дополнение: RSAES-OAEP (RFC 8017) с хеш-функцией Стрибог-512 и MGF1
// на её основе. Сообщения длиннее одного блока (3966 байт) разбиваются
// на блоки, каждый шифруется отдельно.
#pragma once

#include <gmp.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace rsa {

using RandomFn = std::function<void(uint8_t*, size_t)>;
using HashFn   = std::function<std::vector<uint8_t>(const uint8_t*, size_t)>;
using ProgressFn = std::function<void(const std::string&)>;

// ------------------------------------------------------------
// RAII-обёртка над mpz_t
// ------------------------------------------------------------
class Mpz {
public:
    Mpz() { mpz_init(v_); }
    explicit Mpz(unsigned long x) { mpz_init_set_ui(v_, x); }
    Mpz(const Mpz& o) { mpz_init_set(v_, o.v_); }
    Mpz& operator=(const Mpz& o) { if (this != &o) mpz_set(v_, o.v_); return *this; }
    ~Mpz() { wipe(); mpz_clear(v_); }
    mpz_ptr get() { return v_; }
    mpz_srcptr get() const { return v_; }
    operator mpz_ptr() { return v_; }
    operator mpz_srcptr() const { return v_; }

    std::string toHex() const {
        std::vector<char> buf(mpz_sizeinbase(v_, 16) + 2);
        mpz_get_str(buf.data(), 16, v_);
        return std::string(buf.data());
    }
    bool fromHex(const std::string& s) { return !s.empty() && mpz_set_str(v_, s.c_str(), 16) == 0; }
    size_t bits() const { return mpz_sizeinbase(v_, 2); }

    // Затираем лимбы перед освобождением (секретные данные не должны
    // оставаться в освобождённой памяти).
    void wipe() {
        size_t n = mpz_size(v_);
        mp_limb_t* d = mpz_limbs_modify(v_, n ? n : 1);
        volatile mp_limb_t* vd = d;
        for (size_t i = 0; i < (n ? n : 1); i++) vd[i] = 0;
        mpz_set_ui(v_, 0);
    }
private:
    mpz_t v_;
};

// Байты (big-endian) <-> число
inline void os2ip(Mpz& x, const uint8_t* data, size_t len) {
    mpz_import(x, len, 1, 1, 1, 0, data);
}
inline std::vector<uint8_t> i2osp(const Mpz& x, size_t len) {
    size_t need = (mpz_sizeinbase(x, 2) + 7) / 8;
    if (mpz_sgn(x.get()) == 0) need = 0;
    if (need > len) throw std::runtime_error("i2osp: integer too large");
    std::vector<uint8_t> out(len, 0);
    size_t written = 0;
    if (need) mpz_export(out.data() + (len - need), &written, 1, 1, 1, 0, x);
    return out;
}

// ------------------------------------------------------------
// Ключи
// ------------------------------------------------------------
struct PublicKey {
    Mpz n, e;
    size_t k() const { return (n.bits() + 7) / 8; }  // длина модуля в байтах
};

// Закрытый ключ в CRT-представлении RFC 8017 §3.2 (поддерживает и
// классический RSA с двумя простыми, и многопростой RSA с u > 2):
//   n = r_1 * r_2 * ... * r_u
//   d_i = d mod (r_i - 1)                                (CRT-экспоненты)
//   t_i = (r_1 * ... * r_{i-1})^{-1} mod r_i, i >= 2     (CRT-коэффициенты)
struct PrivateKey {
    Mpz n, e, d;
    std::vector<Mpz> primes, exps, coeffs;   // coeffs[0] не используется
    PublicKey pub() const { PublicKey k; k.n = n; k.e = e; return k; }

    static std::string joinHex(const std::vector<Mpz>& v, size_t from = 0) {
        std::string s;
        for (size_t i = from; i < v.size(); i++) { if (i > from) s += ','; s += v[i].toHex(); }
        return s;
    }
    static std::vector<std::string> split(const std::string& s, char delim) {
        std::vector<std::string> parts;
        size_t start = 0;
        while (true) {
            size_t pos = s.find(delim, start);
            parts.push_back(s.substr(start, pos == std::string::npos ? std::string::npos : pos - start));
            if (pos == std::string::npos) break;
            start = pos + 1;
        }
        return parts;
    }

    // d:r_1,...,r_u:d_1,...,d_u:t_2,...,t_u  (n и e хранятся отдельно, открыто)
    std::string serializeSecret() const {
        return d.toHex() + ":" + joinHex(primes) + ":" + joinHex(exps) + ":" + joinHex(coeffs, 1);
    }
    bool deserializeSecret(const std::string& s, const Mpz& nIn, const Mpz& eIn) {
        auto parts = split(s, ':');
        if (parts.size() != 4) return false;
        auto ps = split(parts[1], ','), ds = split(parts[2], ','), ts = split(parts[3], ',');
        size_t u = ps.size();
        if (u < 2 || ds.size() != u || ts.size() != u - 1) return false;
        n = nIn; e = eIn;
        if (!d.fromHex(parts[0])) return false;
        primes.assign(u, Mpz()); exps.assign(u, Mpz()); coeffs.assign(u, Mpz());
        Mpz prod(1);
        for (size_t i = 0; i < u; i++) {
            if (!primes[i].fromHex(ps[i]) || !exps[i].fromHex(ds[i])) return false;
            if (i > 0 && !coeffs[i].fromHex(ts[i - 1])) return false;
            mpz_mul(prod, prod, primes[i]);
        }
        return mpz_cmp(prod, n) == 0;
    }
};

// ------------------------------------------------------------
// Малые простые для решета (решето Эратосфена, вычисляется один раз)
// ------------------------------------------------------------
inline const std::vector<uint32_t>& smallPrimes() {
    static const std::vector<uint32_t> primes = [] {
        const uint32_t LIMIT = 1u << 24;   // 16 777 216 -> ~1,08 млн простых
        std::vector<uint8_t> comp(LIMIT + 1, 0);
        std::vector<uint32_t> res;
        for (uint32_t i = 3; i <= LIMIT; i += 2) {
            if (comp[i]) continue;
            res.push_back(i);
            for (uint64_t j = static_cast<uint64_t>(i) * i; j <= LIMIT; j += 2ull * i) comp[j] = 1;
        }
        return res;
    }();
    return primes;
}

inline unsigned threadCount() {
    unsigned t = std::thread::hardware_concurrency();
    return t == 0 ? 2 : t;
}

// ------------------------------------------------------------
// Статистика генерации (для вывода производительности)
// ------------------------------------------------------------
struct PrimeStats {
    size_t bits = 0;
    size_t windows = 0;          // сколько окон решета понадобилось
    size_t sieveCandidates = 0;  // нечётных кандидатов в окнах
    size_t sieveSurvivors = 0;   // прошли решето
    size_t fermatTests = 0;      // выполнено тестов Ферма
    size_t strongTests = 0;      // кандидатов дошло до BPSW + Миллер–Рабин
    size_t pseudoprimes = 0;     // прошли тест Ферма, но отсеяны строгой проверкой
    double sieveSeconds = 0;     // время решета
    double seconds = 0;          // полное время поиска
};

static constexpr size_t SIEVE_WINDOW = 1u << 16;   // нечётных кандидатов в одном окне

struct KeygenStats {
    std::vector<PrimeStats> primes;
    size_t restarts = 0;         // перезапуски (близкие простые / неполная длина n)
    bool pseudoKnown = true;     // false — статистика старого формата, без учёта псевдопростых
    unsigned threads = 0;
    size_t sievePrimes = 0;
    double seconds = 0;
};

// ------------------------------------------------------------
// Генерация простого числа ровно bits бит, p mod e != 1.
// Четыре старших бита = 1, т.е. p >= 0.9375 * 2^bits: тогда произведение
// до 10 таких чисел гарантированно имеет полную длину (0.9375^10 > 0.5).
// ------------------------------------------------------------
inline void generatePrime(Mpz& out, size_t bits, unsigned long e, const RandomFn& rnd,
                          const ProgressFn& progress, const char* label, PrimeStats* stats = nullptr) {
    const auto& primes = smallPrimes();
    const size_t WINDOW = SIEVE_WINDOW;
    const unsigned nThreads = threadCount();
    size_t totalTested = 0;
    PrimeStats st;
    st.bits = bits;
    auto tStart = std::chrono::steady_clock::now();

    while (true) {
        st.windows++;
        auto tSieve = std::chrono::steady_clock::now();
        // Случайная стартовая точка
        std::vector<uint8_t> rb((bits + 7) / 8);
        rnd(rb.data(), rb.size());
        Mpz base;
        os2ip(base, rb.data(), rb.size());
        std::fill(rb.begin(), rb.end(), 0);
        mpz_tdiv_r_2exp(base, base, bits);
        for (size_t b = 1; b <= 4; b++) mpz_setbit(base, bits - b);
        mpz_setbit(base, 0);

        // Решето: sieve[i] = 1, если base + 2i заведомо не подходит
        // Остатки base mod p для ~1 млн малых простых считаются во всех потоках
        std::vector<uint32_t> residues(primes.size());
        {
            std::vector<std::thread> pool;
            size_t chunk = (primes.size() + nThreads - 1) / nThreads;
            for (unsigned t = 0; t < nThreads; t++) {
                pool.emplace_back([&, t]() {
                    size_t from = t * chunk, to = std::min(primes.size(), from + chunk);
                    for (size_t k = from; k < to; k++)
                        residues[k] = static_cast<uint32_t>(mpz_fdiv_ui(base, primes[k]));
                });
            }
            for (auto& th : pool) th.join();
        }
        std::vector<uint8_t> sieve(WINDOW, 0);
        for (size_t k = 0; k < primes.size(); k++) {
            uint64_t p = primes[k], r = residues[k];
            // base + 2i ≡ 0 (mod p)  =>  i ≡ (p - r) * inv(2) (mod p), inv(2) = (p+1)/2
            uint64_t i0 = ((p - r) % p) * ((p + 1) / 2) % p;
            for (uint64_t i = i0; i < WINDOW; i += p) sieve[i] = 1;
        }
        {   // base + 2i ≡ 1 (mod e) — иначе НОД(e, p-1) != 1
            uint64_t r = mpz_fdiv_ui(base, e);
            uint64_t i0 = ((1 + e - r) % e) * ((e + 1) / 2) % e;
            for (uint64_t i = i0; i < WINDOW; i += e) sieve[i] = 1;
        }
        std::vector<uint32_t> survivors;
        for (uint32_t i = 0; i < WINDOW; i++) if (!sieve[i]) survivors.push_back(i);
        st.sieveCandidates += WINDOW;
        st.sieveSurvivors += survivors.size();
        st.sieveSeconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - tSieve).count();

        // Параллельная проверка выживших кандидатов
        std::atomic<size_t> next{0};
        std::atomic<bool> found{false};
        std::atomic<size_t> tested{0};
        std::atomic<size_t> strong{0};
        std::atomic<size_t> pseudo{0};
        std::mutex resMx;
        Mpz result;

        auto worker = [&]() {
            Mpz cand, nm1, two(2), r;
            while (!found.load(std::memory_order_relaxed)) {
                size_t idx = next.fetch_add(1);
                if (idx >= survivors.size()) return;
                mpz_add_ui(cand, base, 2ul * survivors[idx]);
                // Тест Ферма по основанию 2 — самый дешёвый «фильтр»
                mpz_sub_ui(nm1, cand, 1);
                mpz_powm(r, two, nm1, cand);
                tested.fetch_add(1, std::memory_order_relaxed);
                if (mpz_cmp_ui(r.get(), 1) != 0) continue;
                // Финальная строгая проверка (BPSW + Миллер–Рабин)
                strong.fetch_add(1, std::memory_order_relaxed);
                if (mpz_probab_prime_p(cand, 27) == 0) { pseudo.fetch_add(1); continue; }
                std::lock_guard<std::mutex> lk(resMx);
                if (!found.exchange(true)) result = cand;
                return;
            }
        };

        std::atomic<bool> monitorStop{false};
        std::thread monitor([&]() {
            int ticks = 0;
            while (!monitorStop.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (++ticks % 30 == 0 && progress)
                    progress(std::string(label) + ": проверено кандидатов " +
                             std::to_string(totalTested + tested.load()) + "...");
            }
        });

        std::vector<std::thread> pool;
        for (unsigned t = 0; t < nThreads; t++) pool.emplace_back(worker);
        for (auto& th : pool) th.join();
        monitorStop = true;
        monitor.join();

        totalTested += tested.load();
        st.fermatTests += tested.load();
        st.strongTests += strong.load();
        st.pseudoprimes += pseudo.load();
        if (found) {
            out = result;
            st.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - tStart).count();
            if (stats) *stats = st;
            if (progress)
                progress(std::string(label) + " найдено (" + std::to_string(bits) +
                         " бит), проверено кандидатов: " + std::to_string(totalTested));
            return;
        }
        // Простого в окне не нашлось (очень редко) — новая стартовая точка
    }
}

// ------------------------------------------------------------
// Генерация пары ключей
// ------------------------------------------------------------
// numPrimes = 2 — классический RSA; numPrimes > 2 — многопростой RSA
// (RFC 8017 §3), модуль той же длины собирается из нескольких простых
// меньшего размера. Возведение в степень стоит ~O(b^2.6) на каждый из
// b бит, поэтому простые вдвое короче проверяются в ~4 раза быстрее.
inline PrivateKey generateKey(size_t modulusBits, size_t numPrimes, const RandomFn& rnd,
                              const ProgressFn& progress, KeygenStats* stats = nullptr) {
    const unsigned long E = 65537;
    if (numPrimes < 2 || numPrimes > 10 || modulusBits % numPrimes != 0)
        throw std::runtime_error("RSA: неподдерживаемое число простых");
    const size_t pBits = modulusBits / numPrimes;
    PrivateKey key;
    mpz_set_ui(key.e, E);
    auto t0 = std::chrono::steady_clock::now();
    KeygenStats ks;
    ks.threads = threadCount();
    ks.sievePrimes = smallPrimes().size();
    bool firstAttempt = true;
    struct Finish {   // заполняет stats при любом выходе с готовым ключом
        KeygenStats& ks; KeygenStats* out; std::chrono::steady_clock::time_point t0;
        ~Finish() {
            if (!out) return;
            ks.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            *out = ks;
        }
    } finish{ks, stats, t0};

    while (true) {
        if (!firstAttempt) ks.restarts++;
        firstAttempt = false;
        key.primes.assign(numPrimes, Mpz());
        ks.primes.assign(numPrimes, PrimeStats());
        for (size_t i = 0; i < numPrimes; i++) {
            std::string label = "Простое " + std::to_string(i + 1) + "/" + std::to_string(numPrimes);
            generatePrime(key.primes[i], pBits, E, rnd, progress, label.c_str(), &ks.primes[i]);
        }

        // Все попарные разности должны быть большими (иначе n раскладывается
        // методом Ферма) — для случайных простых это выполняется практически всегда
        bool closePair = false;
        for (size_t i = 0; i < numPrimes && !closePair; i++)
            for (size_t j = i + 1; j < numPrimes && !closePair; j++) {
                Mpz diff;
                mpz_sub(diff, key.primes[i], key.primes[j]);
                mpz_abs(diff, diff);
                if (diff.bits() < pBits - 100) closePair = true;
            }
        if (closePair) continue;

        mpz_set_ui(key.n, 1);
        for (auto& p : key.primes) mpz_mul(key.n, key.n, p);
        if (key.n.bits() != modulusBits) continue;

        Mpz lambda(1), pm1;                                  // функция Кармайкла λ(n) = НОК(r_i - 1)
        for (auto& p : key.primes) { mpz_sub_ui(pm1, p, 1); mpz_lcm(lambda, lambda, pm1); }
        if (mpz_invert(key.d, key.e, lambda) == 0) continue;
        if (key.d.bits() <= modulusBits / 2) continue;       // защита от атаки Винера (формально)

        key.exps.assign(numPrimes, Mpz());
        key.coeffs.assign(numPrimes, Mpz());
        Mpz prefix(1);
        bool ok = true;
        for (size_t i = 0; i < numPrimes; i++) {
            mpz_sub_ui(pm1, key.primes[i], 1);
            mpz_mod(key.exps[i], key.d, pm1);
            if (i > 0 && mpz_invert(key.coeffs[i], prefix, key.primes[i]) == 0) ok = false;
            mpz_mul(prefix, prefix, key.primes[i]);
        }
        if (ok) return key;
    }
}

// ------------------------------------------------------------
// Примитивы RSAEP / RSADP
// ------------------------------------------------------------
inline void rsaep(Mpz& c, const PublicKey& pk, const Mpz& m) {
    mpz_powm(c, m, pk.e, pk.n);
}

// CRT: m_i = c^{d_i} mod r_i считаются ПАРАЛЛЕЛЬНО (по потоку на простое),
// mpz_powm_sec — возведение в степень за постоянное время. Затем m
// собирается обобщённой формулой Гарнера (RFC 8017 §5.1.2):
//   m = m_1;  R = r_1;  для i = 2..u:  h = (m_i - m) * t_i mod r_i;  m += R*h;  R *= r_i
// parallel = false — все возведения в степень в одном потоке (только для
// замера выигрыша от параллельности в бенчмарке).
inline void rsadp(Mpz& m, const PrivateKey& sk, const Mpz& c, bool parallel = true) {
    const size_t u = sk.primes.size();
    std::vector<Mpz> parts(u);
    auto work = [&](size_t i) {
        Mpz ci;
        mpz_mod(ci, c, sk.primes[i]);
        mpz_powm_sec(parts[i], ci, sk.exps[i], sk.primes[i]);
    };
    if (parallel) {
        std::vector<std::thread> pool;
        for (size_t i = 1; i < u; i++) pool.emplace_back(work, i);
        work(0);
        for (auto& t : pool) t.join();
    } else {
        for (size_t i = 0; i < u; i++) work(i);
    }

    Mpz R, h;
    m = parts[0];
    R = sk.primes[0];
    for (size_t i = 1; i < u; i++) {
        mpz_sub(h, parts[i], m);
        mpz_mul(h, h, sk.coeffs[i]);
        mpz_mod(h, h, sk.primes[i]);
        mpz_mul(h, h, R);
        mpz_add(m, m, h);
        mpz_mul(R, R, sk.primes[i]);
    }
    // Проверка от атак сбоев: m^e mod n должно дать исходное c
    Mpz check;
    mpz_powm(check, m, sk.e, sk.n);
    if (mpz_cmp(check, c) != 0) throw std::runtime_error("RSA: CRT self-check failed");
}

// ------------------------------------------------------------
// OAEP (RFC 8017 §7.1), метка L пустая
// ------------------------------------------------------------
inline std::vector<uint8_t> mgf1(const HashFn& H, const uint8_t* seed, size_t seedLen, size_t maskLen) {
    std::vector<uint8_t> out;
    out.reserve(maskLen + 64);
    std::vector<uint8_t> buf(seed, seed + seedLen);
    buf.resize(seedLen + 4);
    for (uint32_t counter = 0; out.size() < maskLen; counter++) {
        buf[seedLen]     = static_cast<uint8_t>(counter >> 24);
        buf[seedLen + 1] = static_cast<uint8_t>(counter >> 16);
        buf[seedLen + 2] = static_cast<uint8_t>(counter >> 8);
        buf[seedLen + 3] = static_cast<uint8_t>(counter);
        auto h = H(buf.data(), buf.size());
        out.insert(out.end(), h.begin(), h.end());
    }
    out.resize(maskLen);
    return out;
}

inline size_t oaepMaxMessage(size_t k, size_t hLen) { return k - 2 * hLen - 2; }

inline std::vector<uint8_t> oaepEncryptBlock(const PublicKey& pk, const HashFn& H, size_t hLen,
                                             const RandomFn& rnd, const uint8_t* msg, size_t mLen) {
    const size_t k = pk.k();
    if (mLen > oaepMaxMessage(k, hLen)) throw std::runtime_error("OAEP: message too long");
    auto lHash = H(nullptr, 0);
    // DB = lHash || PS || 0x01 || M
    std::vector<uint8_t> db(k - hLen - 1, 0);
    std::memcpy(db.data(), lHash.data(), hLen);
    db[db.size() - mLen - 1] = 0x01;
    if (mLen) std::memcpy(db.data() + db.size() - mLen, msg, mLen);
    std::vector<uint8_t> seed(hLen);
    rnd(seed.data(), hLen);
    auto dbMask = mgf1(H, seed.data(), hLen, db.size());
    for (size_t i = 0; i < db.size(); i++) db[i] ^= dbMask[i];
    auto seedMask = mgf1(H, db.data(), db.size(), hLen);
    for (size_t i = 0; i < hLen; i++) seed[i] ^= seedMask[i];
    std::vector<uint8_t> em(k, 0);
    std::memcpy(em.data() + 1, seed.data(), hLen);
    std::memcpy(em.data() + 1 + hLen, db.data(), db.size());

    Mpz m, c;
    os2ip(m, em.data(), em.size());
    rsaep(c, pk, m);
    return i2osp(c, k);
}

// Возвращает false при любой ошибке декодирования (одна общая ошибка —
// защита от атаки Мангера, которая различает причины отказа).
inline bool oaepDecryptBlock(const PrivateKey& sk, const HashFn& H, size_t hLen,
                             const std::vector<uint8_t>& ct, std::vector<uint8_t>& out) {
    const size_t k = (sk.n.bits() + 7) / 8;
    if (ct.size() != k || k < 2 * hLen + 2) return false;
    Mpz c, m;
    os2ip(c, ct.data(), ct.size());
    if (mpz_cmp(c, sk.n) >= 0) return false;
    rsadp(m, sk, c);
    std::vector<uint8_t> em = i2osp(m, k);

    std::vector<uint8_t> seed(em.begin() + 1, em.begin() + 1 + hLen);
    std::vector<uint8_t> db(em.begin() + 1 + hLen, em.end());
    auto seedMask = mgf1(H, db.data(), db.size(), hLen);
    for (size_t i = 0; i < hLen; i++) seed[i] ^= seedMask[i];
    auto dbMask = mgf1(H, seed.data(), hLen, db.size());
    for (size_t i = 0; i < db.size(); i++) db[i] ^= dbMask[i];

    auto lHash = H(nullptr, 0);
    uint8_t bad = em[0];
    for (size_t i = 0; i < hLen; i++) bad |= static_cast<uint8_t>(db[i] ^ lHash[i]);
    // Поиск разделителя 0x01 без раннего выхода
    size_t sepIdx = 0;
    uint8_t lookingFor = 1;   // 1 пока не нашли 0x01
    for (size_t i = hLen; i < db.size(); i++) {
        uint8_t isOne  = static_cast<uint8_t>(db[i] == 0x01);
        uint8_t isZero = static_cast<uint8_t>(db[i] == 0x00);
        if (lookingFor & isOne) sepIdx = i;
        bad |= static_cast<uint8_t>(lookingFor & static_cast<uint8_t>(!isOne) & static_cast<uint8_t>(!isZero));
        lookingFor &= static_cast<uint8_t>(!isOne);
    }
    bad |= lookingFor;
    if (bad) return false;
    out.assign(db.begin() + sepIdx + 1, db.end());
    return true;
}

// Сообщение произвольной длины -> последовательность OAEP-блоков
inline std::vector<std::vector<uint8_t>> encryptMessage(const PublicKey& pk, const HashFn& H, size_t hLen,
                                                        const RandomFn& rnd, const std::string& msg) {
    const size_t maxLen = oaepMaxMessage(pk.k(), hLen);
    std::vector<std::vector<uint8_t>> blocks;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(msg.data());
    size_t off = 0;
    do {
        size_t n = std::min(maxLen, msg.size() - off);
        blocks.push_back(oaepEncryptBlock(pk, H, hLen, rnd, data + off, n));
        off += n;
    } while (off < msg.size());
    return blocks;
}

inline bool decryptMessage(const PrivateKey& sk, const HashFn& H, size_t hLen,
                           const std::vector<std::vector<uint8_t>>& blocks, std::string& out) {
    out.clear();
    for (const auto& b : blocks) {
        std::vector<uint8_t> part;
        if (!oaepDecryptBlock(sk, H, hLen, b, part)) { out.clear(); return false; }
        out.append(part.begin(), part.end());
    }
    return true;
}

} // namespace rsa
