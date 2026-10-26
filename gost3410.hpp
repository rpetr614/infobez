// gost3410.hpp
// Электронная цифровая подпись ГОСТ Р 34.10-2012 (эллиптические кривые),
// вариант 256 бит, с хеш-функцией ГОСТ Р 34.11-2012 «Стрибог-256».
// Реализация с нуля, длинная арифметика — GMP (класс rsa::Mpz из rsa_gmp.hpp).
//
// Кривая в форме Вейерштрасса: y^2 = x^3 + a*x + b (mod p), базовая точка
// P порядка q. Ключи: закрытый d (0 < d < q), открытый Q = d*P.
//
// Подпись (ГОСТ Р 34.10-2012, п. 6.1):
//   1) e = alpha mod q, где alpha — число, двоичная запись которого есть хеш h(M);
//      если e = 0, то e = 1;
//   2) случайное k, 0 < k < q;
//   3) C = k*P, r = x_C mod q; если r = 0 — к шагу 2;
//   4) s = (r*d + k*e) mod q; если s = 0 — к шагу 2;
//   5) подпись — пара (r, s).
// Проверка (п. 6.2):
//   0 < r, s < q; e как выше; v = e^{-1} mod q; z1 = s*v, z2 = -r*v (mod q);
//   C = z1*P + z2*Q; подпись верна, если x_C mod q == r.
//
// Умножение точки на секретное число (k, d) выполняется лестницей Монтгомери:
// последовательность операций не зависит от битов числа (защита от атак по
// времени на уровне алгоритма).
#pragma once

#include "rsa_gmp.hpp"   // rsa::Mpz, os2ip, i2osp

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace gost3410 {

using rsa::Mpz;

struct Curve {
    std::string name, oid;
    Mpz p, a, b, q, x, y;   // модуль, коэффициенты, порядок подгруппы, базовая точка
};

struct Point {
    Mpz x, y;
    bool inf = true;   // точка на бесконечности (нейтральный элемент)
};

inline Mpz hexMpz(const char* h) { Mpz r; r.fromHex(h); return r; }

// ------------------------------------------------------------
// Параметры кривых
// ------------------------------------------------------------
// Рабочая кривая: id-tc26-gost-3410-2012-256-paramSetB
// (= id-GostR3410-2001-CryptoPro-A-ParamSet, RFC 4357 / Р 50.1.114-2016).
constexpr int CURVE_WORK_LINE = __LINE__ + 1;
inline const Curve& workCurve() {
    static const Curve c = [] {
        Curve k;
        k.name = "id-tc26-gost-3410-2012-256-paramSetB (CryptoPro-A)";
        k.oid = "1.2.643.7.1.2.1.1.2";
        k.p = hexMpz("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
        k.a = hexMpz("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94");
        k.b = hexMpz("A6");
        k.q = hexMpz("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893");
        k.x = hexMpz("1");
        k.y = hexMpz("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14");
        return k;
    }();
    return c;
}

// Тестовая кривая из контрольного примера 1 ГОСТ Р 34.10-2012 (прил. А) /
// RFC 7091 §7.1. Используется ТОЛЬКО для самопроверки.
constexpr int CURVE_TEST_LINE = __LINE__ + 1;
inline const Curve& testCurve() {
    static const Curve c = [] {
        Curve k;
        k.name = "тестовая кривая контрольного примера 1";
        k.oid = "";
        k.p = hexMpz("8000000000000000000000000000000000000000000000000000000000000431");
        k.a = hexMpz("7");
        k.b = hexMpz("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E");
        k.q = hexMpz("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3");
        k.x = hexMpz("2");
        k.y = hexMpz("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8");
        return k;
    }();
    return c;
}

// ------------------------------------------------------------
// Арифметика точек (аффинные координаты)
// ------------------------------------------------------------
inline bool onCurve(const Curve& c, const Point& P) {
    if (P.inf) return true;
    Mpz l, r, t;
    mpz_mul(l, P.y, P.y);
    mpz_mod(l, l, c.p);
    mpz_mul(r, P.x, P.x);
    mpz_mul(r, r, P.x);
    mpz_mul(t, c.a, P.x);
    mpz_add(r, r, t);
    mpz_add(r, r, c.b);
    mpz_mod(r, r, c.p);
    return mpz_cmp(l, r) == 0;
}

inline Point add(const Curve& c, const Point& P, const Point& Q) {
    if (P.inf) return Q;
    if (Q.inf) return P;
    Mpz lambda, num, den, t;
    if (mpz_cmp(P.x, Q.x) == 0) {
        mpz_add(t, P.y, Q.y);
        mpz_mod(t, t, c.p);
        if (mpz_sgn(t.get()) == 0) return Point();          // P + (-P) = O
        // удвоение: lambda = (3x^2 + a) / (2y)
        mpz_mul(num, P.x, P.x);
        mpz_mul_ui(num, num, 3);
        mpz_add(num, num, c.a);
        mpz_mul_ui(den, P.y, 2);
    } else {
        mpz_sub(num, Q.y, P.y);
        mpz_sub(den, Q.x, P.x);
    }
    mpz_mod(den, den, c.p);
    if (mpz_invert(den, den, c.p) == 0) throw std::runtime_error("ГОСТ 34.10: необратимый знаменатель");
    mpz_mul(lambda, num, den);
    mpz_mod(lambda, lambda, c.p);
    Point R;
    R.inf = false;
    mpz_mul(R.x, lambda, lambda);
    mpz_sub(R.x, R.x, P.x);
    mpz_sub(R.x, R.x, Q.x);
    mpz_mod(R.x, R.x, c.p);
    mpz_sub(t, P.x, R.x);
    mpz_mul(R.y, lambda, t);
    mpz_sub(R.y, R.y, P.y);
    mpz_mod(R.y, R.y, c.p);
    return R;
}

// k*P лестницей Монтгомери (одинаковая последовательность сложений и удвоений
// для любого k фиксированной длины)
inline Point mul(const Curve& c, const Mpz& k, const Point& P) {
    Point R0, R1 = P;   // R0 = O
    size_t bits = std::max<size_t>(c.q.bits(), k.bits());
    for (size_t i = bits; i-- > 0;) {
        if (mpz_tstbit(k.get(), i)) { R0 = add(c, R0, R1); R1 = add(c, R1, R1); }
        else                        { R1 = add(c, R0, R1); R0 = add(c, R0, R0); }
    }
    return R0;
}

inline Point basePoint(const Curve& c) { Point P; P.x = c.x; P.y = c.y; P.inf = false; return P; }

// Проверка корректности параметров кривой: точка на кривой, q*P = O
inline bool curveSane(const Curve& c) {
    Point P = basePoint(c);
    return onCurve(c, P) && mul(c, c.q, P).inf && mpz_probab_prime_p(c.q.get(), 30) > 0 &&
           mpz_probab_prime_p(c.p.get(), 30) > 0;
}

// ------------------------------------------------------------
// Ключи, подпись, проверка
// ------------------------------------------------------------
struct KeyPair {
    Mpz d;      // закрытый
    Point Q;    // открытый
};

// Случайное число в [1, q-1] выборкой с отказом (без смещения)
inline Mpz randomScalar(const Curve& c, const std::function<void(uint8_t*, size_t)>& rnd) {
    size_t len = (c.q.bits() + 7) / 8;
    std::vector<uint8_t> buf(len);
    while (true) {
        rnd(buf.data(), len);
        Mpz k;
        rsa::os2ip(k, buf.data(), len);
        mpz_tdiv_r_2exp(k.get(), k.get(), c.q.bits());
        if (mpz_sgn(k.get()) != 0 && mpz_cmp(k, c.q) < 0) {
            std::fill(buf.begin(), buf.end(), 0);
            return k;
        }
    }
}

inline KeyPair generateKey(const Curve& c, const std::function<void(uint8_t*, size_t)>& rnd) {
    KeyPair kp;
    kp.d = randomScalar(c, rnd);
    kp.Q = mul(c, kp.d, basePoint(c));
    return kp;
}

inline Point publicFromPrivate(const Curve& c, const Mpz& d) { return mul(c, d, basePoint(c)); }

// Хеш Стрибог-256 в том порядке байтов, в котором его возвращает реализация
// (байт 0 — младший байт числа, как во внутреннем представлении стандарта).
// alpha — число, двоичная запись которого равна хешу => читаем байты как
// little-endian.
inline Mpz hashToE(const Curve& c, const std::vector<uint8_t>& hashLE) {
    std::vector<uint8_t> be(hashLE.rbegin(), hashLE.rend());
    Mpz e;
    rsa::os2ip(e, be.data(), be.size());
    mpz_mod(e, e, c.q);
    if (mpz_sgn(e.get()) == 0) mpz_set_ui(e, 1);
    return e;
}

struct Signature { Mpz r, s; };

// Подпись при заданных e и k (шаги 3-5) — нужна и для контрольного примера.
// Возвращает false, если r = 0 или s = 0 (надо выбрать другое k).
constexpr int SIGN_LINE = __LINE__ + 1;
inline bool signWithK(const Curve& c, const Mpz& d, const Mpz& e, const Mpz& k, Signature& sig) {
    Point C = mul(c, k, basePoint(c));
    mpz_mod(sig.r, C.x, c.q);
    if (mpz_sgn(sig.r.get()) == 0) return false;
    Mpz t;
    mpz_mul(sig.s, sig.r, d);
    mpz_mul(t, k, e);
    mpz_add(sig.s, sig.s, t);
    mpz_mod(sig.s, sig.s, c.q);
    return mpz_sgn(sig.s.get()) != 0;
}

inline Signature sign(const Curve& c, const Mpz& d, const std::vector<uint8_t>& hashLE,
                      const std::function<void(uint8_t*, size_t)>& rnd) {
    Mpz e = hashToE(c, hashLE);
    Signature sig;
    while (true) {
        Mpz k = randomScalar(c, rnd);
        bool ok = signWithK(c, d, e, k, sig);
        k.wipe();
        if (ok) return sig;
    }
}

constexpr int VERIFY_LINE = __LINE__ + 1;
inline bool verifyE(const Curve& c, const Point& Q, const Mpz& e, const Signature& sig) {
    if (mpz_sgn(sig.r.get()) <= 0 || mpz_cmp(sig.r, c.q) >= 0) return false;
    if (mpz_sgn(sig.s.get()) <= 0 || mpz_cmp(sig.s, c.q) >= 0) return false;
    if (Q.inf || !onCurve(c, Q)) return false;
    Mpz v, z1, z2;
    if (mpz_invert(v, e, c.q) == 0) return false;
    mpz_mul(z1, sig.s, v);
    mpz_mod(z1, z1, c.q);
    mpz_mul(z2, sig.r, v);
    mpz_neg(z2, z2);
    mpz_mod(z2, z2, c.q);
    // проверка открытая — секретов нет, можно обычное умножение
    Point C = add(c, mul(c, z1, basePoint(c)), mul(c, z2, Q));
    if (C.inf) return false;
    Mpz R;
    mpz_mod(R, C.x, c.q);
    return mpz_cmp(R, sig.r) == 0;
}

inline bool verify(const Curve& c, const Point& Q, const std::vector<uint8_t>& hashLE, const Signature& sig) {
    return verifyE(c, Q, hashToE(c, hashLE), sig);
}

// ------------------------------------------------------------
// Кодирование (RFC 4491 / RFC 9215 / Р 1323565.1.024-2019):
//   открытый ключ  — 64 октета: x (little-endian, 32) || y (little-endian, 32);
//   подпись в X.509 и CMS — 64 октета: s (big-endian, 32) || r (big-endian, 32).
// ------------------------------------------------------------
inline std::vector<uint8_t> toLE(const Mpz& v, size_t len) {
    auto be = rsa::i2osp(v, len);
    return std::vector<uint8_t>(be.rbegin(), be.rend());
}
inline Mpz fromLE(const uint8_t* p, size_t len) {
    std::vector<uint8_t> be(p, p + len);
    std::reverse(be.begin(), be.end());
    Mpz v;
    rsa::os2ip(v, be.data(), be.size());
    return v;
}

inline std::vector<uint8_t> encodePublicKey(const Point& Q) {
    auto x = toLE(Q.x, 32), y = toLE(Q.y, 32);
    x.insert(x.end(), y.begin(), y.end());
    return x;
}
inline bool decodePublicKey(const Curve& c, const std::vector<uint8_t>& b, Point& Q) {
    if (b.size() != 64) return false;
    Q.x = fromLE(b.data(), 32);
    Q.y = fromLE(b.data() + 32, 32);
    Q.inf = false;
    return onCurve(c, Q);
}

inline std::vector<uint8_t> encodeSignature(const Signature& sig) {
    auto s = rsa::i2osp(sig.s, 32), r = rsa::i2osp(sig.r, 32);
    s.insert(s.end(), r.begin(), r.end());
    return s;
}
inline bool decodeSignature(const std::vector<uint8_t>& b, Signature& sig) {
    if (b.size() != 64) return false;
    rsa::os2ip(sig.s, b.data(), 32);
    rsa::os2ip(sig.r, b.data() + 32, 32);
    return true;
}

} // namespace gost3410
