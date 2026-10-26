// asn1.hpp
// Минимальный кодировщик и разборщик ASN.1 DER — ровно то, что нужно для
// сертификата X.509 и контейнера подписи CMS (PKCS#7) в PDF.
#pragma once

#include <cstdint>
#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

namespace asn1 {

using Bytes = std::vector<uint8_t>;

enum Tag : uint8_t {
    BOOLEAN = 0x01, INTEGER = 0x02, BIT_STRING = 0x03, OCTET_STRING = 0x04, NULL_ = 0x05, OID = 0x06,
    UTF8_STRING = 0x0C, PRINTABLE_STRING = 0x13, UTC_TIME = 0x17, GENERALIZED_TIME = 0x18,
    SEQUENCE = 0x30, SET = 0x31
};

// ------------------------------------------------------------
// Кодирование
// ------------------------------------------------------------
inline Bytes tlv(uint8_t tag, const Bytes& content) {
    Bytes out{tag};
    size_t n = content.size();
    if (n < 0x80) out.push_back(static_cast<uint8_t>(n));
    else {
        Bytes len;
        while (n) { len.insert(len.begin(), static_cast<uint8_t>(n & 0xFF)); n >>= 8; }
        out.push_back(static_cast<uint8_t>(0x80 | len.size()));
        out.insert(out.end(), len.begin(), len.end());
    }
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

inline Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes r;
    for (const auto& p : parts) r.insert(r.end(), p.begin(), p.end());
    return r;
}
inline Bytes seq(std::initializer_list<Bytes> parts) { return tlv(SEQUENCE, cat(parts)); }
inline Bytes set(std::initializer_list<Bytes> parts) { return tlv(SET, cat(parts)); }
inline Bytes explicitTag(int n, const Bytes& inner) { return tlv(static_cast<uint8_t>(0xA0 | n), inner); }
inline Bytes implicitTagConstructed(int n, const Bytes& content) { return tlv(static_cast<uint8_t>(0xA0 | n), content); }

inline Bytes oid(const std::string& dotted) {
    std::vector<uint64_t> arcs;
    uint64_t cur = 0;
    bool have = false;
    for (char ch : dotted) {
        if (ch == '.') { arcs.push_back(cur); cur = 0; have = false; }
        else { cur = cur * 10 + static_cast<uint64_t>(ch - '0'); have = true; }
    }
    if (have) arcs.push_back(cur);
    if (arcs.size() < 2) throw std::runtime_error("bad OID");
    Bytes c;
    auto enc = [&](uint64_t v) {
        Bytes t{static_cast<uint8_t>(v & 0x7F)};
        v >>= 7;
        while (v) { t.insert(t.begin(), static_cast<uint8_t>(0x80 | (v & 0x7F))); v >>= 7; }
        c.insert(c.end(), t.begin(), t.end());
    };
    enc(arcs[0] * 40 + arcs[1]);
    for (size_t i = 2; i < arcs.size(); i++) enc(arcs[i]);
    return tlv(OID, c);
}

// Неотрицательное целое из big-endian байтов
inline Bytes integer(Bytes be) {
    while (be.size() > 1 && be[0] == 0 && !(be[1] & 0x80)) be.erase(be.begin());
    if (be.empty()) be.push_back(0);
    if (be[0] & 0x80) be.insert(be.begin(), 0);
    return tlv(INTEGER, be);
}
inline Bytes integer(uint64_t v) {
    Bytes be;
    do { be.insert(be.begin(), static_cast<uint8_t>(v & 0xFF)); v >>= 8; } while (v);
    return integer(be);
}
inline Bytes octetString(const Bytes& b) { return tlv(OCTET_STRING, b); }
inline Bytes bitString(const Bytes& b) { Bytes c{0}; c.insert(c.end(), b.begin(), b.end()); return tlv(BIT_STRING, c); }
inline Bytes utf8(const std::string& s) { return tlv(UTF8_STRING, Bytes(s.begin(), s.end())); }
inline Bytes null() { return Bytes{NULL_, 0x00}; }

inline std::string timeString(time_t t, bool generalized) {
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char b[32];
    std::strftime(b, sizeof b, generalized ? "%Y%m%d%H%M%SZ" : "%y%m%d%H%M%SZ", &tm);
    return b;
}
// RFC 5280: даты до 2049 года — UTCTime, начиная с 2050 — GeneralizedTime
inline Bytes x509Time(time_t t) {
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    bool gen = tm.tm_year + 1900 >= 2050;
    std::string s = timeString(t, gen);
    return tlv(gen ? GENERALIZED_TIME : UTC_TIME, Bytes(s.begin(), s.end()));
}

// ------------------------------------------------------------
// Разбор
// ------------------------------------------------------------
struct Node {
    uint8_t tag = 0;
    size_t start = 0, headerLen = 0, len = 0;   // смещения в исходном буфере
    const Bytes* buf = nullptr;
    const uint8_t* content() const { return buf->data() + start + headerLen; }
    Bytes contentBytes() const { return Bytes(content(), content() + len); }
    Bytes encoded() const { return Bytes(buf->data() + start, buf->data() + start + headerLen + len); }
    size_t end() const { return start + headerLen + len; }
    bool constructed() const { return tag & 0x20; }
};

inline Node parseAt(const Bytes& b, size_t pos) {
    if (pos + 2 > b.size()) throw std::runtime_error("ASN.1: выход за границу");
    Node n;
    n.buf = &b;
    n.start = pos;
    n.tag = b[pos];
    if ((n.tag & 0x1F) == 0x1F) throw std::runtime_error("ASN.1: многобайтовые теги не поддерживаются");
    uint8_t l = b[pos + 1];
    if (l < 0x80) { n.len = l; n.headerLen = 2; }
    else {
        size_t cnt = l & 0x7F;
        if (cnt == 0 || cnt > 4 || pos + 2 + cnt > b.size()) throw std::runtime_error("ASN.1: неверная длина");
        n.len = 0;
        for (size_t i = 0; i < cnt; i++) n.len = (n.len << 8) | b[pos + 2 + i];
        n.headerLen = 2 + cnt;
    }
    if (n.end() > b.size()) throw std::runtime_error("ASN.1: длина больше данных");
    return n;
}

inline std::vector<Node> children(const Node& n) {
    std::vector<Node> r;
    size_t p = n.start + n.headerLen;
    while (p < n.end()) {
        Node c = parseAt(*n.buf, p);
        r.push_back(c);
        p = c.end();
    }
    return r;
}

inline std::string oidToString(const Node& n) {
    if (n.tag != OID || n.len == 0) throw std::runtime_error("ASN.1: ожидался OID");
    const uint8_t* c = n.content();
    std::string s;
    uint64_t v = 0;
    bool first = true;
    for (size_t i = 0; i < n.len; i++) {
        v = (v << 7) | (c[i] & 0x7F);
        if (!(c[i] & 0x80)) {
            if (first) {
                uint64_t a = v < 40 ? 0 : (v < 80 ? 1 : 2);
                s = std::to_string(a) + "." + std::to_string(v - 40 * a);
                first = false;
            } else s += "." + std::to_string(v);
            v = 0;
        }
    }
    return s;
}

} // namespace asn1
