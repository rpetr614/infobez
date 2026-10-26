// pdf_signature.hpp
// Электронная подпись PDF по ГОСТ Р 34.10-2012 (256 бит) + Стрибог-256.
//
// Как устроена подпись внутри PDF (ISO 32000-1, п. 12.8):
//   - в документе есть поле подписи (/FT /Sig) и словарь подписи /Type /Sig;
//   - /ByteRange [0 a b c] — какие байты файла подписаны: всё, КРОМЕ самого
//     значения /Contents (там лежит подпись, она не может подписывать сама себя);
//   - /Contents <...> — контейнер CMS SignedData (RFC 5652, «PKCS#7 detached»):
//       * сертификат подписанта X.509 с открытым ключом ГОСТ Р 34.10-2012;
//       * подписанные атрибуты: тип содержимого, хеш Стрибог-256 подписанных
//         байтов PDF (messageDigest) и время подписи;
//       * значение подписи ГОСТ Р 34.10-2012 над подписанными атрибутами.
//   - Идентификаторы алгоритмов — по Р 1323565.1.024-2019 / RFC 9215:
//       1.2.643.7.1.1.1.1  ГОСТ Р 34.10-2012, ключ 256 бит
//       1.2.643.7.1.1.2.2  ГОСТ Р 34.11-2012, хеш 256 бит
//       1.2.643.7.1.1.3.2  подпись ГОСТ Р 34.10-2012 с хешем ГОСТ Р 34.11-2012 (256)
//
// Сертификат самоподписанный (удостоверяющего центра в учебном проекте нет):
// подпись математически проверяется, а принадлежность ключа пользователю
// подтверждает сама программа — ключ хранится в его зашифрованном хранилище.
#pragma once

#include "asn1.hpp"
#include "gost3410.hpp"

#include <fstream>
#include <functional>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace pdfsig {

using asn1::Bytes;
using HashFn = std::function<Bytes(const uint8_t*, size_t)>;   // Стрибог-256 (байты в порядке реализации)
using RandomFn = std::function<void(uint8_t*, size_t)>;

constexpr const char* OID_GOST_KEY_256      = "1.2.643.7.1.1.1.1";
constexpr const char* OID_STREEBOG_256      = "1.2.643.7.1.1.2.2";
constexpr const char* OID_GOST_SIGN_256     = "1.2.643.7.1.1.3.2";
constexpr const char* OID_DATA              = "1.2.840.113549.1.7.1";
constexpr const char* OID_SIGNED_DATA       = "1.2.840.113549.1.7.2";
constexpr const char* OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3";
constexpr const char* OID_ATTR_MSG_DIGEST   = "1.2.840.113549.1.9.4";
constexpr const char* OID_ATTR_SIGN_TIME    = "1.2.840.113549.1.9.5";
constexpr const char* OID_CN = "2.5.4.3";
constexpr const char* OID_O  = "2.5.4.10";
constexpr const char* OID_OU = "2.5.4.11";

inline std::string hexOf(const Bytes& b) {
    static const char* h = "0123456789abcdef";
    std::string s;
    for (uint8_t x : b) { s += h[x >> 4]; s += h[x & 15]; }
    return s;
}

// ------------------------------------------------------------
// Сертификат X.509 v3 (самоподписанный)
// ------------------------------------------------------------
inline Bytes name(const std::string& cn, const std::string& org, const std::string& ou) {
    auto rdn = [](const char* o, const std::string& v) { return asn1::set({asn1::seq({asn1::oid(o), asn1::utf8(v)})}); };
    return asn1::seq({rdn(OID_O, org), rdn(OID_OU, ou), rdn(OID_CN, cn)});
}

inline Bytes subjectPublicKeyInfo(const gost3410::Curve& c, const gost3410::Point& Q) {
    Bytes params = asn1::seq({asn1::oid(c.oid), asn1::oid(OID_STREEBOG_256)});
    return asn1::seq({asn1::seq({asn1::oid(OID_GOST_KEY_256), params}),
                      asn1::bitString(asn1::octetString(gost3410::encodePublicKey(Q)))});
}

struct CertInfo {
    std::string commonName, organization = "infobez", unit = "auth3fa";
    time_t notBefore = 0, notAfter = 0;
};

inline Bytes signDer(const gost3410::Curve& c, const rsa::Mpz& d, const Bytes& data, const HashFn& H, const RandomFn& rnd) {
    auto h = H(data.data(), data.size());
    return gost3410::encodeSignature(gost3410::sign(c, d, h, rnd));
}

inline Bytes buildSelfSignedCert(const gost3410::Curve& c, const gost3410::KeyPair& kp, const CertInfo& info,
                                 const HashFn& H, const RandomFn& rnd) {
    Bytes serial(16);
    rnd(serial.data(), serial.size());
    serial[0] &= 0x7F;
    serial[0] |= 0x01;
    Bytes subj = name(info.commonName, info.organization, info.unit);
    Bytes sigAlg = asn1::seq({asn1::oid(OID_GOST_SIGN_256)});
    // Расширения: basicConstraints (не УЦ), keyUsage = digitalSignature + nonRepudiation
    Bytes basicConstraints = asn1::seq({asn1::oid("2.5.29.19"), asn1::octetString(asn1::seq({}))});
    Bytes keyUsage = asn1::seq({asn1::oid("2.5.29.15"), Bytes{asn1::BOOLEAN, 1, 0xFF},
                                asn1::octetString(Bytes{asn1::BIT_STRING, 2, 6, 0xC0})});
    Bytes tbs = asn1::seq({
        asn1::explicitTag(0, asn1::integer(2)),                       // версия v3
        asn1::integer(serial),
        sigAlg,
        subj,                                                         // издатель = субъект
        asn1::seq({asn1::x509Time(info.notBefore), asn1::x509Time(info.notAfter)}),
        subj,
        subjectPublicKeyInfo(c, kp.Q),
        asn1::explicitTag(3, asn1::seq({basicConstraints, keyUsage})),
    });
    return asn1::seq({tbs, sigAlg, asn1::bitString(signDer(c, kp.d, tbs, H, rnd))});
}

// ------------------------------------------------------------
// CMS SignedData (detached) для PDF
// ------------------------------------------------------------
inline Bytes buildCms(const gost3410::Curve& c, const gost3410::KeyPair& kp, const Bytes& certDer,
                      const Bytes& contentHash, time_t signingTime, const HashFn& H, const RandomFn& rnd) {
    asn1::Node cert = asn1::parseAt(certDer, 0);
    auto tbsKids = asn1::children(asn1::children(cert)[0]);
    Bytes issuer = tbsKids[3].encoded(), serial = tbsKids[1].encoded();

    Bytes attrs = asn1::cat({
        asn1::seq({asn1::oid(OID_ATTR_CONTENT_TYPE), asn1::set({asn1::oid(OID_DATA)})}),
        asn1::seq({asn1::oid(OID_ATTR_SIGN_TIME), asn1::set({asn1::x509Time(signingTime)})}),
        asn1::seq({asn1::oid(OID_ATTR_MSG_DIGEST), asn1::set({asn1::octetString(contentHash)})}),
    });
    // Подписываются атрибуты в кодировке SET OF (RFC 5652, п. 5.4)
    Bytes signedAttrsForSig = asn1::tlv(asn1::SET, attrs);
    Bytes signature = signDer(c, kp.d, signedAttrsForSig, H, rnd);

    Bytes digestAlg = asn1::seq({asn1::oid(OID_STREEBOG_256)});
    Bytes signerInfo = asn1::seq({
        asn1::integer(1),
        asn1::seq({issuer, serial}),
        digestAlg,
        asn1::implicitTagConstructed(0, attrs),
        asn1::seq({asn1::oid(OID_GOST_KEY_256)}),
        asn1::octetString(signature),
    });
    Bytes signedData = asn1::seq({
        asn1::integer(1),
        asn1::set({digestAlg}),
        asn1::seq({asn1::oid(OID_DATA)}),                    // содержимое отделено (detached)
        asn1::implicitTagConstructed(0, certDer),            // certificates
        asn1::set({signerInfo}),
    });
    return asn1::seq({asn1::oid(OID_SIGNED_DATA), asn1::explicitTag(0, signedData)});
}

// ------------------------------------------------------------
// Проверка подписи PDF
// ------------------------------------------------------------
struct VerifyReport {
    bool found = false;           // в файле есть подпись
    bool parsed = false;          // CMS и сертификат разобраны
    bool coversWholeFile = false; // подписан весь файл, кроме значения подписи
    bool digestOk = false;        // хеш подписанных байтов совпал с messageDigest
    bool signatureOk = false;     // подпись ГОСТ Р 34.10-2012 над атрибутами верна
    bool certSelfSigOk = false;   // самоподпись сертификата верна
    std::string error;
    std::string subjectCN, organization, signingTime, notBefore, notAfter, serialHex;
    std::string digestAlgOid, sigAlgOid, curveOid;
    Bytes publicKey, certDer, messageDigest, computedDigest;
    size_t fileSize = 0, signedBytes = 0, range[4] = {0, 0, 0, 0}, cmsSize = 0;
    bool valid() const { return found && parsed && coversWholeFile && digestOk && signatureOk && certSelfSigOk; }
};

inline std::string asString(const asn1::Node& n) { return std::string(n.content(), n.content() + n.len); }

// Человекочитаемое время из UTCTime/GeneralizedTime (ГГММДДччммссZ)
inline std::string readableTime(const asn1::Node& n) {
    std::string s = asString(n);
    if (n.tag == asn1::UTC_TIME && s.size() >= 12) s = (s.substr(0, 2) < "50" ? "20" : "19") + s;
    if (s.size() < 14) return s;
    return s.substr(6, 2) + "." + s.substr(4, 2) + "." + s.substr(0, 4) + " " + s.substr(8, 2) + ":" +
           s.substr(10, 2) + ":" + s.substr(12, 2) + " UTC";
}

inline void readName(const asn1::Node& nameNode, std::string& cn, std::string& org) {
    for (const auto& rdn : asn1::children(nameNode))
        for (const auto& atv : asn1::children(rdn)) {
            auto k = asn1::children(atv);
            if (k.size() != 2) continue;
            std::string o = asn1::oidToString(k[0]);
            if (o == OID_CN) cn = asString(k[1]);
            if (o == OID_O) org = asString(k[1]);
        }
}

inline VerifyReport verifyPdfBytes(const std::string& file, const HashFn& H) {
    VerifyReport r;
    r.fileSize = file.size();
    size_t br = file.rfind("/ByteRange");
    if (br == std::string::npos) { r.error = "в файле нет электронной подписи (/ByteRange не найден)"; return r; }
    r.found = true;
    try {
        size_t lb = file.find('[', br), rb = file.find(']', br);
        if (lb == std::string::npos || rb == std::string::npos || rb < lb) throw std::runtime_error("повреждён /ByteRange");
        std::istringstream is(file.substr(lb + 1, rb - lb - 1));
        for (auto& v : r.range) if (!(is >> v)) throw std::runtime_error("повреждён /ByteRange");
        size_t a = r.range[0], b = r.range[1], c = r.range[2], d = r.range[3];
        if (a + b > file.size() || c + d > file.size() || c < a + b) throw std::runtime_error("/ByteRange вне файла");
        r.coversWholeFile = (a == 0 && c + d == file.size() && file[b] == '<' && file[c - 1] == '>');
        r.signedBytes = b + d;

        // Подпись CMS в hex между < и >
        std::string hex = file.substr(b + 1, c - b - 2);
        Bytes cms;
        cms.reserve(hex.size() / 2);
        auto nib = [](char x) { return x <= '9' ? x - '0' : (x | 0x20) - 'a' + 10; };
        for (size_t i = 0; i + 1 < hex.size(); i += 2) cms.push_back(static_cast<uint8_t>(nib(hex[i]) * 16 + nib(hex[i + 1])));
        asn1::Node ci = asn1::parseAt(cms, 0);               // нули-заполнители после DER отбрасываются
        r.cmsSize = ci.end();
        auto ciKids = asn1::children(ci);
        if (ciKids.size() != 2 || asn1::oidToString(ciKids[0]) != OID_SIGNED_DATA) throw std::runtime_error("это не CMS SignedData");
        asn1::Node sd = asn1::children(ciKids[1])[0];
        auto sdKids = asn1::children(sd);
        asn1::Node certs, signerInfos;
        bool haveCert = false;
        for (const auto& k : sdKids) {
            if (k.tag == 0xA0) { certs = k; haveCert = true; }
            if (k.tag == asn1::SET) signerInfos = k;
        }
        if (!haveCert) throw std::runtime_error("в подписи нет сертификата");

        // --- сертификат ---
        asn1::Node cert = asn1::children(certs)[0];
        r.certDer = cert.encoded();
        auto certKids = asn1::children(cert);
        asn1::Node tbs = certKids[0];
        auto tbsKids = asn1::children(tbs);
        r.serialHex = hexOf(tbsKids[1].contentBytes());
        readName(tbsKids[5], r.subjectCN, r.organization);
        auto validity = asn1::children(tbsKids[4]);
        r.notBefore = readableTime(validity[0]);
        r.notAfter = readableTime(validity[1]);
        auto spki = asn1::children(tbsKids[6]);
        auto spkiAlg = asn1::children(spki[0]);
        if (asn1::oidToString(spkiAlg[0]) != OID_GOST_KEY_256) throw std::runtime_error("ключ сертификата не ГОСТ Р 34.10-2012 (256)");
        r.curveOid = asn1::oidToString(asn1::children(spkiAlg[1])[0]);
        const gost3410::Curve& curve = gost3410::workCurve();
        if (r.curveOid != curve.oid) throw std::runtime_error("неподдерживаемые параметры кривой " + r.curveOid);
        Bytes bits = spki[1].contentBytes();
        Bytes keyOctets(bits.begin() + 1, bits.end());
        asn1::Node keyNode = asn1::parseAt(keyOctets, 0);
        r.publicKey = keyNode.contentBytes();
        gost3410::Point Q;
        if (!gost3410::decodePublicKey(curve, r.publicKey, Q)) throw std::runtime_error("открытый ключ не лежит на кривой");

        Bytes certSigBits = certKids[2].contentBytes();
        gost3410::Signature certSig;
        if (gost3410::decodeSignature(Bytes(certSigBits.begin() + 1, certSigBits.end()), certSig)) {
            Bytes tbsDer = tbs.encoded();
            r.certSelfSigOk = gost3410::verify(curve, Q, H(tbsDer.data(), tbsDer.size()), certSig);
        }

        // --- информация о подписанте ---
        asn1::Node si = asn1::children(signerInfos)[0];
        auto siKids = asn1::children(si);
        r.digestAlgOid = asn1::oidToString(asn1::children(siKids[2])[0]);
        asn1::Node attrsNode = siKids[3];
        if (attrsNode.tag != 0xA0) throw std::runtime_error("нет подписанных атрибутов");
        r.sigAlgOid = asn1::oidToString(asn1::children(siKids[4])[0]);
        if (r.digestAlgOid != OID_STREEBOG_256) throw std::runtime_error("хеш не Стрибог-256: " + r.digestAlgOid);
        for (const auto& attr : asn1::children(attrsNode)) {
            auto ak = asn1::children(attr);
            std::string o = asn1::oidToString(ak[0]);
            asn1::Node val = asn1::children(ak[1])[0];
            if (o == OID_ATTR_MSG_DIGEST) r.messageDigest = val.contentBytes();
            if (o == OID_ATTR_SIGN_TIME) r.signingTime = readableTime(val);
        }
        r.parsed = true;

        // --- хеш подписанных байтов PDF ---
        std::string signedPart = file.substr(a, b) + file.substr(c, d);
        r.computedDigest = H(reinterpret_cast<const uint8_t*>(signedPart.data()), signedPart.size());
        r.digestOk = !r.messageDigest.empty() && r.messageDigest == r.computedDigest;

        // --- подпись над атрибутами (тег [0] заменяется на SET) ---
        Bytes attrsDer = attrsNode.encoded();
        attrsDer[0] = asn1::SET;
        gost3410::Signature sig;
        if (gost3410::decodeSignature(siKids[5].contentBytes(), sig))
            r.signatureOk = gost3410::verify(curve, Q, H(attrsDer.data(), attrsDer.size()), sig);
    } catch (const std::exception& e) {
        r.error = e.what();
    }
    return r;
}

inline VerifyReport verifyPdfFile(const std::string& path, const HashFn& H) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { VerifyReport r; r.error = "не удалось открыть файл " + path; return r; }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return verifyPdfBytes(data, H);
}

} // namespace pdfsig
