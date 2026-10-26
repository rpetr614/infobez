// pdf_writer.hpp
// Минимальный генератор PDF без внешних библиотек, с поддержкой кириллицы.
//
// Как это работает: стандартные 14 шрифтов PDF не содержат кириллицы,
// поэтому в документ встраивается TrueType-шрифт из системы (на macOS —
// Arial / Courier New). Шрифт подключается как составной (Type0,
// кодировка Identity-H): в тексте пишутся не коды символов, а номера
// глифов (GID), которые мы находим сами, разбирая таблицу 'cmap' шрифта.
// Для каждого шрифта добавляется CMap ToUnicode, поэтому текст из PDF
// можно выделять, копировать и искать.
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace pdf {

// ------------------------------------------------------------
// UTF-8 -> кодовые точки Unicode
// ------------------------------------------------------------
inline std::vector<uint32_t> utf8Decode(const std::string& s) {
    std::vector<uint32_t> out;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        uint32_t cp; int n;
        if (c < 0x80) { cp = c; n = 1; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; n = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; n = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; n = 4; }
        else { out.push_back(0xFFFD); i++; continue; }
        if (i + n > s.size()) { out.push_back(0xFFFD); break; }
        bool ok = true;
        for (int k = 1; k < n; k++) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (!ok) { out.push_back(0xFFFD); i++; continue; }
        out.push_back(cp);
        i += n;
    }
    return out;
}

inline std::string utf8Encode(const std::vector<uint32_t>& cps) {
    std::string s;
    for (uint32_t cp : cps) {
        if (cp < 0x80) s += static_cast<char>(cp);
        else if (cp < 0x800) { s += static_cast<char>(0xC0 | (cp >> 6)); s += static_cast<char>(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) {
            s += static_cast<char>(0xE0 | (cp >> 12)); s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            s += static_cast<char>(0xF0 | (cp >> 18)); s += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); s += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return s;
}

// Эмодзи и служебные символы эмодзи-последовательностей (в PDF не выводятся)
inline bool isEmoji(uint32_t cp) {
    return (cp >= 0x1F000 && cp <= 0x1FFFF) ||   // смайлы, пиктограммы, транспорт, флаги, карты и т.п.
           (cp >= 0x2600 && cp <= 0x27BF)   ||   // разные символы и «дингбаты»
           (cp >= 0x2B00 && cp <= 0x2BFF)   ||   // звёзды, квадраты, стрелки-эмодзи
           (cp >= 0x231A && cp <= 0x231B)   || (cp >= 0x23E9 && cp <= 0x23FA) ||   // часы, кнопки
           (cp >= 0xFE00 && cp <= 0xFE0F)   ||   // селекторы вариантов (U+FE0F — «эмодзи-стиль»)
           (cp >= 0xE0000 && cp <= 0xE007F) ||   // теги (флаги регионов)
           cp == 0x200D || cp == 0x20E3 ||       // соединитель ZWJ, «клавиша»
           cp == 0x3030 || cp == 0x303D || cp == 0x3297 || cp == 0x3299;
}

inline std::vector<uint32_t> filterEmoji(const std::vector<uint32_t>& cps, size_t* removed = nullptr) {
    std::vector<uint32_t> out;
    size_t n = 0;
    for (uint32_t cp : cps) { if (isEmoji(cp)) n++; else out.push_back(cp); }
    if (removed) *removed = n;
    return out;
}

// Удаляет эмодзи из UTF-8 строки; removed — сколько символов удалено
// (составной эмодзи, например флаг или «семья», считается по частям, без
// служебных ZWJ/селекторов).
inline std::string stripEmoji(const std::string& utf8, size_t& removed) {
    std::vector<uint32_t> cps = utf8Decode(utf8);
    size_t visible = 0;
    std::vector<uint32_t> out;
    for (uint32_t cp : cps) {
        if (!isEmoji(cp)) { out.push_back(cp); continue; }
        if (cp != 0x200D && !(cp >= 0xFE00 && cp <= 0xFE0F) && !(cp >= 0xE0000 && cp <= 0xE007F)) visible++;
    }
    removed = visible;
    return utf8Encode(out);
}

// ------------------------------------------------------------
// Разбор TrueType-шрифта (только то, что нужно для встраивания)
// ------------------------------------------------------------
class TrueTypeFont {
public:
    bool load(const std::string& path, std::string& err) {
        std::ifstream in(path, std::ios::binary);
        if (!in) { err = "не удалось открыть " + path; return false; }
        data_.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        if (data_.size() < 12) { err = "слишком маленький файл шрифта"; return false; }
        uint32_t ver = u32(0);
        if (ver != 0x00010000 && ver != 0x74727565 /*'true'*/) {
            err = "поддерживаются только TrueType-шрифты (.ttf с контурами glyf)"; return false;
        }
        uint16_t numTables = u16(4);
        for (uint16_t i = 0; i < numTables; i++) {
            size_t rec = 12 + 16 * static_cast<size_t>(i);
            if (rec + 16 > data_.size()) break;
            std::string tag(reinterpret_cast<const char*>(&data_[rec]), 4);
            tables_[tag] = {u32(rec + 8), u32(rec + 12)};
        }
        for (const char* t : {"head", "hhea", "hmtx", "maxp", "cmap", "glyf"}) {
            if (!tables_.count(t)) { err = std::string("в шрифте нет таблицы ") + t; return false; }
        }
        size_t head = tables_["head"].first, hhea = tables_["hhea"].first;
        unitsPerEm_ = u16(head + 18);
        bbox_[0] = s16(head + 36); bbox_[1] = s16(head + 38);
        bbox_[2] = s16(head + 40); bbox_[3] = s16(head + 42);
        ascent_ = s16(hhea + 4);
        descent_ = s16(hhea + 6);
        numHMetrics_ = u16(hhea + 34);
        numGlyphs_ = u16(tables_["maxp"].first + 4);
        if (!parseCmap()) { err = "не найдена подходящая Unicode-таблица cmap"; return false; }
        return true;
    }

    uint16_t glyph(uint32_t cp) const {
        auto it = cmap_.find(cp);
        return it == cmap_.end() ? 0 : it->second;
    }
    bool hasGlyph(uint32_t cp) const { return cmap_.count(cp) != 0; }
    // Ширина глифа в единицах 1/1000 кегля (как требует PDF)
    int width1000(uint16_t gid) const {
        size_t hmtx = tables_.at("hmtx").first;
        uint16_t idx = gid < numHMetrics_ ? gid : static_cast<uint16_t>(numHMetrics_ - 1);
        uint16_t adv = u16(hmtx + 4 * static_cast<size_t>(idx));
        return static_cast<int>(adv * 1000L / unitsPerEm_);
    }
    const std::vector<uint8_t>& bytes() const { return data_; }
    int ascent1000() const  { return static_cast<int>(ascent_ * 1000L / unitsPerEm_); }
    int descent1000() const { return static_cast<int>(descent_ * 1000L / unitsPerEm_); }
    int bbox1000(int i) const { return static_cast<int>(bbox_[i] * 1000L / unitsPerEm_); }

private:
    std::vector<uint8_t> data_;
    std::map<std::string, std::pair<uint32_t, uint32_t>> tables_;
    std::map<uint32_t, uint16_t> cmap_;
    uint16_t unitsPerEm_ = 1000, numHMetrics_ = 1, numGlyphs_ = 0;
    int16_t ascent_ = 800, descent_ = -200, bbox_[4] = {0, 0, 0, 0};

    uint16_t u16(size_t o) const { return o + 2 <= data_.size() ? static_cast<uint16_t>((data_[o] << 8) | data_[o + 1]) : 0; }
    int16_t  s16(size_t o) const { return static_cast<int16_t>(u16(o)); }
    uint32_t u32(size_t o) const { return (static_cast<uint32_t>(u16(o)) << 16) | u16(o + 2); }

    bool parseCmap() {
        size_t cmap = tables_["cmap"].first;
        uint16_t n = u16(cmap + 2);
        size_t best4 = 0, best12 = 0;
        for (uint16_t i = 0; i < n; i++) {
            size_t rec = cmap + 4 + 8 * static_cast<size_t>(i);
            uint16_t pid = u16(rec), eid = u16(rec + 2);
            size_t sub = cmap + u32(rec + 4);
            uint16_t fmt = u16(sub);
            bool unicode = (pid == 0) || (pid == 3 && (eid == 1 || eid == 10));
            if (!unicode) continue;
            if (fmt == 12 && !best12) best12 = sub;
            if (fmt == 4 && !best4) best4 = sub;
        }
        if (best12) {
            uint32_t groups = u32(best12 + 12);
            for (uint32_t g = 0; g < groups; g++) {
                size_t r = best12 + 16 + 12 * static_cast<size_t>(g);
                uint32_t start = u32(r), end = u32(r + 4), gid = u32(r + 8);
                if (end - start > 0x10FFFF) continue;
                for (uint32_t c = start; c <= end; c++) {
                    uint32_t gg = gid + (c - start);
                    if (gg != 0 && gg < numGlyphs_) cmap_[c] = static_cast<uint16_t>(gg);
                }
            }
            return !cmap_.empty();
        }
        if (best4) {
            uint16_t segX2 = u16(best4 + 6);
            size_t ends = best4 + 14, starts = ends + segX2 + 2, deltas = starts + segX2, ranges = deltas + segX2;
            for (uint16_t s = 0; s < segX2 / 2; s++) {
                uint16_t end = u16(ends + 2 * s), start = u16(starts + 2 * s);
                int16_t delta = s16(deltas + 2 * s);
                uint16_t ro = u16(ranges + 2 * s);
                for (uint32_t c = start; c <= end && c != 0xFFFF; c++) {
                    uint16_t g;
                    if (ro == 0) g = static_cast<uint16_t>(c + delta);
                    else {
                        size_t addr = ranges + 2 * s + ro + 2 * (c - start);
                        g = u16(addr);
                        if (g) g = static_cast<uint16_t>(g + delta);
                    }
                    if (g != 0 && g < numGlyphs_) cmap_[c] = g;
                }
            }
            return !cmap_.empty();
        }
        return false;
    }
};

// ------------------------------------------------------------
// Документ
// ------------------------------------------------------------
struct Color { double r, g, b; };
static const Color BLACK{0, 0, 0}, GRAY{0.42, 0.42, 0.45}, ACCENT{0.12, 0.30, 0.55},
                   GREEN{0.10, 0.45, 0.20}, RED{0.70, 0.12, 0.12};

class Document {
public:
    static constexpr double PAGE_W = 595.28, PAGE_H = 841.89;   // A4
    static constexpr double MARGIN_X = 50, MARGIN_TOP = 56, MARGIN_BOTTOM = 56;

    // Добавить шрифт; возвращает его номер (0 — основной)
    int addFont(const std::string& path, std::string& err) {
        Font f;
        if (!f.ttf.load(path, err)) return -1;
        f.path = path;
        fonts_.push_back(std::move(f));
        return static_cast<int>(fonts_.size()) - 1;
    }
    size_t fontCount() const { return fonts_.size(); }

    void setFooterLeft(const std::string& s) { footerLeft_ = s; }

    // Абзац с переносом по словам (длинные «слова», например hex-строки,
    // переносятся посимвольно). Явные '\n' сохраняются.
    void paragraph(const std::string& utf8, double size, int font = 0, Color color = BLACK,
                   double indent = 0, double lineGap = 1.3) {
        ensurePage();
        double maxW = PAGE_W - 2 * MARGIN_X - indent;
        std::vector<uint32_t> cps = filterEmoji(utf8Decode(utf8));   // эмодзи в PDF не выводим
        std::vector<std::vector<uint32_t>> lines;
        std::vector<uint32_t> cur;
        double curW = 0;
        size_t i = 0;
        while (i <= cps.size()) {
            if (i == cps.size() || cps[i] == '\n') {
                lines.push_back(cur); cur.clear(); curW = 0;
                if (i == cps.size()) break;
                i++; continue;
            }
            // следующее «слово» (до пробела или перевода строки включительно пробел)
            size_t j = i;
            while (j < cps.size() && cps[j] != ' ' && cps[j] != '\n') j++;
            size_t wordEnd = j;
            if (j < cps.size() && cps[j] == ' ') j++;
            std::vector<uint32_t> word(cps.begin() + i, cps.begin() + j);
            double ww = width(word, font, size);
            double wwNoSpace = width(std::vector<uint32_t>(cps.begin() + i, cps.begin() + wordEnd), font, size);
            if (curW + wwNoSpace <= maxW) {
                cur.insert(cur.end(), word.begin(), word.end()); curW += ww;
            } else if (wwNoSpace <= maxW && !cur.empty()) {
                lines.push_back(cur); cur = word; curW = ww;
            } else {
                for (uint32_t cp : word) {          // посимвольный перенос
                    double cw = width({cp}, font, size);
                    if (curW + cw > maxW && !cur.empty()) { lines.push_back(cur); cur.clear(); curW = 0; }
                    cur.push_back(cp); curW += cw;
                }
            }
            i = j;
        }
        for (auto& l : lines) {
            while (!l.empty() && l.back() == ' ') l.pop_back();
            double lh = size * lineGap;
            if (y_ - lh < MARGIN_BOTTOM) newPage();
            y_ -= lh;
            emitLine(l, font, size, color, MARGIN_X + indent, y_ + size * 0.25);
        }
    }

    // Предформатированный текст (ASCII-таблицы): строки выводятся как есть,
    // без переноса. Если самая длинная строка не помещается по ширине,
    // кегль уменьшается пропорционально. Таблица, помещающаяся на
    // страницу, не разрывается.
    void preformatted(const std::vector<std::string>& lines, double size, int font = 0, Color color = BLACK,
                      double lineGap = 1.2) {
        ensurePage();
        std::vector<std::vector<uint32_t>> cpLines;
        double widest = 0;
        for (const auto& l : lines) {
            cpLines.push_back(filterEmoji(utf8Decode(l)));
            widest = std::max(widest, width(cpLines.back(), font, size));
        }
        double maxW = PAGE_W - 2 * MARGIN_X;
        if (widest > maxW) size *= maxW / widest;
        double lh = size * lineGap;
        double total = lh * cpLines.size();
        if (total < PAGE_H - MARGIN_TOP - MARGIN_BOTTOM) keepTogether(total);
        for (const auto& l : cpLines) {
            if (y_ - lh < MARGIN_BOTTOM) newPage();
            y_ -= lh;
            emitLine(l, font, size, color, MARGIN_X, y_ + size * 0.25);
        }
    }

    void space(double pts) { ensurePage(); y_ -= pts; if (y_ < MARGIN_BOTTOM) newPage(); }

    void rule(Color c = GRAY, double w = 0.5) {
        ensurePage();
        y_ -= 4;
        std::ostringstream os;
        os << fmt(c.r) << ' ' << fmt(c.g) << ' ' << fmt(c.b) << " RG " << fmt(w) << " w "
           << fmt(MARGIN_X) << ' ' << fmt(y_) << " m " << fmt(PAGE_W - MARGIN_X) << ' ' << fmt(y_) << " l S\n";
        pages_.back() += os.str();
        y_ -= 6;
    }

    // Гарантирует, что до низа страницы осталось хотя бы h пунктов
    void keepTogether(double h) { ensurePage(); if (y_ - h < MARGIN_BOTTOM) newPage(); }

    bool save(const std::string& path, std::string& err) {
        if (fonts_.empty()) { err = "не задан шрифт"; return false; }
        ensurePage();
        // Колонтитулы: номер страницы считаем в конце, когда известно их число
        for (size_t p = 0; p < pages_.size(); p++) {
            std::string right = "Страница " + std::to_string(p + 1) + " из " + std::to_string(pages_.size());
            std::string saved; std::swap(saved, pages_[p]);
            emitLineTo(saved, utf8Decode(footerLeft_), 0, 8, GRAY, MARGIN_X, 30);
            auto rcp = utf8Decode(right);
            emitLineTo(saved, rcp, 0, 8, GRAY, PAGE_W - MARGIN_X - width(rcp, 0, 8), 30);
            pages_[p] = saved;
        }

        std::vector<std::string> objs;   // objs[i] = тело объекта i+1
        auto add = [&](const std::string& body) { objs.push_back(body); return static_cast<int>(objs.size()); };
        auto reserve = [&]() { objs.emplace_back(); return static_cast<int>(objs.size()); };

        int catalogId = reserve();
        int pagesId = reserve();

        // Шрифты
        std::vector<int> fontObjIds;
        for (size_t fi = 0; fi < fonts_.size(); fi++) {
            Font& f = fonts_[fi];
            const auto& bytes = f.ttf.bytes();
            std::string fontFile = "<< /Length " + std::to_string(bytes.size()) +
                                   " /Length1 " + std::to_string(bytes.size()) + " >>\nstream\n" +
                                   std::string(bytes.begin(), bytes.end()) + "\nendstream";
            int fileId = add(fontFile);
            std::string psName = "EmbeddedFont" + std::to_string(fi);
            std::ostringstream fd;
            fd << "<< /Type /FontDescriptor /FontName /" << psName << " /Flags 32"
               << " /FontBBox [" << f.ttf.bbox1000(0) << ' ' << f.ttf.bbox1000(1) << ' '
               << f.ttf.bbox1000(2) << ' ' << f.ttf.bbox1000(3) << "]"
               << " /ItalicAngle 0 /Ascent " << f.ttf.ascent1000() << " /Descent " << f.ttf.descent1000()
               << " /CapHeight " << f.ttf.ascent1000() << " /StemV 80 /FontFile2 " << fileId << " 0 R >>";
            int fdId = add(fd.str());

            std::ostringstream w;
            w << "[";
            for (auto& kv : f.used) w << kv.first << " [" << f.ttf.width1000(kv.first) << "] ";
            w << "]";
            std::ostringstream cid;
            cid << "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /" << psName
                << " /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>"
                << " /FontDescriptor " << fdId << " 0 R /DW 1000 /W " << w.str()
                << " /CIDToGIDMap /Identity >>";
            int cidId = add(cid.str());

            std::string cmap = toUnicodeCMap(f.used);
            int tuId = add("<< /Length " + std::to_string(cmap.size()) + " >>\nstream\n" + cmap + "\nendstream");

            std::ostringstream t0;
            t0 << "<< /Type /Font /Subtype /Type0 /BaseFont /" << psName
               << " /Encoding /Identity-H /DescendantFonts [" << cidId << " 0 R] /ToUnicode " << tuId << " 0 R >>";
            fontObjIds.push_back(add(t0.str()));
        }
        std::ostringstream fontRes;
        fontRes << "<< ";
        for (size_t fi = 0; fi < fontObjIds.size(); fi++) fontRes << "/F" << fi << ' ' << fontObjIds[fi] << " 0 R ";
        fontRes << ">>";

        // Электронная подпись: словарь /Sig с заполнителями /ByteRange и
        // /Contents, невидимое поле подписи (виджет) на первой странице.
        int sigId = 0, widgetId = 0;
        const std::string BR_PLACEHOLDER = "/ByteRange [0 0000000000 0000000000 0000000000]";
        if (sig_.signer) {
            std::ostringstream sd;
            sd << "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached " << BR_PLACEHOLDER
               << " /Contents <" << std::string(sig_.reserveBytes * 2, '0') << ">"
               << " /M (" << pdfDate(sig_.when) << ") /Name " << pdfTextString(sig_.name)
               << " /Reason " << pdfTextString(sig_.reason) << " /Location " << pdfTextString(sig_.location)
               << " /ContactInfo " << pdfTextString(sig_.contact) << " >>";
            sigId = add(sd.str());
            widgetId = reserve();
        }

        std::vector<int> pageIds;
        for (size_t pi = 0; pi < pages_.size(); pi++) {
            const auto& content = pages_[pi];
            int contentId = add("<< /Length " + std::to_string(content.size()) + " >>\nstream\n" + content + "\nendstream");
            std::ostringstream pg;
            pg << "<< /Type /Page /Parent " << pagesId << " 0 R /MediaBox [0 0 " << fmt(PAGE_W) << ' ' << fmt(PAGE_H)
               << "] /Resources << /Font " << fontRes.str() << " >> /Contents " << contentId << " 0 R";
            if (sigId && pi == 0) pg << " /Annots [" << widgetId << " 0 R]";
            pg << " >>";
            pageIds.push_back(add(pg.str()));
        }
        std::ostringstream kids;
        for (int id : pageIds) kids << id << " 0 R ";
        objs[pagesId - 1] = "<< /Type /Pages /Kids [" + kids.str() + "] /Count " + std::to_string(pageIds.size()) + " >>";
        if (sigId) {
            objs[widgetId - 1] = "<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 0 0] /F 132 /T " +
                                 pdfTextString("Подпись ГОСТ Р 34.10-2012") + " /V " + std::to_string(sigId) +
                                 " 0 R /P " + std::to_string(pageIds[0]) + " 0 R >>";
            objs[catalogId - 1] = "<< /Type /Catalog /Pages " + std::to_string(pagesId) + " 0 R /AcroForm << /Fields [" +
                                  std::to_string(widgetId) + " 0 R] /SigFlags 3 >> >>";
        } else {
            objs[catalogId - 1] = "<< /Type /Catalog /Pages " + std::to_string(pagesId) + " 0 R >>";
        }
        int infoId = add("<< /Producer " + pdfTextString("infobez auth3fa") +
                         " /Title " + pdfTextString(title_) + " >>");

        std::string out = "%PDF-1.7\n%\xE2\xE3\xCF\xD3\n";
        std::vector<size_t> offsets;
        for (size_t i = 0; i < objs.size(); i++) {
            offsets.push_back(out.size());
            out += std::to_string(i + 1) + " 0 obj\n" + objs[i] + "\nendobj\n";
        }
        size_t xref = out.size();
        out += "xref\n0 " + std::to_string(objs.size() + 1) + "\n0000000000 65535 f \n";
        char buf[32];
        for (size_t off : offsets) { std::snprintf(buf, sizeof buf, "%010zu 00000 n \n", off); out += buf; }
        out += "trailer\n<< /Size " + std::to_string(objs.size() + 1) + " /Root " + std::to_string(catalogId) +
               " 0 R /Info " + std::to_string(infoId) + " 0 R >>\nstartxref\n" + std::to_string(xref) + "\n%%EOF\n";

        if (sigId) {
            // Находим заполнители в словаре подписи и вычисляем /ByteRange:
            // подписывается весь файл, кроме значения /Contents <...>.
            size_t objStart = offsets[sigId - 1];
            size_t brPos = out.find(BR_PLACEHOLDER, objStart);
            size_t lt = out.find("/Contents <", objStart) + 10;          // позиция '<'
            size_t gt = out.find('>', lt);                               // позиция '>'
            if (brPos == std::string::npos || gt == std::string::npos) { err = "внутренняя ошибка разметки подписи"; return false; }
            size_t a = 0, b = lt, c = gt + 1, d = out.size() - c;
            char br[96];
            std::snprintf(br, sizeof br, "/ByteRange [%zu %zu %zu %zu]", a, b, c, d);
            std::string brs = br;
            if (brs.size() > BR_PLACEHOLDER.size()) { err = "файл слишком большой для /ByteRange"; return false; }
            brs += std::string(BR_PLACEHOLDER.size() - brs.size(), ' ');
            out.replace(brPos, BR_PLACEHOLDER.size(), brs);

            std::string signedPart = out.substr(a, b) + out.substr(c, d);
            std::vector<uint8_t> cms;
            try { cms = sig_.signer(signedPart); }
            catch (const std::exception& e) { err = std::string("ошибка подписи: ") + e.what(); return false; }
            if (cms.size() > sig_.reserveBytes) { err = "подпись не помещается в зарезервированное место"; return false; }
            static const char* hx = "0123456789ABCDEF";
            for (size_t i = 0; i < cms.size(); i++) {
                out[lt + 1 + 2 * i] = hx[cms[i] >> 4];
                out[lt + 2 + 2 * i] = hx[cms[i] & 15];
            }
            signedBytes_ = b + d;
            byteRange_[0] = a; byteRange_[1] = b; byteRange_[2] = c; byteRange_[3] = d;
        }

        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) { err = "не удалось создать файл " + path; return false; }
        f.write(out.data(), static_cast<std::streamsize>(out.size()));
        return static_cast<bool>(f);
    }

    void setTitle(const std::string& t) { title_ = t; }

    // Электронная подпись документа. signer получает подписываемые байты
    // файла (всё, кроме значения /Contents) и возвращает DER-контейнер CMS.
    struct SignatureRequest {
        std::string name, reason, location, contact;
        time_t when = 0;
        size_t reserveBytes = 8192;   // место под CMS (сертификат + подпись ~1 КБ)
        std::function<std::vector<uint8_t>(const std::string&)> signer;
    };
    void setSignature(const SignatureRequest& s) { sig_ = s; }
    size_t signedBytes() const { return signedBytes_; }
    const size_t* byteRange() const { return byteRange_; }

private:
    struct Font {
        std::string path;
        TrueTypeFont ttf;
        std::map<uint16_t, uint32_t> used;   // GID -> Unicode (для ToUnicode и /W)
    };
    std::vector<Font> fonts_;
    std::vector<std::string> pages_;
    double y_ = 0;
    std::string footerLeft_, title_ = "Report";
    SignatureRequest sig_;
    size_t signedBytes_ = 0, byteRange_[4] = {0, 0, 0, 0};

    // Дата в формате PDF: D:ГГГГММДДччммсс+00'00' (UTC)
    static std::string pdfDate(time_t t) {
        std::tm tm{};
#ifdef _WIN32
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        char b[40];
        std::strftime(b, sizeof b, "D:%Y%m%d%H%M%S+00'00'", &tm);
        return b;
    }

    static std::string fmt(double v) {
        char b[32]; std::snprintf(b, sizeof b, "%.2f", v); return b;
    }

    void ensurePage() { if (pages_.empty()) newPage(); }
    void newPage() { pages_.emplace_back(); y_ = PAGE_H - MARGIN_TOP; }

    double width(const std::vector<uint32_t>& cps, int font, double size) {
        double w = 0;
        for (uint32_t cp : cps) w += fonts_[font].ttf.width1000(glyphFor(cp, font));
        return w * size / 1000.0;
    }
    uint16_t glyphFor(uint32_t cp, int font) {
        const auto& t = fonts_[font].ttf;
        if (t.hasGlyph(cp)) return t.glyph(cp);
        if (t.hasGlyph('?')) return t.glyph('?');
        return 0;
    }

    void emitLine(const std::vector<uint32_t>& cps, int font, double size, Color c, double x, double y) {
        emitLineTo(pages_.back(), cps, font, size, c, x, y);
    }
    void emitLineTo(std::string& page, const std::vector<uint32_t>& cps, int font, double size,
                    Color c, double x, double y) {
        if (cps.empty()) return;
        std::ostringstream os;
        os << "BT " << fmt(c.r) << ' ' << fmt(c.g) << ' ' << fmt(c.b) << " rg /F" << font << ' ' << fmt(size)
           << " Tf " << fmt(x) << ' ' << fmt(y) << " Td <";
        char b[8];
        for (uint32_t cp : cps) {
            uint16_t g = glyphFor(cp, font);
            uint32_t uni = fonts_[font].ttf.hasGlyph(cp) ? cp : '?';
            fonts_[font].used.emplace(g, uni);
            std::snprintf(b, sizeof b, "%04X", g);
            os << b;
        }
        os << "> Tj ET\n";
        page += os.str();
    }

    static std::string utf16Hex(uint32_t cp) {
        char b[16];
        if (cp < 0x10000) { std::snprintf(b, sizeof b, "%04X", cp); return b; }
        cp -= 0x10000;
        std::snprintf(b, sizeof b, "%04X%04X", 0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
        return b;
    }
    static std::string toUnicodeCMap(const std::map<uint16_t, uint32_t>& used) {
        std::ostringstream os;
        os << "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
           << "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
           << "/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n"
           << "1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n";
        std::vector<std::pair<uint16_t, uint32_t>> v(used.begin(), used.end());
        for (size_t i = 0; i < v.size(); i += 100) {
            size_t n = std::min<size_t>(100, v.size() - i);
            os << n << " beginbfchar\n";
            char b[8];
            for (size_t k = i; k < i + n; k++) {
                std::snprintf(b, sizeof b, "%04X", v[k].first);
                os << '<' << b << "> <" << utf16Hex(v[k].second) << ">\n";
            }
            os << "endbfchar\n";
        }
        os << "endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend";
        return os.str();
    }
    // Строка для словаря /Info в UTF-16BE с BOM (чтобы кириллица в свойствах документа читалась)
    static std::string pdfTextString(const std::string& utf8) {
        std::string s = "<FEFF";
        for (uint32_t cp : utf8Decode(utf8)) s += utf16Hex(cp);
        return s + ">";
    }
};

} // namespace pdf
