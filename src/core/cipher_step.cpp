#include "cipher_step.h"
#include "utils.h"
#include <stdexcept>
#include <sstream>
#include <numeric>
#include <algorithm>

// --- Caesar (символьный) ---
CaesarStep::CaesarStep(int shift, const std::string& alphabet) : shift_(shift) {
    alphabet_ = utils::split_utf8(alphabet);
}
std::string CaesarStep::encrypt(const std::string& input) const {
    if (alphabet_.empty()) {
        std::string result;
        for (unsigned char c : input) result += static_cast<unsigned char>((c + shift_) % 256);
        return result;
    }
    auto chars = utils::split_utf8(input);
    std::string result;
    for (const auto& c : chars) result += utils::shift_char(c, shift_, alphabet_);
    return result;
}
std::string CaesarStep::decrypt(const std::string& input) const {
    if (alphabet_.empty()) {
        std::string result;
        for (unsigned char c : input) result += static_cast<unsigned char>((c - shift_ + 256) % 256);
        return result;
    }
    auto chars = utils::split_utf8(input);
    std::string result;
    for (const auto& c : chars) result += utils::shift_char(c, -shift_, alphabet_);
    return result;
}
std::string CaesarStep::serialize_params() const { return "shift=" + std::to_string(shift_); }
std::map<std::string, std::string> CaesarStep::getParams() const { return {{"shift", std::to_string(shift_)}}; }
std::unique_ptr<ICipherStep> CaesarStep::clone() const { return std::make_unique<CaesarStep>(shift_, utils::join(alphabet_, "")); }
std::unique_ptr<ICipherStep> CaesarStep::from_params(const std::map<std::string, std::string>& p, const std::string& alphabet) {
    return std::make_unique<CaesarStep>(std::stoi(p.at("shift")), alphabet);
}

// --- Substitute (символьный) ---
SubstitutionStep::SubstitutionStep(const std::map<std::string, std::string>& mapping, const std::string& alphabet) {
    alphabet_ = utils::split_utf8(alphabet);
    encrypt_map_ = mapping;
    for (const auto& p : mapping) decrypt_map_[p.second] = p.first;
}
std::string SubstitutionStep::encrypt(const std::string& input) const {
    auto chars = utils::split_utf8(input);
    std::string result;
    for (const auto& c : chars) {
        auto it = encrypt_map_.find(c);
        result += (it != encrypt_map_.end()) ? it->second : c;
    }
    return result;
}
std::string SubstitutionStep::decrypt(const std::string& input) const {
    auto chars = utils::split_utf8(input);
    std::string result;
    for (const auto& c : chars) {
        auto it = decrypt_map_.find(c);
        result += (it != decrypt_map_.end()) ? it->second : c;
    }
    return result;
}
std::string SubstitutionStep::serialize_params() const {
    std::stringstream ss;
    ss << "map=\"";
    bool first = true;
    for (const auto& p : encrypt_map_) {
        if (!first) ss << ",";
        ss << p.first << "->" << p.second;
        first = false;
    }
    ss << "\"";
    return ss.str();
}
std::map<std::string, std::string> SubstitutionStep::getParams() const {
    return {{"map", serialize_params().substr(6, serialize_params().size()-7)}};
}
std::unique_ptr<ICipherStep> SubstitutionStep::clone() const {
    return std::make_unique<SubstitutionStep>(encrypt_map_, utils::join(alphabet_, ""));
}
std::unique_ptr<ICipherStep> SubstitutionStep::from_params(const std::map<std::string, std::string>& p, const std::string& alphabet) {
    std::map<std::string, std::string> mapping;
    std::string mapStr = p.at("map");
    if (mapStr.empty()) throw std::runtime_error("substitute: пустой параметр map");

    auto pairs = utils::split(mapStr, ',');
    for (const auto& pair_str : pairs) {
        auto arrowPos = pair_str.find("->");
        if (arrowPos == std::string::npos || arrowPos == 0 || arrowPos + 2 >= pair_str.size()) {
            throw std::runtime_error("substitute: неверный формат '" + pair_str + "'. Ожидается А->Б");
        }
        std::string from = pair_str.substr(0, arrowPos);
        std::string to   = pair_str.substr(arrowPos + 2);
        if (from.empty() || to.empty()) {
            throw std::runtime_error("substitute: пустая замена в '" + pair_str + "'");
        }
        mapping[from] = to;
    }
    if (mapping.empty()) throw std::runtime_error("substitute: нет допустимых замен");
    return std::make_unique<SubstitutionStep>(mapping, alphabet);
}

// --- Reverse (символьный) ---
std::string ReverseStep::encrypt(const std::string& input) const {
    auto chars = utils::split_utf8(input);
    std::reverse(chars.begin(), chars.end());
    return utils::join(chars, "");
}

// --- Xor (байтовый, не менялся) ---
XorStep::XorStep(const std::string& key) : key_(key) {}
std::string XorStep::encrypt(const std::string& input) const {
    std::string result = input;
    for (size_t i = 0; i < result.size(); ++i) result[i] ^= key_[i % key_.size()];
    return result;
}
std::string XorStep::serialize_params() const { return "key=\"" + key_ + "\""; }
std::map<std::string, std::string> XorStep::getParams() const { return {{"key", key_}}; }
std::unique_ptr<ICipherStep> XorStep::clone() const { return std::make_unique<XorStep>(key_); }
std::unique_ptr<ICipherStep> XorStep::from_params(const std::map<std::string, std::string>& p) {
    auto it = p.find("key");
    if (it == p.end() || it->second.empty()) throw std::runtime_error("xor: ключ не может быть пустым");
    return std::make_unique<XorStep>(it->second);
}

// --- Transpose (символьный) ---
TransposeStep::TransposeStep(const std::string& keyword) : keyword_(keyword) {}
std::string TransposeStep::encrypt(const std::string& input) const {
    if (keyword_.empty()) return input;
    auto chars = utils::split_utf8(input);
    auto keyChars = utils::split_utf8(keyword_);
    int cols = (int)keyChars.size();
    int rows = ((int)chars.size() + cols - 1) / cols;
    std::vector<std::vector<std::string>> table(rows, std::vector<std::string>(cols, ""));
    for (size_t i = 0; i < chars.size(); ++i) table[i / cols][i % cols] = chars[i];
    std::vector<int> order(cols);
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(), [&](int a, int b) {
        return keyChars[a] < keyChars[b] || (keyChars[a] == keyChars[b] && a < b);
    });
    std::string result;
    for (int idx : order)
        for (int r = 0; r < rows; ++r)
            if (!table[r][idx].empty()) result += table[r][idx];
    return result;
}
std::string TransposeStep::decrypt(const std::string& input) const {
    if (keyword_.empty()) return input;
    auto chars = utils::split_utf8(input);
    auto keyChars = utils::split_utf8(keyword_);
    int cols = (int)keyChars.size();
    int len = (int)chars.size();
    int rows = (len + cols - 1) / cols;
    std::vector<int> col_counts(cols, rows);
    int total_cells = rows * cols;
    int extra = total_cells - len;
    std::vector<int> order(cols);
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(), [&](int a, int b) {
        return keyChars[a] < keyChars[b] || (keyChars[a] == keyChars[b] && a < b);
    });
    for (int i = 0; i < extra; ++i) {
        int col_idx = order[cols - 1 - i];
        col_counts[col_idx]--;
    }
    std::vector<std::vector<std::string>> table(rows, std::vector<std::string>(cols, ""));
    size_t pos = 0;
    for (int oidx : order)
        for (int r = 0; r < col_counts[oidx]; ++r)
            table[r][oidx] = chars[pos++];
    std::string result;
    for (int r = 0; r < rows; ++r)
        for (int c = 0; c < cols; ++c)
            if (!table[r][c].empty()) result += table[r][c];
    return result;
}
std::string TransposeStep::serialize_params() const { return "keyword=\"" + keyword_ + "\""; }
std::map<std::string, std::string> TransposeStep::getParams() const { return {{"keyword", keyword_}}; }
std::unique_ptr<ICipherStep> TransposeStep::clone() const { return std::make_unique<TransposeStep>(keyword_); }
std::unique_ptr<ICipherStep> TransposeStep::from_params(const std::map<std::string, std::string>& p) {
    auto it = p.find("keyword");
    if (it == p.end() || it->second.empty()) throw std::runtime_error("transpose: ключевое слово не может быть пустым");
    return std::make_unique<TransposeStep>(it->second);
}

VigenereStep::VigenereStep(const std::string& key, const std::string& alphabet) : key_(key) {
    alphabet_ = utils::split_utf8(alphabet);
}
std::string VigenereStep::encrypt(const std::string& input) const {
    if (alphabet_.empty()) {
        std::string result;
        for (size_t i = 0; i < input.size(); ++i) {
            unsigned char c = input[i];
            unsigned char k = key_[i % key_.size()];
            result += static_cast<unsigned char>((c + k) % 256);
        }
        return result;
    }

    auto chars = utils::split_utf8(input);
    auto keyChars = utils::split_utf8(key_);
    if (keyChars.empty()) return input;

    std::string result;
    size_t key_idx = 0;

    for (const auto& c : chars) {
        int charIndex = utils::index_of(c, alphabet_);
        if (charIndex != -1) {
            const std::string& keyChar = keyChars[key_idx % keyChars.size()];
            int keyShift = utils::index_of(keyChar, alphabet_);
            if (keyShift < 0) {
                result += c;                   
            } else {
                result += utils::shift_char(c, keyShift, alphabet_);
                ++key_idx;                    
            }
        } else {
            result += c;                       
        }
    }
    return result;
}

std::string VigenereStep::decrypt(const std::string& input) const {
    if (alphabet_.empty()) {
        std::string result;
        for (size_t i = 0; i < input.size(); ++i) {
            unsigned char c = input[i];
            unsigned char k = key_[i % key_.size()];
            result += static_cast<unsigned char>((c - k + 256) % 256);
        }
        return result;
    }

    auto chars = utils::split_utf8(input);
    auto keyChars = utils::split_utf8(key_);
    if (keyChars.empty()) return input;

    std::string result;
    size_t key_idx = 0;

    for (const auto& c : chars) {
        int charIndex = utils::index_of(c, alphabet_);
        if (charIndex != -1) {
            const std::string& keyChar = keyChars[key_idx % keyChars.size()];
            int keyShift = utils::index_of(keyChar, alphabet_);
            if (keyShift < 0) {
                result += c;
            } else {
                result += utils::shift_char(c, -keyShift, alphabet_);
                ++key_idx;
            }
        } else {
            result += c;
        }
    }
    return result;
}
std::string VigenereStep::serialize_params() const { return "key=\"" + key_ + "\""; }
std::map<std::string, std::string> VigenereStep::getParams() const { return {{"key", key_}}; }
std::unique_ptr<ICipherStep> VigenereStep::clone() const { return std::make_unique<VigenereStep>(key_, utils::join(alphabet_, "")); }
std::unique_ptr<ICipherStep> VigenereStep::from_params(const std::map<std::string, std::string>& p, const std::string& alphabet) {
    auto it = p.find("key");
    if (it == p.end() || it->second.empty()) throw std::runtime_error("vigenere: ключ не может быть пустым");
    return std::make_unique<VigenereStep>(it->second, alphabet);
}

// --- Factory ---
std::unique_ptr<ICipherStep> StepFactory::create(const std::string& type,
                                                 const std::map<std::string, std::string>& params,
                                                 const std::string& alphabet) {
    if (type == "caesar") return CaesarStep::from_params(params, alphabet);
    if (type == "substitute") return SubstitutionStep::from_params(params, alphabet);
    if (type == "reverse") return std::make_unique<ReverseStep>();
    if (type == "xor") return XorStep::from_params(params);
    if (type == "transpose") return TransposeStep::from_params(params);
    if (type == "vigenere") return VigenereStep::from_params(params, alphabet);
    throw std::runtime_error("Unknown step type: " + type);
}