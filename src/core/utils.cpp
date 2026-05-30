#include "utils.h"
#include <sstream>
#include <algorithm>

namespace utils {

    std::string trim(const std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    std::vector<std::string> split(const std::string& s, char delim) {
        std::vector<std::string> tokens;
        std::stringstream ss(s);
        std::string token;
        while (std::getline(ss, token, delim)) tokens.push_back(trim(token));
        return tokens;
    }

    bool starts_with(const std::string& s, const std::string& prefix) {
        return s.rfind(prefix, 0) == 0;
    }

    std::string join(const std::vector<std::string>& parts, const std::string& delimiter) {
        if (parts.empty()) return "";
        std::string result = parts[0];
        for (size_t i = 1; i < parts.size(); ++i) result += delimiter + parts[i];
        return result;
    }

    std::string to_upper(const std::string& s) {
        std::string r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::toupper);
        return r;
    }

    std::vector<std::string> split_utf8(const std::string& utf8) {
        std::vector<std::string> chars;
        size_t i = 0;
        while (i < utf8.size()) {
            unsigned char c = utf8[i];
            size_t len = 1;
            if ((c & 0x80) == 0) len = 1;
            else if ((c & 0xE0) == 0xC0) len = 2;
            else if ((c & 0xF0) == 0xE0) len = 3;
            else if ((c & 0xF8) == 0xF0) len = 4;
            chars.push_back(utf8.substr(i, len));
            i += len;
        }
        return chars;
    }

    int index_of(const std::string& ch, const std::vector<std::string>& alphabet) {
        for (size_t i = 0; i < alphabet.size(); ++i)
            if (alphabet[i] == ch) return (int)i;
        return -1;
    }

    std::string shift_char(const std::string& ch, int shift, const std::vector<std::string>& alphabet) {
        int idx = index_of(ch, alphabet);
        if (idx == -1) return ch;
        int new_idx = (idx + shift) % (int)alphabet.size();
        if (new_idx < 0) new_idx += (int)alphabet.size();
        return alphabet[new_idx];
    }

}