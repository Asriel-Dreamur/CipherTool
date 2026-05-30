#ifndef UTILS_H
#define UTILS_H
#include <string>
#include <vector>

namespace utils {
    std::string trim(const std::string& s);
    std::vector<std::string> split(const std::string& s, char delim);
    bool starts_with(const std::string& s, const std::string& prefix);
    std::string join(const std::vector<std::string>& parts, const std::string& delimiter);
    std::string to_upper(const std::string& s);
    std::vector<std::string> split_utf8(const std::string& utf8);
    std::string shift_char(const std::string& ch, int shift, const std::vector<std::string>& alphabet);
    int index_of(const std::string& ch, const std::vector<std::string>& alphabet);
}

#endif