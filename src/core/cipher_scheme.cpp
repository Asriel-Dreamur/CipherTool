#include "cipher_scheme.h"
#include "utils.h"
#include <sstream>
#include <stdexcept>
#include <cctype>

static std::string ExpandAlphabetCore(const std::string& input) {
    const std::string RUS = u8"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя";
    const std::string ENG = u8"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string result;
    std::istringstream iss(input);
    std::string token;
    while (std::getline(iss, token, '+')) {
        std::string clean;
        for (char c : token) if (!isspace((unsigned char)c)) clean += (char)tolower((unsigned char)c);
        if (clean == "rus") result += RUS;
        else if (clean == "eng") result += ENG;
        else result += token;
    }
    return result.empty() ? input : result;
}

std::string CipherScheme::serialize() const {
    std::stringstream ss;
    ss << "cipher " << name << " {\n";
    ss << "    version: " << version << "\n";
    if (!description.empty()) ss << "    description: \"" << description << "\"\n";
    std::string alph = originalAlphabet.empty() ? alphabet : originalAlphabet;
    if (!alph.empty()) ss << "    alphabet: \"" << alph << "\"\n";
    ss << "\n    steps:\n";
    for (const auto& step : steps) {
        ss << "        " << step->type_name();
        std::string params = step->serialize_params();
        if (!params.empty()) ss << " " << params;
        ss << "\n";
    }
    ss << "}\n";
    return ss.str();
}

CipherScheme CipherScheme::deserialize(const std::string& data) {
    CipherScheme scheme;
    std::istringstream stream(data);
    std::string line;
    bool in_steps = false;
    while (std::getline(stream, line)) {
        line = utils::trim(line);
        if (line.empty()) continue;
        if (utils::starts_with(line, "cipher ")) {
            auto brace = line.find('{');
            if (brace != std::string::npos) scheme.name = utils::trim(line.substr(7, brace-7));
            else scheme.name = utils::trim(line.substr(7));
        } else if (utils::starts_with(line, "version:")) scheme.version = std::stoi(line.substr(8));
        else if (utils::starts_with(line, "description:")) {
            auto val = utils::trim(line.substr(12));
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"') scheme.description = val.substr(1, val.size()-2);
        } else if (utils::starts_with(line, "alphabet:")) {
            auto val = utils::trim(line.substr(9));
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"') {
                std::string rawAlph = val.substr(1, val.size()-2);
                scheme.originalAlphabet = rawAlph;
                scheme.alphabet = ExpandAlphabetCore(rawAlph);   // <-- раскрытие при загрузке
            }
        } else if (utils::starts_with(line, "steps:")) { in_steps = true; continue; }
        else if (line == "}") break;
        else if (in_steps) {
            auto sp = line.find(' ');
            std::string type = (sp == std::string::npos) ? line : line.substr(0, sp);
            std::string pstr = (sp == std::string::npos) ? "" : utils::trim(line.substr(sp+1));
            std::map<std::string, std::string> params;
            if (!pstr.empty()) {
                size_t pos = 0;
                while (pos < pstr.size()) {
                    while (pos < pstr.size() && pstr[pos] == ' ') ++pos;
                    if (pos >= pstr.size()) break;
                    size_t eq = pstr.find('=', pos);
                    if (eq == std::string::npos) break;
                    std::string key = pstr.substr(pos, eq-pos);
                    pos = eq+1;
                    std::string value;
                    if (pos < pstr.size() && pstr[pos] == '"') {
                        size_t endq = pstr.find('"', pos+1);
                        value = pstr.substr(pos+1, endq-pos-1);
                        pos = endq+1;
                    } else {
                        size_t next = pstr.find(' ', pos);
                        if (next == std::string::npos) { value = pstr.substr(pos); pos = pstr.size(); }
                        else { value = pstr.substr(pos, next-pos); pos = next+1; }
                    }
                    params[key] = value;
                }
            }
            scheme.steps.push_back(StepFactory::create(type, params, scheme.alphabet));
        }
    }
    return scheme;
}