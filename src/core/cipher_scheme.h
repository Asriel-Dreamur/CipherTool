#ifndef CIPHER_SCHEME_H
#define CIPHER_SCHEME_H
#include <string>
#include <vector>
#include <memory>
#include "cipher_step.h"

struct CipherScheme {
    std::string name;
    int version = 1;
    std::string description;
    std::string alphabet;         // расширенный
    std::string originalAlphabet; // как ввёл пользователь
    std::vector<std::unique_ptr<ICipherStep>> steps;

    CipherScheme(const CipherScheme&) = delete;
    CipherScheme& operator=(const CipherScheme&) = delete;
    CipherScheme(CipherScheme&&) = default;
    CipherScheme& operator=(CipherScheme&&) = default;
    CipherScheme() = default;

    std::string serialize() const;
    static CipherScheme deserialize(const std::string& data);
};

#endif