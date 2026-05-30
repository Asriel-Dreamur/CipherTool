#ifndef CIPHER_ENGINE_H
#define CIPHER_ENGINE_H
#include "cipher_scheme.h"
#include <string>

class CipherEngine {
    const CipherScheme& scheme_;
public:
    explicit CipherEngine(const CipherScheme& scheme) : scheme_(scheme) {}
    std::string encrypt(const std::string& plain) const;
    std::string decrypt(const std::string& cipher) const;
};

#endif