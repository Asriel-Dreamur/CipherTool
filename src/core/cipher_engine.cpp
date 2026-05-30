#include "cipher_engine.h"

std::string CipherEngine::encrypt(const std::string& plain) const {
    std::string data = plain;
    for (const auto& step : scheme_.steps) data = step->encrypt(data);
    return data;
}

std::string CipherEngine::decrypt(const std::string& cipher) const {
    std::string data = cipher;
    for (auto it = scheme_.steps.rbegin(); it != scheme_.steps.rend(); ++it) data = (*it)->decrypt(data);
    return data;
}