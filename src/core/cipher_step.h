#ifndef CIPHER_STEP_H
#define CIPHER_STEP_H
#include <string>
#include <map>
#include <memory>
#include <vector>

class ICipherStep {
public:
    virtual ~ICipherStep() = default;
    virtual std::string encrypt(const std::string& input) const = 0;
    virtual std::string decrypt(const std::string& input) const = 0;
    virtual std::string type_name() const = 0;
    virtual std::string serialize_params() const = 0;
    virtual std::map<std::string, std::string> getParams() const = 0;
    virtual std::unique_ptr<ICipherStep> clone() const = 0;
};

class StepFactory {
public:
    static std::unique_ptr<ICipherStep> create(const std::string& type,
                                               const std::map<std::string, std::string>& params,
                                               const std::string& alphabet = "");
};

class CaesarStep : public ICipherStep {
    int shift_;
    std::vector<std::string> alphabet_;
public:
    CaesarStep(int shift, const std::string& alphabet);
    std::string encrypt(const std::string& input) const override;
    std::string decrypt(const std::string& input) const override;
    std::string type_name() const override { return "caesar"; }
    std::string serialize_params() const override;
    std::map<std::string, std::string> getParams() const override;
    std::unique_ptr<ICipherStep> clone() const override;
    static std::unique_ptr<ICipherStep> from_params(const std::map<std::string, std::string>& p, const std::string& alphabet);
};

class SubstitutionStep : public ICipherStep {
    std::map<std::string, std::string> encrypt_map_;
    std::map<std::string, std::string> decrypt_map_;
    std::vector<std::string> alphabet_;
public:
    SubstitutionStep(const std::map<std::string, std::string>& mapping, const std::string& alphabet);
    std::string encrypt(const std::string& input) const override;
    std::string decrypt(const std::string& input) const override;
    std::string type_name() const override { return "substitute"; }
    std::string serialize_params() const override;
    std::map<std::string, std::string> getParams() const override;
    std::unique_ptr<ICipherStep> clone() const override;
    static std::unique_ptr<ICipherStep> from_params(const std::map<std::string, std::string>& p, const std::string& alphabet);
};

class ReverseStep : public ICipherStep {
public:
    std::string encrypt(const std::string& input) const override;
    std::string decrypt(const std::string& input) const override { return encrypt(input); }
    std::string type_name() const override { return "reverse"; }
    std::string serialize_params() const override { return ""; }
    std::map<std::string, std::string> getParams() const override { return {}; }
    std::unique_ptr<ICipherStep> clone() const override { return std::make_unique<ReverseStep>(); }
};

class XorStep : public ICipherStep {
    std::string key_;
public:
    XorStep(const std::string& key);
    std::string encrypt(const std::string& input) const override;
    std::string decrypt(const std::string& input) const override { return encrypt(input); }
    std::string type_name() const override { return "xor"; }
    std::string serialize_params() const override;
    std::map<std::string, std::string> getParams() const override;
    std::unique_ptr<ICipherStep> clone() const override;
    static std::unique_ptr<ICipherStep> from_params(const std::map<std::string, std::string>& p);
};

class TransposeStep : public ICipherStep {
    std::string keyword_;
public:
    TransposeStep(const std::string& keyword);
    std::string encrypt(const std::string& input) const override;
    std::string decrypt(const std::string& input) const override;
    std::string type_name() const override { return "transpose"; }
    std::string serialize_params() const override;
    std::map<std::string, std::string> getParams() const override;
    std::unique_ptr<ICipherStep> clone() const override;
    static std::unique_ptr<ICipherStep> from_params(const std::map<std::string, std::string>& p);
};

class VigenereStep : public ICipherStep {
    std::string key_;
    std::vector<std::string> alphabet_;
public:
    VigenereStep(const std::string& key, const std::string& alphabet);
    std::string encrypt(const std::string& input) const override;
    std::string decrypt(const std::string& input) const override;
    std::string type_name() const override { return "vigenere"; }
    std::string serialize_params() const override;
    std::map<std::string, std::string> getParams() const override;
    std::unique_ptr<ICipherStep> clone() const override;
    static std::unique_ptr<ICipherStep> from_params(const std::map<std::string, std::string>& p, const std::string& alphabet);
};

#endif