#pragma once
// Copyright (c) 2025, Rob J Meijer
// Licensed under the BSD 3-Clause License. See LICENSE
// file in the project root for full license information.
#include <sodium.h>
#include <memory>
#include <stdexcept>
#include <string>
#include "value.hpp"
namespace coinzdense {
namespace sodium {
struct SodiumInitException : std::runtime_error {
  explicit SodiumInitException(const std::string& message):
        std::runtime_error("Sodium initialization failed: " + message) {}
};
struct KdfDeriveException : std::runtime_error {
  explicit KdfDeriveException(const std::string& message):
        std::runtime_error("Key derivation failed: " + message) {}
};
}  // namespace sodium
namespace entropy {
template <uint8_t S>
struct AbstractEntropy {
  virtual ~AbstractEntropy() = default;
  virtual std::array<uint8_t, S> operator () (uint64_t subkey_id) = 0;
};

template <uint8_t S>
struct SecretEntropy: AbstractEntropy<S> {
    explicit SecretEntropy(std::array<uint8_t, crypto_kdf_KEYBYTES> masterkey):
        mContext{'C', 'o', 'i', 'n', 'Z', 'd', 'n', 's'}, mMasterKey(
            masterkey) {
      if (sodium_init() == -1) {
        throw coinzdense::sodium::SodiumInitException(
            "Failed to initialize libsodium");
      }
    }
    std::array<uint8_t, S> operator () (uint64_t subkey_id) {
      uint8_t subkey[S];
      if (crypto_kdf_derive_from_key(subkey, S, subkey_id, mContext.data(),
                                     mMasterKey.data()) == -1) {
        throw coinzdense::sodium::KdfDeriveException(
            "Invalid parameters or system error");
      }
      return std::to_array(subkey);
    }
 private:
    std::array<char, crypto_kdf_CONTEXTBYTES> mContext;
    std::array<uint8_t, crypto_kdf_KEYBYTES> mMasterKey;
};

template <uint8_t S>
coinzdense::value::ValueSemantics<AbstractEntropy<S>, uint64_t, S>
    make_secret_entropy(std::array<uint8_t, 32> masterkey) {
  return coinzdense::value::ValueSemantics<AbstractEntropy<S>,
                                           uint64_t, S>(
        std::make_unique<SecretEntropy<S>>(masterkey));
}
}  // namespace entropy
}  // namespace coinzdense
