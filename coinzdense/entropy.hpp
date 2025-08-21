#pragma once
#include <sodium.h>
#include <memory>
#include "value.hpp"
namespace coinzdense {
  namespace entropy {
    template <uint8_t S>
    struct AbstractEntropy {
        virtual ~AbstractEntropy() = default;
        virtual std::array<uint8_t, S> operator () (uint64_t subkey_id) = 0;
    };
   
    template <uint8_t S>
    struct SecretEntropy: AbstractEntropy<S> {
        SecretEntropy(std::array<uint8_t, 32> masterkey):mContext("CoinZdns"), mMasterKey(masterkey) {}
        std::array<uint8_t, S> operator () (uint64_t subkey_id){
          uint8_t subkey[S];
          crypto_kdf_derive_from_key(subkey, S, subkey_id, mContext.data(), mMasterKey.data());
          return std::to_array(subkey);
        }
      private:
        std::string mContext;
        std::array<uint8_t, 32> mMasterKey;
    };

    template <uint8_t S>
    coinzdense::value::ValueSemantics<AbstractEntropy<S>, uint64_t, S> make_secret_entropy(std::array<uint8_t, 32> masterkey){
        return coinzdense::value::ValueSemantics<AbstractEntropy<S>, uint64_t, S>(std::make_unique<SecretEntropy<S>>(masterkey));
    }
  }
}
