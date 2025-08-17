#include <string>
#include <sodium.h>
#include "coinzdense/entropy.hpp"
namespace coinzdense {
  namespace entropy {
    struct SecretEntropy: AbstractEntropy {
        SecretEntropy(std::basic_string<uint8_t> masterkey):mContext("CoinZdns"), mMasterKey(masterkey) {}
	std::basic_string<uint8_t> operator () (uint64_t subkey_id){
          uint8_t subkey[16];
	  crypto_kdf_derive_from_key(subkey, 16, subkey_id, mContext.data(), mMasterKey.c_str());
	  return std::basic_string<uint8_t>(subkey, 16);
	}
      private:
	std::string mContext;
	std::basic_string<uint8_t> mMasterKey;
    };
    std::unique_ptr<AbstractEntropy> make_secret_entropy(std::basic_string<uint8_t> masterkey){
        return std::make_unique<SecretEntropy>(masterkey);
    }
  }
} 
