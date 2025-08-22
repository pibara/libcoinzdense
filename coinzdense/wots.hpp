#pragma once
// Copyright (c) 2025, Rob J Meijer
// Licensed under the BSD 3-Clause License. See LICENSE
// file in the project root for full license information.
#include <sodium.h>
#include <string.h>
#include <memory>
#include <string>
#include "value.hpp"
namespace coinzdense {
namespace sodium {
struct GenericHashException : std::runtime_error {
  explicit GenericHashException(const std::string& message):
      std::runtime_error("Generic hash failed : " + message) {}
};
}  // namespace sodium
namespace wots {
template<std::uint64_t S>
struct AbstractWotsChainPair {
  virtual ~AbstractWotsChainPair() = default;
  virtual std::array<uint8_t, 2*S> operator () (uint32_t index) = 0;
};
template<std::uint64_t D, std::uint64_t S>
// dual chain wots primitive
struct WotsChainPair: AbstractWotsChainPair<S> {
  static_assert(D >= 4 && D <= 16, "Depthbits must be in the range 4 to 16");
  static_assert(S >= 20 && S <= crypto_kdf_BYTES_MAX,
      "Subkey size must be 20 up to crypto_kdf_BYTES_MAX bytes");
  //  constructor
  WotsChainPair(std::array<uint8_t, S> up_seed, std::array<uint8_t, S>
            down_seed, std::array<uint8_t, S> salt):
               mUpSeed(up_seed), mDownSeed(down_seed), mSalt(salt) {}
  //  callable operation
  std::array<uint8_t, 2*S>  operator () (uint32_t index) {
    if (index > (1 << D)) {
      throw std::out_of_range("WotsChainPair index out of range.");
    }
    //  two working buffers
    unsigned char temp_in[2*S];
    unsigned char temp_out[2*S];
    //  Fill the buffers with the initial seeds
    memcpy(temp_in, mUpSeed.data(), S);
    memcpy(temp_in+S, mDownSeed.data(), S);
    //  the second chain uses the reverse index as a more secure alternative to
    //  a single chain with CRC.
    //  NOTE: the invalid index (1 << D) is used to calculate the partial OTS
    //  public key instead of a partial signature.
    uint32_t rindex = (index < (1 << D)) ?  (1 << D) - index : index;
    //  Find the min and the max of the two indices
    uint32_t mindex = (rindex > index) ? index : rindex;
    uint32_t maxdex = (rindex > index) ? rindex : index;
    //  Determine the offset for the tail chain
    uint32_t offset = (rindex > index) ? S : 0;
    //  Do the shared bit for both chains
    for (unsigned int i = 0; i < mindex; i++) {
      if (crypto_generichash(temp_out, S, temp_in, S, mSalt.data(), S) == -1) {
        throw coinzdense::sodium::GenericHashException(
            "Invalid parameters or system error");
      }
      if (crypto_generichash(temp_out+S, S, temp_in+S, S,
            mSalt.data(), S) == -1) {
        throw coinzdense::sodium::GenericHashException(
            "Invalid parameters or system error");
      }
      memcpy(temp_in, temp_out, S*2);
    }
    //  Complete the longer chain
    for (unsigned int i = mindex; i < maxdex; i++) {
      if (crypto_generichash(temp_out+offset, S, temp_in+offset, S,
                mSalt.data(), S) == -1) {
        throw coinzdense::sodium::GenericHashException(
                "Invalid parameters or system error");
      }
      memcpy(temp_in+offset, temp_out+offset, S);
    }
    //  One extra hashing because we are 1 based, not 0 based in indexing,
    //  we need at least one hashing round.
    if (crypto_generichash(temp_out, S, temp_in, S, mSalt.data(), S) == -1) {
      throw coinzdense::sodium::GenericHashException(
              "Invalid parameters or system error");
    }
    if (crypto_generichash(temp_out+S, S, temp_in+S, S,
              mSalt.data(), S) == -1) {
      throw coinzdense::sodium::GenericHashException(
              "Invalid parameters or system error");
    }
    //  Return partial signature as concatted array.
    return std::to_array(temp_out);
  }

 private:
  std::array<uint8_t, S> mUpSeed;
  std::array<uint8_t, S> mDownSeed;
  std::array<uint8_t, S> mSalt;
};

template<std::uint64_t D, std::uint64_t S>
coinzdense::value::ValueSemantics<AbstractWotsChainPair<S>, uint32_t, S*2>
        make_wots_chain_pair(std::array<uint8_t, S> up_seed,
                             std::array<uint8_t, S> down_seed,
                             std::array<uint8_t, S> salt) {
    return coinzdense::value::ValueSemantics<AbstractWotsChainPair<S>,
            uint32_t, S*2>(
                std::make_unique<WotsChainPair<D, S> >(
                    up_seed, down_seed, salt));
}
}  //  namespace wots
}  //  namespace coinzdense
