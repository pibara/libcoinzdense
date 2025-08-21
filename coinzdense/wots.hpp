#pragma once
#include <sodium.h>
#include <string.h>
#include <memory>
#include "value.hpp"
namespace coinzdense {
  namespace wots {
    template<std::uint64_t S>
    struct AbstractWotsChainPair {
      virtual ~AbstractWotsChainPair() = default;
      virtual std::array<uint8_t, 2*S> operator () (uint32_t index) = 0;
    };
     template<std::uint64_t D, std::uint64_t S>
    // dual chain wots primitive
    struct WotsChainPair: AbstractWotsChainPair<S> {
	//constructor
        WotsChainPair(std::array<uint8_t, S> up_seed, std::array<uint8_t, S> down_seed, std::array<uint8_t, S> salt):
	        mUpSeed(up_seed), mDownSeed(down_seed), mSalt(salt) {}
	//callable operation
        std::array<uint8_t, 2*S>  operator () (uint32_t index){
	    // two working buffers
            unsigned char temp_in[2*S];
	    unsigned char temp_out[2*S];
	    //Fill the buffers with the initial seeds
	    memcpy(temp_in, mUpSeed.data(), S);
	    memcpy(temp_in+S, mDownSeed.data(), S);
	    // the second chain uses the reverse index as a more secure alternative to a single chain with CRC
	    uint32_t rindex = (1 << D) - index;
	    // Find the min and the max of the two indices
            uint32_t mindex = (rindex > index) ? index : rindex;
	    uint32_t maxdex = (rindex > index) ? rindex : index;
	    // Determine the offset for the tail chain
	    uint32_t offset = (rindex > index) ? S : 0;
	    // Do the shared bit for both chains
	    for (unsigned int i = 0; i < mindex; i++) {
              crypto_generichash(temp_out, S, temp_in, S, mSalt.data(), S);
	      crypto_generichash(temp_out+S, S, temp_in+S, S, mSalt.data(), S);
	      memcpy(temp_in, temp_out, S*2);
	    }
	    // Complete the longer chain
	    for (unsigned int i = mindex; i < maxdex; i++) {
              crypto_generichash(temp_out+offset, S, temp_in+offset, S, mSalt.data(), S);
	      memcpy(temp_in+offset, temp_out+offset, S);
	    }
	    // One extra hashing round in case one of tha chains had zero rounds
	    crypto_generichash(temp_out, S, temp_in, S, mSalt.data(), S);
            crypto_generichash(temp_out+S, S, temp_in+S, S, mSalt.data(), S);
	    // Return partial signature as concatted array.
            return std::to_array(temp_out);
        }
      private:
	std::array<uint8_t, S> mUpSeed;
	std::array<uint8_t, S> mDownSeed;
	std::array<uint8_t, S> mSalt;
    };

    template<std::uint64_t D, std::uint64_t S>
    coinzdense::value::ValueSemantics<AbstractWotsChainPair<S>, uint32_t, S*2> make_wots_chain_pair(std::array<uint8_t, S> up_seed, std::array<uint8_t, S> down_seed, std::array<uint8_t, S> salt) {
        return coinzdense::value::ValueSemantics<AbstractWotsChainPair<S>, uint32_t, S*2>(std::make_unique<WotsChainPair<D, S> >(up_seed, down_seed, salt));
    }
  }
}
