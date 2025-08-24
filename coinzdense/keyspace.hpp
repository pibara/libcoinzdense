#pragma once
// Copyright (c) 2025, Rob J Meijer
// Licensed under the BSD 3-Clause License. See LICENSE
// file in the project root for full license information.
#include <limits>
#include "isa.hpp"
#include "entropy.hpp"
#include "value.hpp"
namespace coinzdense {
namespace keyspace {

template<uint8_t S, std::uint64_t D, std::uint64_t L, std::uint64_t H1,
        std::uint64_t ... Heights>
struct full_keyspace {
  explicit full_keyspace(coinzdense::value::ValueSemantics<
            coinzdense::entropy::AbstractEntropy<S>,
            uint64_t,
            S> const &entropy):
    rEntropy(entropy) {}
  static constexpr uint64_t mainkey_last() {
     return coinzdense::isa::coinzdensekey<D, L, H1, Heights...>::size() - 1;
  }
  static constexpr uint64_t unallocated_first() {
        return coinzdense::isa::coinzdensekey<D, L, H1, Heights...>::size();
  }
  static constexpr uint64_t unallocated_last() {
        return std::numeric_limits<uint64_t>::max();
  }
  static constexpr uint64_t l0_last() {
        return coinzdense::isa::levelkey<D, L, H1>::size() -1;
  }
  coinzdense::value::Ranged<coinzdense::entropy::AbstractEntropy<S>,
                            uint64_t,
                            S,
                            0,
                            mainkey_last()> mainkey_keyspace() {
    return rEntropy.template ranged<0, mainkey_last()>();
  }
  coinzdense::value::Ranged<coinzdense::entropy::AbstractEntropy<S>,
                            uint64_t,
                            S,
                            unallocated_first(),
                            unallocated_last()> unallocated_keyspace() {
    return rEntropy.template ranged<unallocated_first(), unallocated_last()>();
  }
  coinzdense::value::Ranged<coinzdense::entropy::AbstractEntropy<S>,
                            uint64_t,
                            S,
                            0,
                            l0_last()> l0_keyspace() {
    return rEntropy.template ranged<0, l0_last()>();
  }

 private:
  coinzdense::value::ValueSemantics<coinzdense::entropy::AbstractEntropy<S>,
                                    uint64_t,
                                    S> &rEntropy;
};

}  // namespace keyspace
}  // namespace coinzdense
