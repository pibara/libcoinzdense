#pragma once
// Copyright (c) 2025, Rob J Meijer
// Licensed under the BSD 3-Clause License. See LICENSE
// file in the project root for full license information.
#include <array>
#include <stdexcept>
#include <memory>
#include <type_traits>
#include <limits>
#include <utility>
namespace coinzdense {
namespace value {
template <typename Abstract, typename I, uint8_t S, I Min, I Max>
struct Ranged: Abstract {
  static_assert(std::is_integral_v<I>, "I must be an integral type");
    explicit Ranged(std::weak_ptr<Abstract> ptr): pImpl(ptr) {}
    std::array<uint8_t, S> operator () (I id) {
      if (id < 0 || id + Min > Max) {
        throw std::out_of_range("Ranged invocation outside of defined range");
      }
      auto sp = pImpl.lock();  //  Convert weak_ptr to shared_ptr
      if (!sp) {
        throw std::runtime_error("Ranged: Underlying object no longer exists");
      }
      return (*sp)(id+Min);
    }
    template<I Start, I End>
    Ranged<Abstract, I, S, Min + Start, Min + End> ranged() {
      static_assert(
         Start >= 0 && Start + Min < Max && End > 0 &&
             End + Min <= Max && End > Start,
         "Ranged decomposition outside of defined range");
      return Ranged<Abstract, I, S, Min + Start, Min + End>(pImpl);
    }
 private:
    std::weak_ptr<Abstract> pImpl;
};
template <typename Abstract, typename I, uint8_t S>
struct ValueSemantics: Abstract {
  static_assert(std::is_integral_v<I>, "I must be an integral type");
    explicit ValueSemantics(std::unique_ptr<Abstract> ptr):
          pImpl(std::move(ptr)) {}
    std::array<uint8_t, S> operator () (I id) {
      return (*pImpl)(id);
    }
    template<I Start, I End>
    Ranged<Abstract, I, S, Start, End> ranged() {
      static_assert(End > Start && End <= std::numeric_limits<I>::max() &&
                      Start >= std::numeric_limits<I>::min(),
                      "Ranged decomposition outside of type limits");
      return Ranged<Abstract, I, S, Start, End>(pImpl);
    }
 private:
    std::shared_ptr<Abstract> pImpl;
};
}  // namespace value
}  // namespace coinzdense
