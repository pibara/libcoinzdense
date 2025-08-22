#include <cstdint>
#include <iostream>
#include <string>
#include "coinzdense/isa.hpp"
#include "coinzdense/entropy.hpp"
#include "coinzdense/wots.hpp"


int main() {
    std::array<uint8_t, 32> key{0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1};
    auto entropy = coinzdense::entropy::make_secret_entropy<20>(key);
    auto sub = entropy(1234567);
    auto range1 = entropy.ranged<4000, 8000>();
    auto sub2 = range1(1500);
    try {
      auto sub2b = range1(5000);
      throw std::runtime_error("Failure in first range test");
    }
    catch (std::out_of_range const &e) {
    }
    auto range2 = range1.ranged<50, 150>();
    auto sub3 = range2(75);
    try {
      auto sub3b = range2(110);
      throw std::runtime_error("Failure in second range test");
    }
    catch (std::out_of_range const &e) {
    }
}
