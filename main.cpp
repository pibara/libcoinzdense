#include <cstdint>
#include <iostream>
#include <string>
#include "coinzdense/isa.hpp"
#include "coinzdense/entropy.hpp"
#include "coinzdense/wots.hpp"


int main() {
    std::array<uint8_t, 32> key{0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1};
    auto entropy = coinzdense::entropy::make_secret_entropy<16>(key);
    std::array<uint8_t, 16> sub = entropy(1234567);

    typedef coinzdense::isa::coinzdensekey<12, 16, 9, 9, 9, 8> hivekeytype;
    std::cout << hivekeytype::items() << " " << hivekeytype::size()  << " " << hivekeytype::bits() << " " << hivekeytype::index(0,0) << " " << hivekeytype::index(0,1) << " " << hivekeytype::index(0,10000) << " " << hivekeytype::index(0,1000000) << std::endl;

    auto chainpair = coinzdense::wots::make_wots_chain_pair<16>(entropy(1234567), entropy(1234568), entropy(1234569));
    auto res = chainpair(188);
}
