#pragma once
namespace coinzdense {
  namespace value {
    template <typename Abstract, typename I, uint8_t S>
    struct ValueSemantics: Abstract {
        ValueSemantics(std::unique_ptr<Abstract> ptr): pImpl(std::move(ptr)){}
        std::array<uint8_t, S> operator () (I subkey_id){
            return (*pImpl)(subkey_id);
        }
      private:
        std::unique_ptr<Abstract> pImpl;
    };
  }
}
