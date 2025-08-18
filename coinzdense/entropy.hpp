#include <string>
#include <memory>
namespace coinzdense {
  namespace entropy {
    struct AbstractEntropy {
        virtual ~AbstractEntropy() = default;
        virtual std::basic_string<uint8_t> operator () (uint64_t subkey_id) = 0;
    };
    struct ValueSemantics: AbstractEntropy {
        ValueSemantics(std::unique_ptr<AbstractEntropy> ptr): mPtr(std::move(ptr)){}
        std::basic_string<uint8_t> operator () (uint64_t subkey_id){
            return (*mPtr)(subkey_id);
        }
      private:
        std::unique_ptr<AbstractEntropy> mPtr;
    };
    ValueSemantics make_secret_entropy(std::basic_string<uint8_t> masterkey);
  }
}
