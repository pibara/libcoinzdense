#include <string>
#include <memory>
namespace coinzdense {
  namespace entropy {
    struct AbstractEntropy {
        virtual ~AbstractEntropy() = default;
        virtual std::basic_string<uint8_t> operator () (uint64_t subkey_id) = 0;
    };
    std::unique_ptr<AbstractEntropy> make_secret_entropy(std::basic_string<uint8_t> masterkey);
  }
}
