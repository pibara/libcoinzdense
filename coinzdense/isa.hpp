#include <cstdint>
#include <cmath>
// Top namespace for the coinzdense library
namespace coinzdense {
  // Index space allocation (isa) sub namespace, the isa subsystem takes care of unique indices that should get used in
  // the libsodium key derivation function to derive seeding keys, salts and nonces from a single master key.
  namespace isa {
    // a chainset represents a combination of two WOTS chains (an up and a down chain) plus a salt used for both chains.
    // The WOTS chains use salted BLAKE2B operations in each hashing step.
    struct chainset {
      // enun to distinguis between the UP chain seed, the DOWN chain seed and the shared WOTS operations SALT 
      enum Purpose {
        UP=0, DOWN=1, SALT=2
      };
      // The size of the index space used by a single chainset is always three, an UP chain seed, a DOWN chain seed and a SALT
      static constexpr std::uint64_t size() {
        return 3;
      }
      // Get the index of a specific seed or salt given a baseindex
      static constexpr std::uint64_t index(std::uint64_t baseindex, Purpose purpose ) {
        return baseindex + purpose;
      }
    };

    // A onetime key is a set of chainsets that together are capable to signing a L long transaction digest,
    // level key digest, or POLA-key level 0 level key digest
    template<std::uint64_t D, std::uint64_t L>
    struct onetimekey {
      // Enum for distinguishing between the transaction Nonce and the POLA delegation Nonce
      enum Nonce {
        TRANSACTION=0, POLASUBSIG=1
      };
      // A WOTS chain is at least 16 (2^4) and at most 65536 (2^16) secure hash operations long.
      static_assert(D >= 4 && D <= 16, "Depthbits must be in the range 4 to 16");
      // The transactin digest is at least 16 bytes (128 bits) and at most 64 bytes (512 bits) long.
      static_assert(L >= 16 && L <= 64, "Hashlength must be in the range 16 to 64");
      //Fetch the index of one of the nonces available at this level. 
      static constexpr std::uint64_t nonceindex(std::uint64_t baseindex, Nonce noncetype) {
        return baseindex + noncetype;
      }
      //Fetch the index of a specific chainset.
      static constexpr std::uint64_t index(std::uint64_t baseindex, Nonce index) {
        return baseindex + 2 + index;
      }
      //Calculate the chunk of unique index space used by a single onetimekey 
      static constexpr std::uint64_t size() {
        return (((L*8-1) / D)+1) * chainset::size(); 
      }
      // Calculate the number of bits of adressing space used by a onetimekey, needed in asserts to make sure we don't overdimension.
      static constexpr std::uint64_t bits() {
        return static_cast<unsigned int>(std::log2(onetimekey<D, L>::size())) + 1;
      }
    };

    // A levelkey combines a collection of onetimekey in a merkletree construction. A levelkey is an exaustable resource.
    template<std::uint64_t D, std::uint64_t L, std::uint64_t H>
    struct levelkey {
      static_assert(D >= 4 && D <= 16, "Depthbits must be in the range 4 to 16");
      static_assert(L >= 16 && L <= 64, "Hashlength must be in the range 16 to 64");
      // A single level key has a merkle tree that is between 3 (8 onetimekeys) and 16 (65536 onetimekeys) high. 
      static_assert(H >= 3 && H <= 16, "LevelkeyHeight must be in the range 4 to 16");
      //The index reserved for the merkle tree SALT used in leaf operations as key in BLAKE2B operations
      static constexpr std::uint64_t saltindex(std::uint64_t baseindex) {
        return baseindex;
      }
      //Index for specific onetimekeys
      static constexpr std::uint64_t index(std::uint64_t baseindex, std::uint64_t index) {
        return baseindex + index * onetimekey<D, L>::size() + 1;
      }
      //The total index space the levelkey takes in
      static constexpr std::uint64_t size() {
        return  1 + (1 << H) * onetimekey<D, L>::size();
      }
      // The number of items the level key can sign.
      static constexpr std::uint64_t items() {
        return 1 << H;
      }
      // The total number of bits of index space the levelkey takes up
      static constexpr std::uint64_t bits() {
        return H + onetimekey<D, L>::bits();
      }
    };

    // A coinzdensekey is a lazy (JIT) tree of levelkeys. The top of the tree is either the user's level 0 root key, 
    // or a POLA level 0 key.  
    template<std::uint64_t D, std::uint64_t L, std::uint64_t ... Heights>
    struct coinzdensekey;

    // Class representing the lower two layers of a coinzdensekey tree.
    template<std::uint64_t D, std::uint64_t L, std::uint64_t H1, std::uint64_t H2>
    struct coinzdensekey<D, L, H1, H2> {
      static_assert(D >= 4 && D <= 16, "Depthbits must be in the range 4 to 16");
      static_assert(L >= 16 && L <= 64, "Hashlength must be in the range 16 to 64");
      static_assert(H1 >= 3 && H1 <= 16, "LevelkeyHeight must be in the range 4 to 16");
      static_assert(H2 >= 3 && H2 <= 16, "LevelkeyHeight must be in the range 4 to 16");
      // Make sure the key doesn't exceed the total 64 bits index space.
      static_assert(levelkey<D, L, H1>::bits() + levelkey<D, L, H2>::bits() <= 48, "Keyspace too big for 48 bits");
      // Get the index for a specific onetimekey
      static constexpr std::uint64_t index(std::uint64_t baseindex, std::uint64_t index) {
        return baseindex + 
	       levelkey<D, L, H1>::size() +
	       (index / levelkey<D, L, H2>::items()) * levelkey<D, L, H2>::size() + 
	       levelkey<D, L, H2>::index(baseindex, index % levelkey<D, L, H2>::items());
      }
      // The total index space taken up by a level key and level keys below it.
      static constexpr std::uint64_t size() {
        return levelkey<D, L, H1>::size() + 
	       levelkey<D, L, H1>::items() * levelkey<D, L, H2>::size();
      }
      // The total numbers of items that the lowest level of level keys can sign from this point down.
      static constexpr std::uint64_t items() {
        return levelkey<D, L, H1>::items() * levelkey<D, L, H2>::items();  
      }
      // Like size, but expressed in bits for use in asserts.
      static constexpr std::uint64_t bits() {
        return levelkey<D, L, H1>::bits() + levelkey<D, L, H2>::bits();
      }
    };

    // The pack version of the above, this takes care of the higher levels of the levelkeys tree.
    template<std::uint64_t D, std::uint64_t L, std::uint64_t H1, std::uint64_t ... Heights>
    struct coinzdensekey<D, L, H1, Heights...> {
      static_assert(D >= 4 && D <= 16, "Depthbits must be in the range 4 to 16");
      static_assert(L >= 16 && L <= 64, "Hashlength must be in the range 16 to 64");
      static_assert(H1 >= 3 && H1 <= 16, "LevelkeyHeight must be in the range 4 to 16");
      static_assert(levelkey<D, L, H1>::bits() + coinzdensekey<D, L, Heights...>::bits() <= 64, "Keyspace too big for 64 bits");
      static constexpr std::uint64_t index(std::uint64_t baseindex, std::uint64_t index) {
	return baseindex + 
	       levelkey<D, L, H1>::size() + 
	       coinzdensekey<D, L, Heights...>::size() * (index / coinzdensekey<D, L, Heights...>::items()) + 
	       coinzdensekey<D, L, Heights...>::index(0,index % coinzdensekey<D, L, Heights...>::items());
      }
      static constexpr std::uint64_t size() {
	return levelkey<D, L, H1>::size() + 
	       levelkey<D, L, H1>::items() * coinzdensekey<D, L, Heights...>::size();
      }
      static constexpr std::uint64_t items() {
	return levelkey<D, L, H1>::items() * coinzdensekey<D, L, Heights...>::items();
      }
      static constexpr std::uint64_t bits() {
	return levelkey<D, L, H1>::bits() +
	       coinzdensekey<D, L, Heights...>::bits();
      }
    };
  
    // Python and other languages using this lib don't do compile time templates and there are too many options to compile
    // all possible combinations. The below class provides a more limited set of options that we can compile for Python, WASM,
    // and other language bindings.
    template<std::uint64_t D, std::uint64_t L, std::uint64_t C>
    struct keyapi {
      static_assert(D == 8 || D == 12 || D == 16, "Depthbits must be 8, 12, or 16");
      static_assert(L == 16 || L ==24 || L == 32, "Hashlength must be 16, 24, or 32");
      static_assert(C >= 4 && C <=6, "LevelCount must be 4, 5 or 6");
      typedef coinzdensekey<D, L, 11, 11, 11, 10> key4_1;
      typedef coinzdensekey<D, L, 11, 11, 10, 10> key4_2;
      typedef coinzdensekey<D, L, 11, 10, 10, 10> key4_3;
      typedef coinzdensekey<D, L, 9, 9, 9, 8, 8> key5_1;
      typedef coinzdensekey<D, L, 9, 9, 8, 8, 8> key5_2;
      typedef coinzdensekey<D, L, 9, 8, 8, 8, 8> key5_3;
      typedef coinzdensekey<D, L, 8, 7, 7, 7, 7, 7> key6_1;
      typedef coinzdensekey<D, L, 7, 7, 7, 7, 7, 7> key6_2;
      typedef coinzdensekey<D, L, 7, 7, 7, 7, 7, 6> key6_3;
      typedef std::conditional_t< C==4, key4_1, std::conditional_t< C==5, key5_1, key6_1> >  key1;
      typedef std::conditional_t< C==4, key4_2, std::conditional_t< C==5, key5_2, key6_2> >  key2;
      typedef std::conditional_t< C==4, key4_3, std::conditional_t< C==5, key5_3, key6_3> >  key3;
      typedef std::conditional_t< onetimekey<D, L>::bits() == 5,
	                          key1,
				  std::conditional_t< onetimekey<D, L>::bits() == 6,
				                      key2,
						      key3> > keytype; 


      static constexpr std::uint64_t index(std::uint64_t baseindex, std::uint64_t index) {
	return keytype::index(baseindex, index);
      }
      static constexpr std::uint64_t size() {
	return keytype::size();
      }
      static constexpr std::uint64_t items() {
	return keytype::items();
      }
      static constexpr std::uint64_t bits() {
	return keytype::bits();
      }
    };
  }
}
