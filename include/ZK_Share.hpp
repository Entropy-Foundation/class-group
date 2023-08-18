#ifndef ZK_SHARE_HPP__
#define ZK_SHARE_HPP__

#include "Utils.hpp"
#include "bicycl.hpp"
#include "pair_BLS12381.h"

using namespace core;
using namespace BICYCL;

/// Domain separators for the zk proof of sharing
const std::string DOMAIN_PROOF_OF_SHARING_CHALLENGE = "crypto-classgroup-dkg-zk-proof-of-sharing-challenge";
const std::string DOMAIN_PROOF_OF_SHARING_INSTANCE = "crypto-classgroup-dkg-zk-proof-of-sharing-instance";


class SharingInstance{
    public:
      /** Class used to represent a public key of the cryptosystem */
      using PublicKey = _Utils::CL_HSM_PublicKey<CL_HSMqk>;
      /** Class used to represent a ciphertext for the cryptosystem */
      using CipherText = _Utils::CL_HSM_CipherText<CL_HSMqk>;

      ECP g1_gen;
      ECP g;
      PublicKey* public_keys;
      QFI g_r;
      CipherText* ciphertexts;
      ECP* public_coefficients;

      SharingInstance(ECP& g1_gen, ECP& g, PublicKey* public_keys,
                      QFI& g_r, CipherText* ciphertexts, ECP* public_coefficients);

      void hash_to_scalar(BIG x, unsigned int node_count, unsigned int threshold);

};


class Witness{

    Mpz r;
    BIG* s;
  public:
    Witness(const Mpz& r, BIG* s){
      this->r = r;
      this->s = s;
    };

    Mpz get_r(){return r;};
    BIG* get_s(){return s;};
};

class ZkProofSharing{
    public:
      QFI ff;
      ECP aa;
      QFI yy;
      Mpz z_r;
      BIG z_alpha;
};

void sharing_proof_challenge( BIG& x, QFI& ff, ECP& aa, QFI& yy , BIG& x_challenge);
ZkProofSharing* prove_sharing(const CL_HSMqk &C, Witness& witness, SharingInstance& instance, RandGen& randgen, csprng& RNG, unsigned int node_count, unsigned int threshold);
bool verify_sharing(const CL_HSMqk &C, SharingInstance& instance, ZkProofSharing* nizk, unsigned int node_count, unsigned int threshold);

#endif