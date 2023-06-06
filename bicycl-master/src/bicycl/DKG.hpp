/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2022  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef DKG_HPP__
#define DKG_HPP__

#include <iostream>
#include <tuple>
#include <stdexcept>
#include <fstream>
#include "dealing.pb.h"

#include <openssl/evp.h> /* for Shake256 implementation */

#include "bicycl/gmp_extras.hpp"
#include "bicycl/qfi.hpp"
#include "bicycl/CL_HSM_utils.hpp"
#include "bicycl/CL_HSMqk.hpp"
#include "bicycl/seclevel.hpp"

#include <string>
#include <stdio.h>
#include "pair_BLS12381.h"
#include "randapi.h"


using namespace core;
using namespace BLS12381;
using namespace BLS12381_FP;
using namespace BLS12381_BIG;

namespace BICYCL
{
  const std::string DOMAIN_PROOF_OF_SHARING_INSTANCE = "crypto-classgroup-dkg-zk-proof-of-sharing-instance";
  const std::string DOMAIN_PROOF_OF_SHARING_CHALLENGE = "crypto-classgroup-dkg-zk-proof-of-sharing-challenge";

  
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
      //bool check_instance();

  };

  class Witness{

  public:
    Mpz r;
    BIG* s;

    Witness();
  };

  class ZkProofSharing{

    public:
      QFI ff;
      ECP aa;
      QFI yy;
      Mpz z_r;
      BIG z_alpha;
  };


  class NIZK {

  public:
    unsigned int node_count;
    unsigned int threshold;

    NIZK(int nodes, int threshold);

    void sharing_proof_challenge( BIG& x, QFI& ff, ECP& aa, QFI& yy , BIG& x_challenge);
    ZkProofSharing* prove_sharing(const CL_HSMqk &C, Witness& witness, SharingInstance& instance, RandGen& randgen, csprng& RNG);
    bool verify_sharing(const CL_HSMqk &C, SharingInstance& instance, ZkProofSharing* nizk);


};


class DKG_Dealing{

  /** Class used to represent a ciphertext for the cryptosystem */
  using CipherText = _Utils::CL_HSM_CipherText<CL_HSMqk>;

  public:
  CipherText* ciphertexts;
  QFI g_r;
  ECP* public_coefficients;
  ZkProofSharing* nizk_share;

  DKG_Dealing(CipherText*, QFI&, ECP*, ZkProofSharing*);
  DKG_Dealing(){};

};



class DKG_Helper{

  using SecretKey = _Utils::CL_HSM_SecretKey<CL_HSMqk>;
  using PublicKey = _Utils::CL_HSM_PublicKey<CL_HSMqk>;
  using ClearText = _Utils::CL_HSM_ClearText<CL_HSMqk>;
  using CipherText = _Utils::CL_HSM_CipherText<CL_HSMqk>;

  unsigned int node_count;
  unsigned int threshold;
  PublicKey* public_keys;

  void randseed (RandGen &randgen);
  void randseed(csprng& RNG);
  void read_config(Mpz& q, Mpz&p, ECP& g1_gen, ECP& g);
  bool read_public_keys(PublicKey*);
  void gen_poly_evals(csprng& RNG, BIG* poly_evals, ECP* public_coefficients, ECP& g);

  //generate public private keys for a test run of dkg
  //keys are stored in a local file in plaintext
  //Note: this is for test purposes only. In real world use the keys should be stored securely
  void gen_test_config();
  void serialize_qfi(QFI&, protobuff_ser::QFI&);
  void serialize_ecp(ECP&, protobuff_ser::ECP&);

  void deserialize_qfi(const protobuff_ser::QFI&, QFI&, Mpz&);
  void deserialize_ecp(const protobuff_ser::ECP&, ECP&);

public:

  DKG_Helper(unsigned int node_count, unsigned int threshold){
    this->node_count = node_count;
    this->threshold = threshold;
    public_keys = new PublicKey[node_count];
    if (!read_public_keys(public_keys)){
      gen_test_config();
      read_public_keys(public_keys);
    }
  };

  //generates dkg dealing
  //uses pregenerated public keys stored in the config directory
  DKG_Dealing gen_test_dealing();
  void print_dealing(DKG_Dealing&);
  bool verify_dealing(DKG_Dealing&);
  bool verify_dealing(protobuff_ser::Dealing&);
  void serialize_dealing(DKG_Dealing&, protobuff_ser::Dealing& dealing_bytes);
  void deserialize_dealing(protobuff_ser::Dealing&, DKG_Dealing&, CL_HSMqk&);

  void compute_benchmarks();

};



void process_mpz_hash(hash256& hash, std::vector<unsigned char>& mpz_char);
void powmod(BIG& result, BIG& base, BIG& exp, BIG& m);

  #include "DKG.inl"

} /* BICYCL namespace */

#endif /* CL_HSM_HPP__ */
