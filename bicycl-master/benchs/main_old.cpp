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
#include <string>
#include <sstream>
#include <chrono>

#include "bicycl.hpp"
#include "internals.hpp"

#include "pair_BLS12381.h"

using namespace core;
using namespace BLS12381;
using namespace BLS12381_FP;
using namespace BLS12381_BIG;

using std::string;

using namespace std;

using namespace BICYCL;
using BICYCL::Bench::ms;
using BICYCL::Bench::us;


string DOMAIN_PROOF_OF_SHARING_INSTANCE = "crypto-classgroup-dkg-zk-proof-of-sharing-instance";
string DOMAIN_PROOF_OF_SHARING_CHALLENGE = "crypto-classgroup-dkg-zk-proof-of-sharing-challenge";




// sets result = base^exp mod m
void powmod(BIG& result, BIG& base, BIG& exp, BIG& m){

  BIG_norm(base);
  BIG e;
  BIG_rcopy(e, exp);
  BIG_norm(e);
  BIG a;
  BIG_one(a);
  BIG z;
  BIG_rcopy(z, e);
  BIG s;
  BIG_rcopy(s, base);

  while(1){
    int bt = BIG_parity(z);
    BIG_fshr(z, 1);

    if (bt == 1) {
      BIG_modmul(a, a, s, m);
    }

    if (BIG_iszilch(z)){
      break;
    }

    BIG_modsqr(s, s, m);

  }

  BIG_rcopy(result, a);

}




class ZkProofSharing{

public:
  ECP ff;
  ECP aa;
  QFI yy;
  BIG z_r;
  DBIG z_r_dbig;
  BIG z_alpha;
};



class SharingInstance{

public:
  /** Class used to represent a public key of the cryptosystem */
  using PublicKey = _Utils::CL_HSM_PublicKey<CL_HSMqk>;
  /** Class used to represent a ciphertext for the cryptosystem */
  using CipherText = _Utils::CL_HSM_CipherText<CL_HSMqk>;


  ECP g1_gen;
  ECP g;
  vector<PublicKey> public_keys;
  ECP g_r;
  vector<CipherText> ciphertexts;
  vector<ECP> public_evals;


  SharingInstance(const ECP& g1_gen, const ECP& g, const vector<PublicKey>& public_keys,
                  const ECP& g_r, const vector<CipherText>& ciphertexts,
                  const vector<ECP>&  public_evals){
    
    this->g1_gen = g1_gen;
    this->g = g;

    for(unsigned int i=0; i<public_keys.size(); i++){
      this->public_keys.push_back(public_keys[i]);

    }

    this->g_r = g_r;

    for(unsigned int i=0; i<ciphertexts.size(); i++){
      this->ciphertexts.push_back(ciphertexts[i]);

    }

    for(unsigned int i=0; i<public_evals.size(); i++){
      this->public_evals.push_back(public_evals[i]);

    }


  }



  void hash_to_scalar(BIG x){

    hash256 hash;
    HASH256_init(&hash);

    for(unsigned int i=0; i<DOMAIN_PROOF_OF_SHARING_INSTANCE.length(); i++){

      HASH256_process(&hash, int(DOMAIN_PROOF_OF_SHARING_INSTANCE[i]));
    }

    char* g1_gen_x_bytes = new char[48];
    char* g1_gen_y_bytes = new char[48];
    char* g1_gen_z_bytes = new char[48];

    FP_toBytes(g1_gen_x_bytes,&g1_gen.x);
    FP_toBytes(g1_gen_y_bytes,&g1_gen.y);
    FP_toBytes(g1_gen_z_bytes,&g1_gen.z);

    char* g_x_bytes = new char[48];
    char* g_y_bytes = new char[48];
    char* g_z_bytes = new char[48];

    FP_toBytes(g_x_bytes,&g.x);
    FP_toBytes(g_y_bytes,&g.y);
    FP_toBytes(g_z_bytes,&g.z);

    for(int i=0; i<48; i++){

      HASH256_process(&hash, int(g1_gen_x_bytes[i]));
    }

    for(int i=0; i<48; i++){

      HASH256_process(&hash, int(g1_gen_y_bytes[i]));
    }

    for(int i=0; i<48; i++){

      HASH256_process(&hash, int(g1_gen_z_bytes[i]));
    }

    for(int i=0; i<48; i++){

      HASH256_process(&hash, int(g_x_bytes[i]));
    }

    for(int i=0; i<48; i++){

      HASH256_process(&hash, int(g_y_bytes[i]));
    }

    for(int i=0; i<48; i++){

      HASH256_process(&hash, int(g_z_bytes[i]));
    }


    for(unsigned int i=0; i<public_keys.size(); i++){

      std::stringstream ss;
      ss<<public_keys[i].elt();

      string output = ss.str();

      for(unsigned int j=0; j<output.length(); j++){
        HASH256_process(&hash, int(output[j]));
      }

    }


    char* g_r_x_bytes = new char[48];
    char* g_r_y_bytes = new char[48];
    char* g_r_z_bytes = new char[48];

    FP_toBytes(g_r_x_bytes,&g_r.x);
    FP_toBytes(g_r_y_bytes,&g_r.y);
    FP_toBytes(g_r_z_bytes,&g_r.z);

    for(int i=0; i<48; i++){

      HASH256_process(&hash, int(g_r_x_bytes[i]));
    }

    for(int i=0; i<48; i++){

      HASH256_process(&hash, int(g_r_y_bytes[i]));
    }

    for(int i=0; i<48; i++){

      HASH256_process(&hash, int(g_r_z_bytes[i]));
    }


    for(unsigned int i=0; i<ciphertexts.size(); i++){

      std::stringstream ss;
      ss<<ciphertexts[i].c1();
      ss<<ciphertexts[i].c2();

      string output = ss.str();

      for(unsigned int j=0; j<output.length(); j++){
        HASH256_process(&hash, int(output[j]));
      }

    }

    for(unsigned int i=0; i<public_evals.size(); i++){

      char* x_bytes = new char[48];
      char* y_bytes = new char[48];
      char* z_bytes = new char[48];

      FP_toBytes(x_bytes,&public_evals[i].x);
      FP_toBytes(y_bytes,&public_evals[i].y);
      FP_toBytes(z_bytes,&public_evals[i].z);

      for(int i=0; i<48; i++){

        HASH256_process(&hash, int(x_bytes[i]));
      }

      for(int i=0; i<48; i++){

        HASH256_process(&hash, int(y_bytes[i]));
      }

      for(int i=0; i<48; i++){

        HASH256_process(&hash, int(z_bytes[i]));
      }

    }

    char* hash_output = new char[32];
    HASH256_hash(&hash, hash_output);

    csprng hash_RNG;
    RAND_seed(&hash_RNG, 32, hash_output);

    BIG curve_order;
    BIG_rcopy(curve_order, CURVE_Order);

    
    BIG_randomnum(x, curve_order, &hash_RNG);

    delete[] hash_output;


  }


  bool check_instance(){

    if (this->public_keys.size() == 0 || this->public_evals.size() == 0){
      return false;
    }

    if (this->public_keys.size() != this->ciphertexts.size()){
      return false;
    }

    return true;

  }



};




class Witness{

public:
  BIG r;
  BIG* s;

  Witness(){}


};



void sharing_proof_challenge(BIG& x, ECP& ff, ECP& aa, QFI& yy , BIG& x_challenge){

  hash256 hash;
  HASH256_init(&hash);

  for(unsigned int i=0; i<DOMAIN_PROOF_OF_SHARING_CHALLENGE.length(); i++){

    HASH256_process(&hash, int(DOMAIN_PROOF_OF_SHARING_CHALLENGE[i]));
  }

  char* x_bytes = new char[48];
  BIG_toBytes(x_bytes, x);

  for(int i=0; i<48; i++){

      HASH256_process(&hash, int(x_bytes[i]));
  }

  char* ff_x_bytes = new char[48];
  char* ff_y_bytes = new char[48];
  char* ff_z_bytes = new char[48];

  FP_toBytes(ff_x_bytes,&ff.x);
  FP_toBytes(ff_y_bytes,&ff.y);
  FP_toBytes(ff_z_bytes,&ff.z);

  for(int i=0; i<48; i++){

    HASH256_process(&hash, int(ff_x_bytes[i]));
  }

  for(int i=0; i<48; i++){

    HASH256_process(&hash, int(ff_y_bytes[i]));
  }

  for(int i=0; i<48; i++){

    HASH256_process(&hash, int(ff_z_bytes[i]));
  }

  char* aa_x_bytes = new char[48];
  char* aa_y_bytes = new char[48];
  char* aa_z_bytes = new char[48];

  FP_toBytes(aa_x_bytes,&aa.x);
  FP_toBytes(aa_y_bytes,&aa.y);
  FP_toBytes(aa_z_bytes,&aa.z);

  for(int i=0; i<48; i++){

    HASH256_process(&hash, int(aa_x_bytes[i]));
  }

  for(int i=0; i<48; i++){

    HASH256_process(&hash, int(aa_y_bytes[i]));
  }

  for(int i=0; i<48; i++){

    HASH256_process(&hash, int(aa_z_bytes[i]));
  }


  std::stringstream ss;
  ss<<yy;

  string output = ss.str();

  for(unsigned int j=0; j<output.length(); j++){
    HASH256_process(&hash, int(output[j]));
  }


  char* hash_output = new char[32];
  HASH256_hash(&hash, hash_output);

  csprng hash_RNG;
  RAND_seed(&hash_RNG, 32, hash_output);

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);
  
  BIG_randomnum(x_challenge, curve_order, &hash_RNG);

  delete[] hash_output;

}




template <class Cryptosystem>
ZkProofSharing* prove_sharing(const Cryptosystem &C, Witness& witness, SharingInstance& instance){

  if (instance.check_instance() == false){
    return nullptr;
  }

  csprng RNG;
  int i;
  char pr[10];
  unsigned long ran;

  time((time_t *)&ran);
  pr[0] = ran;
  pr[1] = ran >> 8;
  pr[2] = ran >> 16;
  pr[3] = ran >> 24;
  for (i = 4; i < 10; i++) pr[i] = i; /*****4****/
  RAND_seed(&RNG, 10, pr);

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);

  BIG alpha_fe;
  BIG_randomnum(alpha_fe, curve_order, &RNG);
  BIG rho_fe;
  BIG_randomnum(rho_fe, curve_order, &RNG);

  char* alpha_bytes = new char[48];
  BIG_toBytes(alpha_bytes, alpha_fe);
  Mpz alpha;
  alpha.BIG_to_Mpz(alpha_bytes, 48);

  char* rho_bytes = new char[48];
  BIG_toBytes(rho_bytes, rho_fe);
  Mpz rho;
  rho.BIG_to_Mpz(rho_bytes, 48);

  ECP ff = instance.g1_gen;
  ECP_mul(&ff, rho_fe);

  ECP aa = instance.g;
  ECP_mul(&aa, alpha_fe);

  BIG x;
  instance.hash_to_scalar(x);

  BIG* x_pows = new BIG[instance.public_keys.size()];
  BIG_rcopy(x_pows[0], x);

  for(unsigned int i=1; i<instance.public_keys.size(); i++){

    BIG_modmul(x_pows[i], x_pows[i-1], x, curve_order);
  }

  QFI acc_pk;

  char* x_pow_bytes = new char[48];
  BIG_toBytes(x_pow_bytes, x_pows[0]);

  Mpz x_pow_mpz;
  x_pow_mpz.BIG_to_Mpz(x_pow_bytes, 48);

  delete[] x_pow_bytes;

  instance.public_keys[0].exponentiation(C, acc_pk, x_pow_mpz);


  for(unsigned int i=1; i<instance.public_keys.size(); i++){

    char* x_pow_bytes = new char[48];
    BIG_toBytes(x_pow_bytes, x_pows[i]);

    Mpz x_pow_mpz;
    x_pow_mpz.BIG_to_Mpz(x_pow_bytes, 48);
    delete[] x_pow_bytes;

    QFI acc_pk_i;
    instance.public_keys[i].exponentiation(C, acc_pk_i, x_pow_mpz);

    C.Cl_Delta().nucomp (acc_pk, acc_pk, acc_pk_i);

  }


  QFI f_aa = C.power_of_f(alpha);

  QFI yy;

  C.Cl_G().nupow(yy, acc_pk, rho);

  C.Cl_Delta().nucomp (yy, yy, f_aa);


  // Second move (verifier's challenge)
  // x' = oracle(x, F, A, Y)

  BIG x_challenge;
  sharing_proof_challenge(x, ff, aa, yy, x_challenge);

  // Third move (prover)
  // z_r = r * x' + rho mod p
  // z_alpha = x' * sum [s_i*x^i | i <- [1..n]] + alpha mod p

  BIG z_r;
  BIG_modmul(z_r, witness.r, x_challenge, curve_order);
  BIG_modadd(z_r, z_r, rho_fe, curve_order);

  DBIG z_r_dbig;

  BIG_mul(z_r_dbig, witness.r, x_challenge);

  DBIG rho_fe_big;
  BIG_dscopy(rho_fe_big, rho_fe);

  BIG_dadd(z_r_dbig, z_r_dbig, rho_fe_big);

  
  BIG z_alpha;
  BIG_zero(z_alpha);

  BIG_modmul(z_alpha, witness.s[0], x_pows[0], curve_order);


  for(unsigned int i=1; i<instance.public_keys.size(); i++){

    BIG tmp;
    BIG_modmul(tmp, witness.s[i], x_pows[i], curve_order);
    BIG_modadd(z_alpha, z_alpha, tmp, curve_order);

  }


  BIG_modmul(z_alpha, z_alpha, x_challenge, curve_order);
  BIG_modadd(z_alpha, z_alpha, alpha_fe, curve_order);


  ZkProofSharing* proof = new ZkProofSharing();

  proof->ff = ff;
  proof->aa = aa;
  proof->yy = yy;
  BIG_rcopy(proof->z_r, z_r);
  BIG_dcopy(proof->z_r_dbig, z_r_dbig);
  BIG_rcopy(proof->z_alpha, z_alpha);


  return proof;


}


template <class Cryptosystem>
bool verify_sharing(const Cryptosystem &C, SharingInstance& instance, ZkProofSharing* nizk){

  if (instance.check_instance() == false){
    return false;
  }

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);

  BIG x;
  instance.hash_to_scalar(x);

  BIG x_challenge;
  sharing_proof_challenge(x, nizk->ff, nizk->aa, nizk->yy, x_challenge);

  BIG* x_pows = new BIG[instance.public_keys.size()];
  BIG_rcopy(x_pows[0], x);

  for(unsigned int i=1; i<instance.public_keys.size(); i++){

    BIG_modmul(x_pows[i], x_pows[i-1], x, curve_order);
  }

  // First verification equation
  // R^x' * F == g_1^z_r

  ECP lhs;
  ECP_copy(&lhs, &instance.g_r);
  ECP_mul(&lhs, x_challenge);
  ECP_add(&lhs, &nizk->ff);

  ECP rhs;
  ECP_copy(&rhs, &instance.g1_gen);

  ECP_mul(&rhs, nizk->z_r);

  if(ECP_equals(&lhs, &rhs) == 0){
    return false;
  }

  // Second verification equation
  // Verify: product [A_k ^ sum [i^k * x^i | i <- [1..n]] | k <- [0..t-1]]^x' * A
  // == g_2^z_alpha

  ECP_inf(&lhs);
  ECP_inf(&rhs);

  ECP_copy(&lhs, &public_evals[0]);
  ECP_mul(&lhs, x_pows[0]);


  for(unsigned int i=1; i<public_evals.size(); i++){

    ECP tmp;
    ECP_copy(&tmp, &public_evals[i]);
    ECP_mul(&tmp, x_pows[i]);
    ECP_add(&lhs, &tmp);

  }

  ECP_mul(&lhs, x_challenge);
  ECP_add(&lhs, &nizk->aa);

  ECP_copy(&rhs, &instance.g);
  ECP_mul(&rhs, nizk->z_alpha);


  if(ECP_equals(&lhs, &rhs) == 0){
    return false;
  }

  // Third verification equation
  // LHS = product [C_i ^ x^i | i <- [1..n]]^x' * Y
  // RHS = product [y_i ^ x^i | i <- 1..n]^z_r * g_1^z_alpha


  QFI lhs_qfi = instance.ciphertexts[0].c2();

  char* x_pow_bytes = new char[48];
  BIG_toBytes(x_pow_bytes, x_pows[0]);
  Mpz x_pow_mpz;
  x_pow_mpz.BIG_to_Mpz(x_pow_bytes, 48);
  delete[] x_pow_bytes;


  C.Cl_G().nupow(lhs_qfi, lhs_qfi, x_pow_mpz);

  for(unsigned int i=1; i<instance.ciphertexts.size(); i++){

    char* x_pow_bytes_i = new char[48];
    BIG_toBytes(x_pow_bytes_i, x_pows[i]);
    Mpz x_pow_mpz_i;
    x_pow_mpz_i.BIG_to_Mpz(x_pow_bytes_i, 48);
    delete[] x_pow_bytes_i;

    QFI ci = instance.ciphertexts[i].c2();
    QFI ci_exp_x_pow;
    C.Cl_G().nupow(ci_exp_x_pow, ci, x_pow_mpz_i);
    C.Cl_Delta().nucomp (lhs_qfi, lhs_qfi, ci_exp_x_pow);

  }

  char* x_challenge_bytes = new char[48];
  BIG_toBytes(x_challenge_bytes, x_challenge);
  Mpz x_challenge_mpz;
  x_challenge_mpz.BIG_to_Mpz(x_challenge_bytes, 48);
  delete[] x_challenge_bytes;


  C.Cl_G().nupow(lhs_qfi, lhs_qfi, x_challenge_mpz);
  C.Cl_Delta().nucomp (lhs_qfi, lhs_qfi, nizk->yy);



  QFI rhs_qfi;

  instance.public_keys[0].exponentiation(C, rhs_qfi, x_pow_mpz);


  for(unsigned int i=1; i<instance.public_keys.size(); i++){

    char* x_pow_bytes = new char[48];
    BIG_toBytes(x_pow_bytes, x_pows[i]);

    Mpz x_pow_mpz;
    x_pow_mpz.BIG_to_Mpz(x_pow_bytes, 48);
    delete[] x_pow_bytes;

    QFI acc_pk_i;
    instance.public_keys[i].exponentiation(C, acc_pk_i, x_pow_mpz);

    C.Cl_Delta().nucomp (rhs_qfi, rhs_qfi, acc_pk_i);

  }


  char* z_alpha_bytes = new char[48];
  BIG_toBytes(z_alpha_bytes, nizk->z_alpha);
  Mpz z_alpha_mpz;
  z_alpha_mpz.BIG_to_Mpz(z_alpha_bytes, 48);


  QFI f_z_alpha = C.power_of_f(z_alpha_mpz);

  char* z_r_bytes = new char[48*2];
  DBIG c;
  BIG_dcopy(c, nizk->z_r_dbig);
  BIG_dnorm(c);


  int i;
  for (i = (48*2) - 1; i >= 0; i--)
  {
      z_r_bytes[i] = c[0] & 0xff;
      BIG_dshr(c, 8);
  }

  Mpz z_r_mpz;
  z_r_mpz.BIG_to_Mpz(z_r_bytes, 48*2);


  C.Cl_G().nupow(rhs_qfi, rhs_qfi, z_r_mpz);
  C.Cl_Delta().nucomp(rhs_qfi, rhs_qfi, f_z_alpha);



  if(!(lhs_qfi == rhs_qfi)){
    return false;
  }


  return true;

}







int
main (int argc, char *argv[])
{

  /** Class used to represent a public key of the cryptosystem */
  using SecretKey = _Utils::CL_HSM_SecretKey<CL_HSMqk>;

  /** Class used to represent a public key of the cryptosystem */
  using PublicKey = _Utils::CL_HSM_PublicKey<CL_HSMqk>;
  /** Class used to represent a ciphertext for the cryptosystem */
  using ClearText = _Utils::CL_HSM_ClearText<CL_HSMqk>;
  /** Class used to represent a ciphertext for the cryptosystem */
  using CipherText = _Utils::CL_HSM_CipherText<CL_HSMqk>;

  int node_count = 50;
  int threshold = 17;


  RandGen randgen;
  randseed_from_argv (randgen, argc, argv);

  csprng RNG;
  int i;
  char pr[10];
  unsigned long ran;

  time((time_t *)&ran);
  pr[0] = ran;
  pr[1] = ran >> 8;
  pr[2] = ran >> 16;
  pr[3] = ran >> 24;
  for (i = 4; i < 10; i++) pr[i] = i; /*****4****/
  RAND_seed(&RNG, 10, pr);

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);

  ECP g1_gen;
  ECP g;
  ECP_generator(&g1_gen);
  ECP_generator(&g);

  vector<PublicKey> public_keys;
  vector<CipherText> ciphertexts;


  BIG* a = new BIG[threshold];
  vector<ECP> aa; 


  /* With a random q twice as big as the security level */
  //CL_HSMqk C (2*SecLevel::All()[1], 1, SecLevel::All()[1], randgen, false);

  char*  q_bytes = new char[48];
  BIG_toBytes(q_bytes, curve_order);
  Mpz q_mpz;
  q_mpz.BIG_to_Mpz(q_bytes, 48);

  CL_HSMqk C(q_mpz, 1, SecLevel::All()[1], randgen);


  for(int i=0; i<node_count; i++){
    SecretKey sk = C.keygen (randgen);
    PublicKey pk = C.keygen (sk);
    public_keys.push_back(pk);
  }

  for(int i=0; i<threshold; i++){

    BIG_randomnum(a[i], curve_order, &RNG);
    ECP x_g;
    ECP_copy(&x_g, &g);
    ECP_mul(&x_g, a[i]);
    aa.push_back(x_g);
    
  }

  BIG r;
  BIG_randomnum(r, curve_order, &RNG);

  ECP rr;
  ECP_copy(&rr, &g1_gen);
  ECP_mul(&rr, r);

  BIG* s = new BIG[node_count];

  vector<ClearText> msgs;


  // s = [sum [a_k ^ i^k | (a_k, k) <- zip a [0..t-1]] | i <- [1..n]]

  BIG ibig, one;
  BIG_one(one);
  BIG_one(ibig);

  vector<ECP> public_evals;


  for(int i=0; i<node_count; i++){

    BIG ipow;
    BIG_one(ipow);

    BIG acc;
    BIG_zero(acc);

    for(int i=0; i<threshold; i++){

      BIG temp;

      BIG_modmul(temp, a[i], ipow, curve_order);
      BIG_modadd(acc, acc, temp, curve_order);
      BIG_modmul(ipow, ipow, ibig, curve_order);
    }

    BIG_rcopy(s[i], acc); 

    char* acc_bytes = new char[48];
    BIG_toBytes(acc_bytes, acc);

    Mpz acc_mpz;
    acc_mpz.BIG_to_Mpz(acc_bytes, 48);
    
    msgs.push_back(ClearText(C, acc_mpz));

    ECP acc_ecp;
    ECP_copy(&acc_ecp, &g);
    ECP_mul(&acc_ecp, acc);

    public_evals.push_back(acc_ecp);

    delete[] acc_bytes;

    BIG_modadd(ibig, ibig, one, curve_order);
    
  }

  vector<CipherText> cc;

  char* r_bytes = new char[48];
  BIG_toBytes(r_bytes, r);
  Mpz r_mpz;
  r_mpz.BIG_to_Mpz(r_bytes, 48);

  auto begin = std::chrono::high_resolution_clock::now();

  vector<CipherText> ciphers = C.encrypt_all (public_keys, msgs, r_mpz);

  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);

  cout<<"Ecnryption time: "<<elapsed.count()<<endl;



  begin = std::chrono::high_resolution_clock::now();


  SharingInstance instance(g1_gen, g, public_keys, rr, ciphers, public_evals);

  Witness witness;
  BIG_rcopy(witness.r, r);
  witness.s = s;


  ZkProofSharing* nizk = prove_sharing(C, witness, instance);

  end = std::chrono::high_resolution_clock::now();
  elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);

  cout<<"Elapsed time: "<<elapsed.count()<<endl;



  begin = std::chrono::high_resolution_clock::now();

  bool flag = verify_sharing(C, instance, nizk);

  end = std::chrono::high_resolution_clock::now();

  elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);

  cout<<"Elapsed time: "<<elapsed.count()<<endl;



  cout<<flag<<endl;



  

  return EXIT_SUCCESS;
}
