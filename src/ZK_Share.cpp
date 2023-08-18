#include "ZK_Share.hpp"

SharingInstance::SharingInstance(ECP& g1_gen, ECP& g, PublicKey* public_keys,
                      QFI& g_r, CipherText* ciphertexts, ECP* public_coefficients){
    
    this->g1_gen = g1_gen;
    this->g = g;
    this->public_keys = public_keys;
    this->g_r = g_r;
    this->ciphertexts = ciphertexts;
    this->public_coefficients = public_coefficients;

}

void SharingInstance::hash_to_scalar(BIG x, unsigned int node_count, unsigned int threshold){

  hash256 hash;
  HASH256_init(&hash);

  for(unsigned int i=0; i<DOMAIN_PROOF_OF_SHARING_INSTANCE.length(); i++){

    HASH256_process(&hash, int(DOMAIN_PROOF_OF_SHARING_INSTANCE[i]));
  }


  std::vector<unsigned char> x_bytes_g1_gen, y_bytes_g1_gen;
  BIG x_g1_gen,y_g1_gen;
  Mpz x_mpz_g1_gen, y_mpz_g1_gen;
  ECP_get(x_g1_gen, y_g1_gen, &g1_gen);

  x_mpz_g1_gen.BIG_to_Mpz(x_g1_gen);
  y_mpz_g1_gen.BIG_to_Mpz(y_g1_gen);

  x_mpz_g1_gen.mpz_to_vector(x_bytes_g1_gen);
  y_mpz_g1_gen.mpz_to_vector(y_bytes_g1_gen);

  process_mpz_hash(hash, x_bytes_g1_gen);
  process_mpz_hash(hash, y_bytes_g1_gen);

  std::vector<unsigned char> x_bytes_g, y_bytes_g;
  BIG x_g,y_g;
  Mpz x_mpz_g, y_mpz_g;
  ECP_get(x_g, y_g, &g);

  x_mpz_g.BIG_to_Mpz(x_g);
  y_mpz_g.BIG_to_Mpz(y_g);

  x_mpz_g.mpz_to_vector(x_bytes_g);
  y_mpz_g.mpz_to_vector(y_bytes_g);

  process_mpz_hash(hash, x_bytes_g);
  process_mpz_hash(hash, y_bytes_g);


  for(unsigned int i=0; i<node_count; i++){

    std::vector<unsigned char> mpz_char;

    public_keys[i].elt().a().mpz_to_vector(mpz_char);
    process_mpz_hash(hash, mpz_char);
    mpz_char.clear();

    public_keys[i].elt().b().mpz_to_vector(mpz_char);
    process_mpz_hash(hash, mpz_char);
    mpz_char.clear();

    public_keys[i].elt().c().mpz_to_vector(mpz_char);
    process_mpz_hash(hash, mpz_char);

  }

  std::vector<unsigned char> mpz_char;

  g_r.a().mpz_to_vector(mpz_char);
  process_mpz_hash(hash, mpz_char);
  mpz_char.clear();

  g_r.b().mpz_to_vector(mpz_char);
  process_mpz_hash(hash, mpz_char);
  mpz_char.clear();

  g_r.c().mpz_to_vector(mpz_char);
  process_mpz_hash(hash, mpz_char);
  mpz_char.clear();


  for(unsigned int i=0; i<node_count; i++){

    std::vector<unsigned char> mpz_char;

    ciphertexts[i].c1().a().mpz_to_vector(mpz_char);
    process_mpz_hash(hash, mpz_char);
    mpz_char.clear();

    ciphertexts[i].c1().b().mpz_to_vector(mpz_char);
    process_mpz_hash(hash, mpz_char);
    mpz_char.clear();

    ciphertexts[i].c1().c().mpz_to_vector(mpz_char);
    process_mpz_hash(hash, mpz_char);
    mpz_char.clear();

    ciphertexts[i].c2().a().mpz_to_vector(mpz_char);
    process_mpz_hash(hash, mpz_char);
    mpz_char.clear();

    ciphertexts[i].c2().b().mpz_to_vector(mpz_char);
    process_mpz_hash(hash, mpz_char);
    mpz_char.clear();

    ciphertexts[i].c2().c().mpz_to_vector(mpz_char);
    process_mpz_hash(hash, mpz_char);
    mpz_char.clear();

  }

  for(unsigned int i=0; i<threshold; i++){

    std::vector<unsigned char> x_bytes, y_bytes;
    BIG x,y;
    Mpz x_mpz, y_mpz;
    ECP_get(x, y, &public_coefficients[i]);

    x_mpz.BIG_to_Mpz(x);
    y_mpz.BIG_to_Mpz(y);

    x_mpz.mpz_to_vector(x_bytes);
    y_mpz.mpz_to_vector(y_bytes);

    process_mpz_hash(hash, x_bytes);
    process_mpz_hash(hash, y_bytes);

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


void sharing_proof_challenge(BIG& x, QFI& ff, ECP& aa, QFI& yy , BIG& x_challenge){

  hash256 hash;
  HASH256_init(&hash);

  for(unsigned int i=0; i<DOMAIN_PROOF_OF_SHARING_CHALLENGE.length(); i++){

    HASH256_process(&hash, int(DOMAIN_PROOF_OF_SHARING_CHALLENGE[i]));
  }

  std::vector<unsigned char> x_bytes;
  Mpz x_mpz;
  x_mpz.BIG_to_Mpz(x);
  x_mpz.mpz_to_vector(x_bytes);
  process_mpz_hash(hash, x_bytes);

  std::vector<unsigned char> mpz_char;

  ff.a().mpz_to_vector(mpz_char);
  process_mpz_hash(hash, mpz_char);
  mpz_char.clear();

  ff.b().mpz_to_vector(mpz_char);
  process_mpz_hash(hash, mpz_char);
  mpz_char.clear();

  ff.c().mpz_to_vector(mpz_char);
  process_mpz_hash(hash, mpz_char);
  mpz_char.clear();


  std::vector<unsigned char> x_bytes_aa, y_bytes_aa;
  BIG x_aa,y_aa;
  Mpz x_mpz_aa, y_mpz_aa;
  ECP_get(x_aa, y_aa, &aa);

  x_mpz_aa.BIG_to_Mpz(x_aa);
  y_mpz_aa.BIG_to_Mpz(y_aa);

  x_mpz_aa.mpz_to_vector(x_bytes_aa);
  y_mpz_aa.mpz_to_vector(y_bytes_aa);

  process_mpz_hash(hash, x_bytes_aa);
  process_mpz_hash(hash, y_bytes_aa);


  yy.a().mpz_to_vector(mpz_char);
  process_mpz_hash(hash, mpz_char);
  mpz_char.clear();

  yy.b().mpz_to_vector(mpz_char);
  process_mpz_hash(hash, mpz_char);
  mpz_char.clear();

  yy.c().mpz_to_vector(mpz_char);
  process_mpz_hash(hash, mpz_char);
  mpz_char.clear();

  char* hash_output = new char[32];
  HASH256_hash(&hash, hash_output);

  csprng hash_RNG;
  RAND_seed(&hash_RNG, 32, hash_output);

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);
  
  BIG_randomnum(x_challenge, curve_order, &hash_RNG);

  delete[] hash_output;

}



ZkProofSharing* prove_sharing(const CL_HSMqk &C, Witness& witness, SharingInstance& instance, RandGen& randgen, csprng& RNG, unsigned int node_count, unsigned int threshold){

  //if (instance.check_instance() == false){
  //  return nullptr;
  //}

  const int hash256_nbits = 256;

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);

  BIG alpha_fe;
  BIG_randomnum(alpha_fe, curve_order, &RNG);

  Mpz rho = randgen.random_mpz_2exp(witness.get_r().nbits() + hash256_nbits + 40); 

  Mpz alpha;
  alpha.BIG_to_Mpz(alpha_fe);

  QFI ff;
  C.power_of_h(ff, rho);

  ECP aa = instance.g;
  ECP_mul(&aa, alpha_fe);

  BIG x;
  instance.hash_to_scalar(x, node_count, threshold);

  BIG* x_pows = new BIG[node_count];
  BIG_rcopy(x_pows[0], x);

  for(unsigned int i=1; i<node_count; i++){

    BIG_modmul(x_pows[i], x_pows[i-1], x, curve_order);
  }

  //converting from BIG representation to MPZ representation
  std::vector<Mpz> x_pows_mpz;
  for(unsigned int i=0; i<node_count; i++){

    Mpz x_pow_mpz;
    x_pow_mpz.BIG_to_Mpz(x_pows[i]);
    x_pows_mpz.push_back(x_pow_mpz);
  }

  std::vector<QFI> pks;
  for(unsigned int i=0; i<node_count; i++){
    pks.push_back(instance.public_keys[i].elt());
  }

  QFI acc_pk;
  C.Cl_G().mult_exp(acc_pk, pks, x_pows_mpz);

  QFI f_aa;
  f_aa = C.power_of_f(alpha);

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

  Mpz x_challenge_mpz;
  x_challenge_mpz.BIG_to_Mpz(x_challenge);

  Mpz z_r;
  Mpz::mul(z_r, witness.get_r(), x_challenge_mpz);
  Mpz::add(z_r, z_r, rho);
  
  BIG* witness_s =  witness.get_s();
  BIG z_alpha;
  BIG_zero(z_alpha);
  BIG_modmul(z_alpha, witness_s[0], x_pows[0], curve_order);
  for(unsigned int i=1; i<node_count; i++){

    BIG tmp;
    BIG_modmul(tmp, witness_s[i], x_pows[i], curve_order);
    BIG_modadd(z_alpha, z_alpha, tmp, curve_order);
  }
  BIG_modmul(z_alpha, z_alpha, x_challenge, curve_order);
  BIG_modadd(z_alpha, z_alpha, alpha_fe, curve_order);


  ZkProofSharing* proof = new ZkProofSharing();

  proof->ff = ff;
  proof->aa = aa;
  proof->yy = yy;
  proof->z_r = z_r;
  BIG_rcopy(proof->z_alpha, z_alpha);

  return proof;

}



bool verify_sharing(const CL_HSMqk &C, SharingInstance& instance, ZkProofSharing* nizk, unsigned int node_count, unsigned int threshold){

  //if (instance.check_instance() == false){
    //return false;
  //}

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);

  BIG x;
  instance.hash_to_scalar(x, node_count, threshold);


  BIG x_challenge;
  sharing_proof_challenge(x, nizk->ff, nizk->aa, nizk->yy, x_challenge);


  BIG* x_pows = new BIG[node_count];
  BIG_rcopy(x_pows[0], x);

  for(unsigned int i=1; i<node_count; i++){

    BIG_modmul(x_pows[i], x_pows[i-1], x, curve_order);
  }

  // First verification equation
  // R^x' * F == g_1^z_r

  Mpz x_challenge_mpz;
  x_challenge_mpz.BIG_to_Mpz(x_challenge);

  QFI lhs_first;
  C.Cl_G().nupow(lhs_first, instance.g_r, x_challenge_mpz);
  C.Cl_Delta().nucomp(lhs_first, lhs_first, nizk->ff);

  QFI rhs_first;
  C.power_of_h(rhs_first, nizk->z_r);

  Mpz x_mpz;
  x_mpz.BIG_to_Mpz(x);


  if(!(lhs_first == rhs_first)){
    return false;
  }

  // Second verification equation
  // Verify: product [A_k ^ sum [i^k * x^i | i <- [1..n]] | k <- [0..t-1]]^x' * A
  // == g_2^z_alpha

  ECP lhs;
  ECP rhs;
  ECP_inf(&lhs);
  ECP_inf(&rhs);

  BIG kbig;
  BIG_zero(kbig);
  BIG one;
  BIG_one(one);

  BIG* accs = new BIG[threshold];

  for(unsigned int i = 0; i < threshold; i++){

    BIG acc;
    BIG_zero(acc);
    BIG x_pow;
    BIG_rcopy(x_pow, x);
    BIG ibig;
    BIG_one(ibig);

    for(unsigned int j = 0; j < node_count; j++){
      BIG tmp;
      BIG exp_res;
      powmod(exp_res, ibig, kbig, curve_order);
      BIG_modmul(tmp, exp_res, x_pow, curve_order);
      BIG_modadd(acc, acc, tmp, curve_order);
      BIG_modmul(x_pow, x_pow, x, curve_order);
      BIG_modadd(ibig, ibig, one, curve_order);

    }

    BIG_rcopy(accs[i], acc);
    BIG_modadd(kbig, kbig, one, curve_order);

  }

  //multi-exponentiation
  ECP_muln(&lhs,threshold, &instance.public_coefficients[0], accs);
  delete[] accs;

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

  //converting from BIG representation to MPZ representation
  std::vector<Mpz> x_pows_mpz;
  for(unsigned int i=0; i<node_count; i++){

    Mpz x_pow_mpz;
    x_pow_mpz.BIG_to_Mpz(x_pows[i]);
    x_pows_mpz.push_back(x_pow_mpz);
  }

  std::vector<QFI> ciphers;
  for(unsigned int i=0; i<node_count; i++){
    ciphers.push_back(instance.ciphertexts[i].c2());
  }


  QFI lhs_qfi;
  QFI rhs_qfi;
  C.Cl_G().mult_exp(lhs_qfi, ciphers, x_pows_mpz);

  C.Cl_G().nupow(lhs_qfi, lhs_qfi, x_challenge_mpz);
  C.Cl_Delta().nucomp (lhs_qfi, lhs_qfi, nizk->yy);

  std::vector<QFI> pks;
  for(unsigned int i=0; i<node_count; i++){
    pks.push_back(instance.public_keys[i].elt());
  }

  C.Cl_G().mult_exp(rhs_qfi, pks, x_pows_mpz);

  Mpz z_alpha_mpz;
  z_alpha_mpz.BIG_to_Mpz(nizk->z_alpha);

  QFI f_z_alpha;
  f_z_alpha = C.power_of_f(z_alpha_mpz);
  C.Cl_G().nupow(rhs_qfi, rhs_qfi, nizk->z_r);
  C.Cl_Delta().nucomp(rhs_qfi, rhs_qfi, f_z_alpha);

  if(!(lhs_qfi == rhs_qfi)){
    return false;
  }

  return true;

}