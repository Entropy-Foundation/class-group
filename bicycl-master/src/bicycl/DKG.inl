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
#ifndef DKG_INL__
#define DKG_INL__


void process_mpz_hash(hash256& hash, std::vector<unsigned char>& mpz_char){

    for(size_t j=0; j<mpz_char.size(); j++){

      HASH256_process(&hash, int(mpz_char[j]));
    }

  }

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


/*bool SharingInstance::check_instance(){

  if (this->public_keys.size() == 0 || this->public_coefficients.size() == 0){
    return false;
  }

  if (this->public_keys.size() != this->ciphertexts.size()){
    return false;
  }

  return true;

}*/


Witness::Witness(){}


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


NIZK::NIZK(int nodes, int threshold): node_count(nodes), threshold(threshold){

}



void NIZK::sharing_proof_challenge(BIG& x, QFI& ff, ECP& aa, QFI& yy , BIG& x_challenge){

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



ZkProofSharing* NIZK::prove_sharing(const CL_HSMqk &C, Witness& witness, SharingInstance& instance, RandGen& randgen, csprng& RNG){

  //if (instance.check_instance() == false){
  //  return nullptr;
  //}

  const int hash256_nbits = 256;

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);

  BIG alpha_fe;
  BIG_randomnum(alpha_fe, curve_order, &RNG);

  Mpz rho = randgen.random_mpz_2exp(witness.r.nbits() + hash256_nbits + 40); 

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
  Mpz::mul(z_r, witness.r, x_challenge_mpz);
  Mpz::add(z_r, z_r, rho);
  
  BIG z_alpha;
  BIG_zero(z_alpha);
  BIG_modmul(z_alpha, witness.s[0], x_pows[0], curve_order);
  for(unsigned int i=1; i<node_count; i++){

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
  proof->z_r = z_r;
  BIG_rcopy(proof->z_alpha, z_alpha);

  return proof;

}



bool NIZK::verify_sharing(const CL_HSMqk &C, SharingInstance& instance, ZkProofSharing* nizk){

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


inline DKG_Dealing::DKG_Dealing(CipherText* ciphertexts, QFI& g_r, ECP* public_coefficients,
                                 ZkProofSharing* nizk_share){

  this->g_r = g_r;
  this->ciphertexts = ciphertexts;
  this->public_coefficients = public_coefficients;
  this->nizk_share = nizk_share;

}

void DKG_Helper::compute_benchmarks(){

  RandGen randgen;
  randseed (randgen);
  csprng RNG;
  randseed (RNG);

  NIZK nizk(node_count, threshold);
  CipherText* ciphers = new CipherText[node_count];
  DKG_Dealing dealing;
  ECP g1_gen, g;
  Mpz q, p;
  read_config(q, p, g1_gen, g);
  CL_HSMqk C(q,1,p);

  ClearText* poly_evals_cleartext = new ClearText[node_count];
  BIG* poly_evals = new BIG[node_count];
  ECP* public_coefficients = new ECP[threshold];

  //generate polynomial evaluations
  gen_poly_evals(RNG, poly_evals, public_coefficients, g);

  for(unsigned int i=0; i<node_count; i++){

    Mpz poly_eval_mpz;
    poly_eval_mpz.BIG_to_Mpz(poly_evals[i]);
    poly_evals_cleartext[i] = ClearText(C, poly_eval_mpz);

  }

  Mpz r(randgen.random_mpz (C.encrypt_randomness_bound()));
  QFI g_r;
  C.power_of_h(g_r, r);


  auto begin = std::chrono::high_resolution_clock::now();

  for(int i=0; i<10; i++){

    C.encrypt_all (public_keys, poly_evals_cleartext, r, ciphers, node_count);

  }

  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
  std::cout<<"Encryption Time: "<<elapsed.count()/10<<std::endl;


  begin = std::chrono::high_resolution_clock::now();

  for(int i=0; i<10; i++){

    SharingInstance instance(g1_gen, g, public_keys, g_r, ciphers, public_coefficients);

    Witness witness;
    witness.r = r;
    witness.s = poly_evals;

    ZkProofSharing* sharing_proof;
    sharing_proof = nizk.prove_sharing(C, witness, instance, randgen, RNG);

  }

  end = std::chrono::high_resolution_clock::now();
  elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
  std::cout<<"Sharing proof gen time: "<<elapsed.count()/10<<std::endl;

  SharingInstance instance(g1_gen, g, public_keys, g_r, ciphers, public_coefficients);

  Witness witness;
  witness.r = r;
  witness.s = poly_evals;

  ZkProofSharing* sharing_proof;
  sharing_proof = nizk.prove_sharing(C, witness, instance, randgen, RNG);



  dealing.ciphertexts = ciphers;
  dealing.g_r = g_r;
  dealing.public_coefficients = public_coefficients;
  dealing.nizk_share = sharing_proof;


  begin = std::chrono::high_resolution_clock::now();

  for(int i=0; i<10; i++){

    SharingInstance instance(g1_gen, g, public_keys, dealing.g_r, dealing.ciphertexts, dealing.public_coefficients);
    nizk.verify_sharing(C, instance, dealing.nizk_share);

  }

  end = std::chrono::high_resolution_clock::now();
  elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
  std::cout<<"Sharing proof ver time: "<<elapsed.count()/10<<std::endl;


  //decrypt

  SecretKey sk = C.keygen (randgen);
  PublicKey pk = C.keygen (sk);

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);

  BIG a;
  BIG_randomnum(a, curve_order, &RNG);

  Mpz a_mpz;
  a_mpz.BIG_to_Mpz(a);

  ClearText  a_cleartext = ClearText(C, a_mpz);


  CipherText cipher_a = C.encrypt (pk, a_cleartext,
                          randgen);



  begin = std::chrono::high_resolution_clock::now();

  for(int i=0; i<10; i++){

    CipherText cipher_a = C.encrypt (pk, a_cleartext,
                          randgen);

  }

  end = std::chrono::high_resolution_clock::now();
  elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
  std::cout<<"Encryption time Single: "<<elapsed.count()/10<<std::endl;




  begin = std::chrono::high_resolution_clock::now();

  for(int i=0; i<10; i++){
    ClearText res = C.decrypt (sk, cipher_a);
  }

  end = std::chrono::high_resolution_clock::now();
  elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
  std::cout<<"Decryption time Single: "<<elapsed.count()/10<<std::endl;


}


inline void DKG_Helper::randseed (RandGen &randgen)
  {
    BICYCL::Mpz seed;

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());

    randgen.set_seed (seed);

  }


  // this is taken from miracl's testbls.cpp file: https://github.com/miracl/core/blob/b24694584adcf6f16ae5d9e169fd018a1464e8fb/cpp/testbls.cpp#L301
  //todo: check if this is a secure way of seeding the random number generator
  inline void DKG_Helper::randseed (csprng& RNG)
  {
    int i;
    unsigned long ran;

    char raw[100];
    octet RAW = {0, sizeof(raw), raw};

    time((time_t *)&ran);

    RAW.len = 100;              // fake random seed source
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (i = 4; i < 100; i++) RAW.val[i] = i;

    CREATE_CSPRNG(&RNG, &RAW);  // initialise strong RNG
  }



void DKG_Helper::gen_test_config(){

  const std::string config_folder = "config";
  const std::string config_file_sks = config_folder + "/sks_" + "nodes_"+std::to_string(node_count)+"_threshold_"+std::to_string(threshold)+".bin";
  const std::string config_file_pks = config_folder + "/pks_" + "nodes_"+std::to_string(node_count)+"_threshold_"+std::to_string(threshold)+".bin";
  const std::string config_file_cl = config_folder + "/cl_config_128_" + "nodes_"+std::to_string(node_count)+"_threshold_"+std::to_string(threshold)+".bin";

  //128 bit security level
  //SecLevel sec_level(128);
  RandGen randgen;
  csprng RNG;
  randseed (randgen);
  randseed (RNG);

  NIZK nizk(node_count, threshold);
  Mpz q_mpz;
  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);
  q_mpz.BIG_to_Mpz (curve_order);
  
  ECP g1_gen;
  ECP g;
  ECP_generator(&g1_gen);
  ECP_generator(&g);
  BIG r;
  BIG_randomnum(r, curve_order, &RNG);
  ECP_mul(&g, r);

  std::vector<SecretKey> secret_keys;
  std::vector<PublicKey> public_keys;
  std::vector<CipherText> ciphertexts;

  CL_HSMqk C(q_mpz, 1, SecLevel::All()[1], randgen);

  std::ofstream outfile_cl(config_file_cl, std::ios::binary);
    if (!outfile_cl.is_open()) {
      throw std::invalid_argument ("Unable to open file");
      return;
  }

  //storing CL config parameters on disk
  std::vector<unsigned char> q_vec; 
  C.q_.mpz_to_vector(q_vec);

  size_t q_size = q_vec.size();
  outfile_cl.write(reinterpret_cast<const char*>(&q_size), sizeof(q_size));
  outfile_cl.write(reinterpret_cast<const char*>(q_vec.data()), q_size);

  std::vector<unsigned char> p_vec; 
  C.p_.mpz_to_vector(p_vec);

  size_t p_size = p_vec.size();
  outfile_cl.write(reinterpret_cast<const char*>(&p_size), sizeof(p_size));
  outfile_cl.write(reinterpret_cast<const char*>(p_vec.data()), p_size);

  BIG g1_gen_x, g1_gen_y, g_x, g_y;
  Mpz g1_gen_x_mpz, g1_gen_y_mpz, g_x_mpz, g_y_mpz;

  ECP_get(g1_gen_x, g1_gen_y, &g1_gen);
  ECP_get(g_x, g_y, &g);


  g1_gen_x_mpz.BIG_to_Mpz(g1_gen_x);
  g1_gen_y_mpz.BIG_to_Mpz(g1_gen_y);
  g_x_mpz.BIG_to_Mpz(g_x);
  g_y_mpz.BIG_to_Mpz(g_y);


  std::vector<unsigned char> g1_gen_x_vec; 
  g1_gen_x_mpz.mpz_to_vector(g1_gen_x_vec);

  size_t g1_gen_x_size = g1_gen_x_vec.size();
  outfile_cl.write(reinterpret_cast<const char*>(&g1_gen_x_size), sizeof(g1_gen_x_size));
  outfile_cl.write(reinterpret_cast<const char*>(g1_gen_x_vec.data()), g1_gen_x_size);

  std::vector<unsigned char> g1_gen_y_vec; 
  g1_gen_y_mpz.mpz_to_vector(g1_gen_y_vec);

  size_t g1_gen_y_size = g1_gen_y_vec.size();
  outfile_cl.write(reinterpret_cast<const char*>(&g1_gen_y_size), sizeof(g1_gen_y_size));
  outfile_cl.write(reinterpret_cast<const char*>(g1_gen_y_vec.data()), g1_gen_y_size);

  std::vector<unsigned char> g_x_vec; 
  g_x_mpz.mpz_to_vector(g_x_vec);

  size_t g_x_size = g_x_vec.size();
  outfile_cl.write(reinterpret_cast<const char*>(&g_x_size), sizeof(g_x_size));
  outfile_cl.write(reinterpret_cast<const char*>(g_x_vec.data()), g_x_size);

  std::vector<unsigned char> g_y_vec; 
  g_y_mpz.mpz_to_vector(g_y_vec);

  size_t g_y_size = g_y_vec.size();
  outfile_cl.write(reinterpret_cast<const char*>(&g_y_size), sizeof(g_y_size));
  outfile_cl.write(reinterpret_cast<const char*>(g_y_vec.data()), g_y_size);


  outfile_cl.close();

  //generate pk and sks for all nodes
  for(unsigned int i=0; i<node_count; i++){
    SecretKey sk = C.keygen (randgen);
    PublicKey pk = C.keygen (sk);

    secret_keys.push_back(sk);
    public_keys.push_back(pk);
  }

  std::ofstream outfile_sk(config_file_sks, std::ios::binary);
    if (!outfile_sk.is_open()) {
      throw std::invalid_argument ("Unable to open file");
      return;
  }

  //storing secret keys of all nodes on disk
  for(unsigned int i=0; i<node_count; i++){

    std::vector<unsigned char> vec;
    secret_keys[i].mpz_to_vector(vec);

    size_t size = vec.size();
    outfile_sk.write(reinterpret_cast<const char*>(&size), sizeof(size));
    outfile_sk.write(reinterpret_cast<const char*>(vec.data()), size);
  }

  outfile_sk.close();


  //storing public keys of all nodes on disk
  std::ofstream outfile_pk(config_file_pks, std::ios::binary);
    if (!outfile_pk.is_open()) {
      throw std::invalid_argument ("Unable to open file");
      return;
  }

  for(unsigned int i=0; i<node_count; i++){

    std::vector<unsigned char> vec_a;
    public_keys[i].pk_.a_.mpz_to_vector(vec_a);

    size_t size = vec_a.size();
    outfile_pk.write(reinterpret_cast<const char*>(&size), sizeof(size));
    outfile_pk.write(reinterpret_cast<const char*>(vec_a.data()), size);

    std::vector<unsigned char> vec_b;
    public_keys[i].pk_.b_.mpz_to_vector(vec_b);

    size = vec_b.size();
    outfile_pk.write(reinterpret_cast<const char*>(&size), sizeof(size));
    outfile_pk.write(reinterpret_cast<const char*>(vec_b.data()), size);

    std::vector<unsigned char> vec_c;
    public_keys[i].pk_.c_.mpz_to_vector(vec_c);

    size = vec_c.size();
    outfile_pk.write(reinterpret_cast<const char*>(&size), sizeof(size));
    outfile_pk.write(reinterpret_cast<const char*>(vec_c.data()), size);

  }

  outfile_pk.close();

}

void DKG_Helper::read_config(Mpz& q, Mpz&p, ECP& g1_gen, ECP& g){

  const std::string config_folder = "config";
  const std::string config_file_cl = config_folder + "/cl_config_128_"+ "nodes_"+std::to_string(node_count)+"_threshold_"+std::to_string(threshold)+".bin";

  std::ifstream infile_cl(config_file_cl, std::ios::binary);
    if (infile_cl.is_open()) {

        while (!infile_cl.eof()) {
            // Read the size of the vector
            size_t size;
            infile_cl.read(reinterpret_cast<char*>(&size), sizeof(size));
            if (infile_cl.gcount() != sizeof(size)) break;  // Reached the end of the file

            // Read the vector data
            std::vector<unsigned char> vec_q(size);
            infile_cl.read(reinterpret_cast<char*>(vec_q.data()), size);
            Mpz q_mpz(vec_q);

            size = 0;

            infile_cl.read(reinterpret_cast<char*>(&size), sizeof(size));

            std::vector<unsigned char> vec_p(size);
            infile_cl.read(reinterpret_cast<char*>(vec_p.data()), size);
            Mpz p_mpz(vec_p);

            size = 0;

            infile_cl.read(reinterpret_cast<char*>(&size), sizeof(size));

            std::vector<unsigned char> vec_g1gen_x(size);
            infile_cl.read(reinterpret_cast<char*>(vec_g1gen_x.data()), size);
            Mpz g1gen_x_mpz(vec_g1gen_x);

            size = 0;

            infile_cl.read(reinterpret_cast<char*>(&size), sizeof(size));

            std::vector<unsigned char> vec_g1gen_y(size);
            infile_cl.read(reinterpret_cast<char*>(vec_g1gen_y.data()), size);
            Mpz g1gen_y_mpz(vec_g1gen_y);

            size = 0;

            infile_cl.read(reinterpret_cast<char*>(&size), sizeof(size));

            std::vector<unsigned char> vec_g_x(size);
            infile_cl.read(reinterpret_cast<char*>(vec_g_x.data()), size);
            Mpz g_x_mpz(vec_g_x);

            size = 0;

            infile_cl.read(reinterpret_cast<char*>(&size), sizeof(size));

            std::vector<unsigned char> vec_g_y(size);
            infile_cl.read(reinterpret_cast<char*>(vec_g_y.data()), size);
            Mpz g_y_mpz(vec_g_y);

            q = q_mpz;
            p = p_mpz;

            BIG g1_gen_x, g1_gen_y, g_x, g_y;

            g1gen_x_mpz.Mpz_to_BIG(g1_gen_x);
            g1gen_y_mpz.Mpz_to_BIG(g1_gen_y);
            g_x_mpz.Mpz_to_BIG(g_x);
            g_y_mpz.Mpz_to_BIG(g_y);

            ECP_set(&g1_gen, g1_gen_x, g1_gen_y);
            ECP_set(&g, g_x, g_y);

        }

        infile_cl.close();

    } else {
        std::cerr << "Unable to open file for reading." << std::endl;
        return;
    }

}


bool DKG_Helper::read_public_keys(PublicKey* pks){

  const std::string config_folder = "config";
  const std::string config_file_pks = config_folder + "/pks_" + "nodes_"+std::to_string(node_count)+"_threshold_"+std::to_string(threshold)+".bin";

  // Read the vectors back from the binary file
    std::ifstream infile(config_file_pks, std::ios::binary);
    if (infile.is_open()) {

        Mpz q, p;
        ECP g1_gen, g;
        read_config(q, p, g1_gen, g);

        int i = 0;
        CL_HSMqk C(q,1,p);

        while (!infile.eof()) {
            // Read the size of the vector
            size_t size;
            infile.read(reinterpret_cast<char*>(&size), sizeof(size));
            if (infile.gcount() != sizeof(size)) break;  // Reached the end of the file

            // Read the vector data
            std::vector<unsigned char> vec_a(size);
            infile.read(reinterpret_cast<char*>(vec_a.data()), size);
            Mpz a_mpz(vec_a);

            size = 0;

            infile.read(reinterpret_cast<char*>(&size), sizeof(size));

            std::vector<unsigned char> vec_b(size);
            infile.read(reinterpret_cast<char*>(vec_b.data()), size);
            Mpz b_mpz(vec_b);

            size = 0;

            infile.read(reinterpret_cast<char*>(&size), sizeof(size));

            std::vector<unsigned char> vec_c(size);
            infile.read(reinterpret_cast<char*>(vec_c.data()), size);
            Mpz c_mpz(vec_c);

            pks[i++] = PublicKey(C, QFI(a_mpz,b_mpz,c_mpz));

        }

        infile.close();
        return true;

    } else {
        std::cerr << "Unable to open file for reading." << std::endl;
        return false;
    }

}

void DKG_Helper::gen_poly_evals(csprng& RNG, BIG* poly_evals, ECP* public_coefficients, ECP& g){

  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);

  BIG* a = new BIG[threshold];

  for(unsigned int i=0; i<threshold; i++){

    BIG_randomnum(a[i], curve_order, &RNG);
    ECP x_g;
    ECP_copy(&x_g, &g);
    ECP_mul(&x_g, a[i]);
    public_coefficients[i] = x_g;
  }

  // s = [sum [a_k ^ i^k | (a_k, k) <- zip a [0..t-1]] | i <- [1..n]]

  BIG ibig, one;
  BIG_one(one);
  BIG_one(ibig);

  for(unsigned int i=0; i<node_count; i++){

    BIG ipow;
    BIG_one(ipow);

    BIG acc;
    BIG_zero(acc);

    for(unsigned int i=0; i<threshold; i++){

      BIG temp;

      BIG_modmul(temp, a[i], ipow, curve_order);
      BIG_modadd(acc, acc, temp, curve_order);
      BIG_modmul(ipow, ipow, ibig, curve_order);
    }

    BIG_rcopy(poly_evals[i], acc); 
    ECP acc_ecp;
    ECP_copy(&acc_ecp, &g);
    ECP_mul(&acc_ecp, acc);
    BIG_modadd(ibig, ibig, one, curve_order);

  }

  delete[] a;

}

DKG_Dealing DKG_Helper::gen_test_dealing(){

  RandGen randgen;
  randseed (randgen);
  csprng RNG;
  randseed (RNG);

  NIZK nizk(node_count, threshold);
  CipherText* ciphers = new CipherText[node_count];
  DKG_Dealing dealing;
  ECP g1_gen, g;
  Mpz q, p;
  read_config(q, p, g1_gen, g);
  CL_HSMqk C(q,1,p);

  ClearText* poly_evals_cleartext = new ClearText[node_count];
  BIG* poly_evals = new BIG[node_count];
  ECP* public_coefficients = new ECP[threshold];

  //generate polynomial evaluations
  gen_poly_evals(RNG, poly_evals, public_coefficients, g);

  for(unsigned int i=0; i<node_count; i++){

    Mpz poly_eval_mpz;
    poly_eval_mpz.BIG_to_Mpz(poly_evals[i]);
    poly_evals_cleartext[i] = ClearText(C, poly_eval_mpz);

  }

  Mpz r(randgen.random_mpz (C.encrypt_randomness_bound()));
  QFI g_r;
  C.power_of_h(g_r, r);

  C.encrypt_all (public_keys, poly_evals_cleartext, r, ciphers, node_count);

  SharingInstance instance(g1_gen, g, public_keys, g_r, ciphers, public_coefficients);

  Witness witness;
  witness.r = r;
  witness.s = poly_evals;

  ZkProofSharing* sharing_proof;
  sharing_proof = nizk.prove_sharing(C, witness, instance, randgen, RNG);

  dealing.ciphertexts = ciphers;
  dealing.g_r = g_r;
  dealing.public_coefficients = public_coefficients;
  dealing.nizk_share = sharing_proof;

  return dealing;
}

bool DKG_Helper::verify_dealing(DKG_Dealing& dealing){

  NIZK nizk(node_count, threshold);

  ECP g1_gen, g;
  Mpz q, p;
  read_config(q, p, g1_gen, g);
  CL_HSMqk C(q,1,p);


  SharingInstance instance(g1_gen, g, public_keys, dealing.g_r, dealing.ciphertexts, dealing.public_coefficients);

  return nizk.verify_sharing(C, instance, dealing.nizk_share);

}

bool DKG_Helper::verify_dealing(protobuff_ser::Dealing& dealing_bytes){

  NIZK nizk(node_count, threshold);

  ECP g1_gen, g;
  Mpz q, p;
  read_config(q, p, g1_gen, g);
  CL_HSMqk C(q,1,p);

  DKG_Dealing dealing;
  deserialize_dealing(dealing_bytes, dealing, C);

  SharingInstance instance(g1_gen, g, public_keys, dealing.g_r, dealing.ciphertexts, dealing.public_coefficients);

  return nizk.verify_sharing(C, instance, dealing.nizk_share);

}


void DKG_Helper::serialize_qfi(QFI& qfi, protobuff_ser::QFI& qfi_bytes){

  QFICompressedRepresentation qfi_comp = qfi.compressed_repr();
  
  std::vector<unsigned char> ap;
  std::vector<unsigned char> g;
  std::vector<unsigned char> tp;
  std::vector<unsigned char> b0;

  qfi_comp.ap.mpz_to_vector(ap);
  qfi_comp.g.mpz_to_vector(g);
  qfi_comp.tp.mpz_to_vector(tp);
  qfi_comp.b0.mpz_to_vector(b0);

  qfi_bytes.set_ap_vec(ap.data(), ap.size());
  qfi_bytes.set_g_vec(g.data(), g.size());
  qfi_bytes.set_tp_vec(tp.data(), tp.size());
  qfi_bytes.set_b0_vec(b0.data(), b0.size());
  qfi_bytes.set_is_neg(qfi_comp.is_neg);


  /*std::cout<<"ap: "<<qfi_comp.ap<<std::endl;
  std::cout<<"g: "<<qfi_comp.g<<std::endl;
  std::cout<<"tp: "<<qfi_comp.tp<<std::endl;
  std::cout<<"b0: "<<qfi_comp.b0<<std::endl;
  std::cout<<"is_neg: "<<qfi_comp.is_neg<<std::endl;*/

}


void DKG_Helper::serialize_ecp(ECP& ecp, protobuff_ser::ECP& ecp_bytes){

  BIG x, y;
  Mpz x_mpz, y_mpz;

  ECP_get(x, y, &ecp);

  x_mpz.BIG_to_Mpz(x);
  y_mpz.BIG_to_Mpz(y);

  std::vector<unsigned char> x_vec;
  std::vector<unsigned char> y_vec; 

  x_mpz.mpz_to_vector(x_vec);
  y_mpz.mpz_to_vector(y_vec);

  ecp_bytes.set_x_vec(x_vec.data(), x_vec.size());
  ecp_bytes.set_y_vec(y_vec.data(), y_vec.size());

}


void DKG_Helper::deserialize_qfi(const protobuff_ser::QFI& qfi_bytes, QFI& qfi, Mpz& disc){

  const std::string& ap_str = qfi_bytes.ap_vec();
  const std::string& g_str = qfi_bytes.g_vec();
  const std::string& tp_str = qfi_bytes.tp_vec();
  const std::string& b0_str = qfi_bytes.b0_vec();

  Mpz ap(std::vector<unsigned char>(ap_str.begin(), ap_str.end()));
  Mpz g(std::vector<unsigned char>(g_str.begin(), g_str.end()));
  Mpz tp(std::vector<unsigned char>(tp_str.begin(), tp_str.end()));
  Mpz b0(std::vector<unsigned char>(b0_str.begin(), b0_str.end()));

  QFICompressedRepresentation qfi_comp = QFICompressedRepresentation(ap, g, tp, b0, qfi_bytes.is_neg());
  qfi = QFI(qfi_comp, disc);

  /*std::cout<<"ap: "<<ap<<std::endl;
  std::cout<<"g: "<<g<<std::endl;
  std::cout<<"tp: "<<tp<<std::endl;
  std::cout<<"b0: "<<b0<<std::endl;
  std::cout<<"is_neg: "<<qfi_bytes.is_neg()<<std::endl;*/

}


void DKG_Helper::deserialize_ecp(const protobuff_ser::ECP& ecp_bytes, ECP& ecp){

  BIG x, y;

  const std::string& x_str = ecp_bytes.x_vec();
  const std::string& y_str = ecp_bytes.y_vec();

  Mpz x_mpz(std::vector<unsigned char>(x_str.begin(), x_str.end()));
  Mpz y_mpz(std::vector<unsigned char>(y_str.begin(), y_str.end()));

  x_mpz.Mpz_to_BIG(x);
  y_mpz.Mpz_to_BIG(y);

  ECP_set(&ecp, x, y);

}


void DKG_Helper::serialize_dealing(DKG_Dealing& dealing, protobuff_ser::Dealing& dealing_bytes){

  protobuff_ser::QFI* gr_qfi_bytes = dealing_bytes.mutable_g_r();
  serialize_qfi(dealing.g_r, *gr_qfi_bytes);

  //std::cout<<"g_r: "<<dealing.g_r<<std::endl;

  for(unsigned int i=0; i<node_count; i++){
    protobuff_ser::QFI qfi_bytes;
    serialize_qfi(dealing.ciphertexts[i].c2_, qfi_bytes);
    *dealing_bytes.add_ciphertexts() = qfi_bytes;

    //std::cout<<"ser c1: "<<dealing.ciphertexts[i].c1_<<std::endl;
    //std::cout<<"ser c2: "<<dealing.ciphertexts[i].c2_<<std::endl;
  }

  for(unsigned int i=0; i<threshold; i++){

    protobuff_ser::ECP ecp_bytes;
    serialize_ecp(dealing.public_coefficients[i], ecp_bytes);
    *dealing_bytes.add_public_coefficients() = ecp_bytes;

    BIG x, y;
    Mpz x_mpz, y_mpz;
    ECP_get(x, y, &dealing.public_coefficients[i]);
    x_mpz.BIG_to_Mpz(x);
    y_mpz.BIG_to_Mpz(y);
    //std::cout<<"x: "<<x_mpz<<std::endl;
    //std::cout<<"y: "<<y_mpz<<std::endl;
  }

  protobuff_ser::NIZK* nizk_bytes = dealing_bytes.mutable_nizk_share();
  protobuff_ser::QFI* ff_qfi_bytes = nizk_bytes->mutable_ff_qfi();
  protobuff_ser::ECP* aa_ecp_bytes = nizk_bytes->mutable_aa_ecp();
  protobuff_ser::QFI* yy_qfi_bytes = nizk_bytes->mutable_yy_qfi();

  serialize_qfi(dealing.nizk_share->ff, *ff_qfi_bytes);
  serialize_ecp(dealing.nizk_share->aa, *aa_ecp_bytes);
  serialize_qfi(dealing.nizk_share->yy, *yy_qfi_bytes);

  std::vector<unsigned char> z_r_vec;
  dealing.nizk_share->z_r.mpz_to_vector(z_r_vec);
  nizk_bytes->set_z_r_vec(z_r_vec.data(), z_r_vec.size());

  Mpz z_alpha_mpz;
  std::vector<unsigned char> z_alpha_vec;
  z_alpha_mpz.BIG_to_Mpz(dealing.nizk_share->z_alpha);
  z_alpha_mpz.mpz_to_vector(z_alpha_vec);
  nizk_bytes->set_z_alpha_vec(z_alpha_vec.data(), z_alpha_vec.size());

  //std::cout<<"z_alpha: "<<z_alpha_mpz<<std::endl;

}


void DKG_Helper::deserialize_dealing(protobuff_ser::Dealing& dealing_bytes, DKG_Dealing& dealing, CL_HSMqk& C){

  Mpz disc = C.Delta ();

  // Deserialize g_r
  const protobuff_ser::QFI& gr_qfi_bytes = dealing_bytes.g_r();
  deserialize_qfi(gr_qfi_bytes, dealing.g_r, disc);

  //std::cout<<"deser g_r: "<<dealing.g_r<<std::endl;

  dealing.ciphertexts = new CipherText[dealing_bytes.ciphertexts_size()];

  // Deserialize the ciphertexts
  for (int i = 0; i < dealing_bytes.ciphertexts_size(); i++) {
    const protobuff_ser::QFI& qfi_bytes = dealing_bytes.ciphertexts(i);
    QFI qfi;
    deserialize_qfi(qfi_bytes, qfi, disc);

    dealing.ciphertexts[i].c1_ = dealing.g_r;
    dealing.ciphertexts[i].c2_ = qfi;

    //std::cout<<"deser c1: "<<dealing.ciphertexts[i].c1_<<std::endl;
    //std::cout<<"deser c2: "<<dealing.ciphertexts[i].c2_<<std::endl;

  }

  // Deserialize the public coefficients

  dealing.public_coefficients = new ECP[dealing_bytes.public_coefficients_size()];

  for (int i = 0; i < dealing_bytes.public_coefficients_size(); i++) {
    const protobuff_ser::ECP& ecp_bytes = dealing_bytes.public_coefficients(i);
    ECP ecp;
    deserialize_ecp(ecp_bytes, ecp);
    dealing.public_coefficients[i] = ecp;

    BIG x, y;
    Mpz x_mpz, y_mpz;
    ECP_get(x, y, &ecp);
    x_mpz.BIG_to_Mpz(x);
    y_mpz.BIG_to_Mpz(y);
    //std::cout<<"x: "<<x_mpz<<std::endl;
    //std::cout<<"y: "<<y_mpz<<std::endl;
  }

  // Deserialize the NIZK share
  const protobuff_ser::NIZK& nizk_bytes = dealing_bytes.nizk_share();
  dealing.nizk_share = new ZkProofSharing();

  const protobuff_ser::QFI& ff_qfi_bytes = nizk_bytes.ff_qfi();
  deserialize_qfi(ff_qfi_bytes, dealing.nizk_share->ff, disc);

  const protobuff_ser::ECP& aa_ecp_bytes = nizk_bytes.aa_ecp();
  deserialize_ecp(aa_ecp_bytes, dealing.nizk_share->aa);

  const protobuff_ser::QFI& yy_qfi_bytes = nizk_bytes.yy_qfi();
  deserialize_qfi(yy_qfi_bytes, dealing.nizk_share->yy, disc);

  const std::string& z_r_vec = nizk_bytes.z_r_vec();
  Mpz z_r(std::vector<unsigned char>(z_r_vec.begin(), z_r_vec.end()));
  dealing.nizk_share->z_r = z_r;

  const std::string& z_alpha_vec = nizk_bytes.z_alpha_vec();
  Mpz z_alpha(std::vector<unsigned char>(z_alpha_vec.begin(), z_alpha_vec.end()));
  BIG z_alpha_big;
  z_alpha.Mpz_to_BIG(z_alpha_big);
  BIG_rcopy(dealing.nizk_share->z_alpha, z_alpha_big);

  //std::cout<<"z_alpha: "<<z_alpha<<std::endl;


  Mpz z_alpha_2;
  z_alpha_2.BIG_to_Mpz(z_alpha_big);
  //std::cout<<"z_alpha2: "<<z_alpha_2<<std::endl;






 }


void DKG_Helper::print_dealing(DKG_Dealing& dealing){


  std::cout<<"Cipers"<<std::endl<<std::endl;

  for(unsigned int i=0; i<node_count; i++){

    std::cout<<"c1: "<<dealing.ciphertexts[i].c1_<<std::endl;
    std::cout<<"c2: "<<dealing.ciphertexts[i].c2_<<std::endl;
  }


  std::cout<<std::endl<<std::endl;

  std::cout<<"g_r: "<<dealing.g_r<<std::endl;

  std::cout<<std::endl<<std::endl;

  std::cout<<"public_coefficients"<<std::endl<<std::endl;

  for(unsigned int i=0; i<threshold; i++){

    BIG x, y;
    Mpz x_mpz, y_mpz;
    ECP_get(x, y, &dealing.public_coefficients[i]);

    x_mpz.BIG_to_Mpz(x);
    y_mpz.BIG_to_Mpz(y);

    std::cout<<"x: "<<x_mpz<<std::endl;
    std::cout<<"y: "<<y_mpz<<std::endl;

  }

  std::cout<<std::endl<<std::endl;

  std::cout<<"NIZK Share"<<std::endl<<std::endl;

  std::cout<<"ff: "<<dealing.nizk_share->ff<<std::endl;
  BIG x, y;
  Mpz x_mpz, y_mpz;
  ECP_get(x, y, &dealing.nizk_share->aa);
  x_mpz.BIG_to_Mpz(x);
  y_mpz.BIG_to_Mpz(y);

  Mpz z_alpha_mpz;
  z_alpha_mpz.BIG_to_Mpz(dealing.nizk_share->z_alpha);
  

  std::cout<<"aa x: "<<x_mpz<<std::endl;
  std::cout<<"aa y: "<<y_mpz<<std::endl;
  std::cout<<"yy: "<<dealing.nizk_share->yy<<std::endl;
  std::cout<<"z_r: "<<dealing.nizk_share->z_r<<std::endl;
  std::cout<<"z_alpha: "<<z_alpha_mpz<<std::endl;


}


#endif /* DKG__ */
