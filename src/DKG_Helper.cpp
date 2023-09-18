#include "DKG_Helper.hpp"

void DKG_Helper::compute_benchmarks(){

  std::cout<<"Total nodes: "<<node_count<<" , Threshold: "<<threshold<<std::endl;

  RandGen randgen;
  randseed (randgen);
  csprng RNG;
  randseed (RNG);

  CipherText* ciphers = new CipherText[node_count];
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
    Witness witness(r, poly_evals);
    ZkProofSharing* sharing_proof = prove_sharing(C, witness, instance, randgen, RNG, node_count, threshold );
    delete sharing_proof;

  }

  end = std::chrono::high_resolution_clock::now();
  elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
  std::cout<<"Sharing proof gen time: "<<elapsed.count()/10<<std::endl;

  SharingInstance instance(g1_gen, g, public_keys, g_r, ciphers, public_coefficients);

  Witness witness(r, poly_evals);

  ZkProofSharing* sharing_proof;
  sharing_proof = prove_sharing(C, witness, instance, randgen, RNG, node_count, threshold);

  DKG_Dealing dealing(ciphers, g_r, public_coefficients, sharing_proof);

  begin = std::chrono::high_resolution_clock::now();

  for(int i=0; i<10; i++){
    SharingInstance instance(g1_gen, g, public_keys, dealing.get_g_r(), dealing.get_ciphertexts(), dealing.get_public_coefficients());
    verify_sharing(C, instance, dealing.get_nizk_share(), node_count, threshold);

  }

  end = std::chrono::high_resolution_clock::now();
  elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
  std::cout<<"Sharing proof ver time: "<<elapsed.count()/10<<std::endl;


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


void DKG_Helper::gen_test_config(){

  const std::string config_folder = "../config";
  const std::string config_file_sks = config_folder + "/sks_" + "nodes_"+std::to_string(node_count)+"_threshold_"+std::to_string(threshold)+".bin";
  const std::string config_file_pks = config_folder + "/pks_" + "nodes_"+std::to_string(node_count)+"_threshold_"+std::to_string(threshold)+".bin";
  const std::string config_file_cl = config_folder + "/cl_config_128_" + "nodes_"+std::to_string(node_count)+"_threshold_"+std::to_string(threshold)+".bin";

  RandGen randgen;
  csprng RNG;
  randseed (randgen);
  randseed (RNG);

  Mpz q_mpz;
  BIG curve_order;
  BIG_rcopy(curve_order, CURVE_Order);
  q_mpz.BIG_to_Mpz (curve_order);
  
  ECP g1_gen;
  ECP g;
  ECP_generator(&g1_gen);
  
  //todo: generate g by hashing instead of using a random r
  ECP_generator(&g);
  BIG r;
  BIG_randomnum(r, curve_order, &RNG);
  ECP_mul(&g, r);

  std::vector<SecretKey> secret_keys;
  std::vector<PublicKey> public_keys;
  std::vector<CipherText> ciphertexts;

  SecLevel seclevel("128");

  CL_HSMqk C(q_mpz, 1, seclevel, randgen);

  std::ofstream outfile_cl(config_file_cl, std::ios::binary);
    if (!outfile_cl.is_open()) {
      throw std::invalid_argument ("Unable to open file");
      return;
  }

  //storing CL config parameters on disk
  std::vector<unsigned char> q_vec; 
  C.q().mpz_to_vector(q_vec);

  size_t q_size = q_vec.size();
  outfile_cl.write(reinterpret_cast<const char*>(&q_size), sizeof(q_size));
  outfile_cl.write(reinterpret_cast<const char*>(q_vec.data()), q_size);

  std::vector<unsigned char> p_vec; 
  C.p().mpz_to_vector(p_vec);

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
  //Note: This is for test purposes only. In real use, a secret key should be stored securely.
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
    public_keys[i].pk_.a().mpz_to_vector(vec_a);

    size_t size = vec_a.size();
    outfile_pk.write(reinterpret_cast<const char*>(&size), sizeof(size));
    outfile_pk.write(reinterpret_cast<const char*>(vec_a.data()), size);

    std::vector<unsigned char> vec_b;
    public_keys[i].pk_.b().mpz_to_vector(vec_b);

    size = vec_b.size();
    outfile_pk.write(reinterpret_cast<const char*>(&size), sizeof(size));
    outfile_pk.write(reinterpret_cast<const char*>(vec_b.data()), size);

    std::vector<unsigned char> vec_c;
    public_keys[i].pk_.c().mpz_to_vector(vec_c);

    size = vec_c.size();
    outfile_pk.write(reinterpret_cast<const char*>(&size), sizeof(size));
    outfile_pk.write(reinterpret_cast<const char*>(vec_c.data()), size);

  }

  outfile_pk.close();

}

void DKG_Helper::read_config(Mpz& q, Mpz&p, ECP& g1_gen, ECP& g){

  const std::string config_folder = "../config";
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

  const std::string config_folder = "../config";
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

  CipherText* ciphers = new CipherText[node_count];
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
  Witness witness(r, poly_evals);
  ZkProofSharing* sharing_proof;
  sharing_proof = prove_sharing(C, witness, instance, randgen, RNG, node_count, threshold);

  DKG_Dealing dealing(ciphers, g_r, public_coefficients, sharing_proof);
  return dealing;
}

bool DKG_Helper::verify_dealing(DKG_Dealing& dealing){

  ECP g1_gen, g;
  Mpz q, p;
  read_config(q, p, g1_gen, g);
  CL_HSMqk C(q,1,p);

  SharingInstance instance(g1_gen, g, public_keys, dealing.get_g_r(), dealing.get_ciphertexts(), dealing.get_public_coefficients());
  return verify_sharing(C, instance, dealing.get_nizk_share(), node_count, threshold);

}

