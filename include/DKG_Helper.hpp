#ifndef DKG_HELPER_HPP__
#define DKG_HELPER_HPP__

#include <iostream>
#include <fstream>
#include "DKG_Dealing.hpp"
#include "ZK_Share.hpp"

class DKG_Helper{

  unsigned int node_count;
  unsigned int threshold;
  PublicKey* public_keys;

  void read_config(Mpz& q, Mpz&p, ECP& g1_gen, ECP& g);
  bool read_public_keys(PublicKey*);
  void gen_poly_evals(csprng& RNG, BIG* poly_evals, ECP* public_coefficients, ECP& g);

  //generate public/private keys for a test run of dkg
  //keys are stored in a local file in plaintext
  //Note: this is for test purposes only. In real world the private keys should be stored securely
  void gen_test_config();

public:

  DKG_Helper(unsigned int node_count, unsigned int threshold){
    this->node_count = node_count;
    this->threshold = threshold;
    public_keys = new PublicKey[node_count];

    //if public keys are not provided, generate new config and public keys
    if (!read_public_keys(public_keys)){

      std::cout<<"No config found. Generating test config!"<<std::endl;
      gen_test_config();
      read_public_keys(public_keys);
    }
  };

  //generates dkg dealing
  //uses public keys stored in the config directory
  DKG_Dealing gen_test_dealing();
  bool verify_dealing(DKG_Dealing&);
  void compute_benchmarks();
};


#endif
