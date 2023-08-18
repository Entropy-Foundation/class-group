#ifndef DKG_DEALING_HPP__
#define DKG_DEALING_HPP__

#include "ZK_Share.hpp"

class DKG_Dealing{

  /** Class used to represent a ciphertext for the cryptosystem */
  using CipherText = _Utils::CL_HSM_CipherText<CL_HSMqk>;

  CipherText* ciphertexts;
  QFI g_r;
  ECP* public_coefficients;
  ZkProofSharing* nizk_share;

  public:

  DKG_Dealing(CipherText* ciphertexts, QFI& g_r, ECP* public_coefficients, ZkProofSharing* nizk_share){
    this->g_r = g_r;
    this->ciphertexts = ciphertexts;
    this->public_coefficients = public_coefficients;
    this->nizk_share = nizk_share;
  };

  CipherText* get_ciphertexts(){return this->ciphertexts;};
  QFI& get_g_r(){return this->g_r;};
  ECP* get_public_coefficients(){return this->public_coefficients;};
  ZkProofSharing* get_nizk_share(){return this->nizk_share;};

};
#endif