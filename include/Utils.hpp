#ifndef UTILS_HPP__
#define UTILS_HPP__

#include <vector>
#include "bicycl.hpp"
#include "pair_BLS12381.h"
#include <random>
#include "randapi.h"

using namespace core;
using namespace BLS12381_BIG;
using namespace BICYCL;

using SecretKey = _Utils::CL_HSM_SecretKey<CL_HSMqk>;
using PublicKey = _Utils::CL_HSM_PublicKey<CL_HSMqk>;
using ClearText = _Utils::CL_HSM_ClearText<CL_HSMqk>;
using CipherText = _Utils::CL_HSM_CipherText<CL_HSMqk>;

void process_mpz_hash(hash256& hash, const std::vector<unsigned char>& mpz_char);
void powmod(BIG& result, BIG& base, BIG& exp, BIG& m);
void randseed(RandGen &randgen);
void randseed(csprng& RNG);

#endif