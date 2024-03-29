#include "Utils.hpp"

void process_mpz_hash(hash256& hash, const std::vector<unsigned char>& mpz_char){

    for(size_t j=0; j<mpz_char.size(); j++){

      HASH256_process(&hash, int(mpz_char[j]));
    }

}

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

//todo: check if this is a secure way of seeding the random number generator
void randseed (RandGen &randgen)
  {
    Mpz seed;
    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed (seed);
  }


//todo: check if this is a secure way of seeding the random number generator
void randseed (csprng& RNG)
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