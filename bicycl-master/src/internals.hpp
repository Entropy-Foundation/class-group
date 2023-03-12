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
#ifndef INTERNALS_HPP__
#define INTERNALS_HPP__

#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <stdexcept>

namespace BICYCL
{
  /*
   * Return zero    if seed was taken from realtime
   *        nonzero if seed was taken from command line
   */
  static inline int
  randseed_from_argv (RandGen &randgen, int argc, char *argv[])
  {
    BICYCL::Mpz seed;
    int ret = 1;

    if (argc > 1)
    {
      try
      {
        seed = argv[1];
      }
      catch (std::runtime_error &e)
      {
        seed = 0UL;
      }
    }

    if (seed.is_zero())
    {
      auto T = std::chrono::system_clock::now();
      seed = static_cast<unsigned long>(T.time_since_epoch().count());
      ret = 0;
    }
    //std::cout << "# seed = " << seed << std::endl << "# Run '" << argv[0]
      //        << " " << seed << "' to rerun the same test" << std::endl;

    randgen.set_seed (seed);

    return ret;
  }

  /****************************************************************************/
  namespace Test
  {
    /* */
    void result_line (const std::string &s, bool res)
    {
      size_t padlen = 70;
      size_t len = s.length()+3 > padlen ? 3 : padlen-s.length();
      std::cout << s.substr (0, padlen-3) << " " << std::string (len, '.')
                << " " << (res ? "success" : "failure") << std::endl;
    }

    /* */
    template <class Cryptosystem>
    bool test_encryption (const Cryptosystem &C, RandGen &randgen, size_t niter,
                          const std::string & pre = std::string(""))
    {
      using PublicKey = typename Cryptosystem::PublicKey;
      using SecretKey = typename Cryptosystem::SecretKey;
      using ClearText = typename Cryptosystem::ClearText;
      using CipherText = typename Cryptosystem::CipherText;

      bool ret = true;

      SecretKey sk = C.keygen (randgen);
      PublicKey pk = C.keygen (sk);

      /* Test niter random encryption + decryption */
      for (size_t i = 0; i < niter; i++)
      {
        ClearText m (C, randgen);
        CipherText c = C.encrypt (pk, m, randgen);
        ClearText t = C.decrypt (sk, c);

        ret &= (m == t);
      }

      /* Test encryption + decryption of 0 */
      ClearText m (C, 0UL);
      CipherText c (C.encrypt (pk, m, randgen));
      ClearText t (C.decrypt (sk, c));
      ret &= (m == t);

      Test::result_line (pre + " encrypt/decrypt", ret);
      return ret;
    }

    /* */
    template <class Cryptosystem>
    bool test_ciphertext_ops (const Cryptosystem &C, RandGen &randgen,
                              size_t niter,
                              const std::string & pre = std::string(""))
    {
      using PublicKey = typename Cryptosystem::PublicKey;
      using SecretKey = typename Cryptosystem::SecretKey;
      using ClearText = typename Cryptosystem::ClearText;
      using CipherText = typename Cryptosystem::CipherText;

      bool ret = true;

      SecretKey sk = C.keygen (randgen);
      PublicKey pk = C.keygen (sk);

      /* Test niter random additions of ciphertexts */
      for (size_t i = 0; i < niter; i++)
      {
        ClearText ma (C, randgen);
        ClearText mb (C, randgen);
        ClearText ms = C.add_cleartexts (ma, mb);
        CipherText ca = C.encrypt (pk, ma, randgen);
        CipherText cb = C.encrypt (pk, mb, randgen);
        CipherText cs = C.add_ciphertexts (pk, ca, cb, randgen);
        ClearText t = C.decrypt (sk, cs);

        ret &= (ms == t);
      }

      /* Test niter random scalar multiplications of ciphertexts */
      for (size_t i = 0; i < niter; i++)
      {
        ClearText m (C, randgen);
        Mpz s = randgen.random_mpz (0x10000UL); /* arbitrary bound */
        ClearText ms = C.scal_cleartexts (m, s);
        CipherText c = C.encrypt (pk, m, randgen);
        CipherText cs = C.scal_ciphertexts (pk, c, s, randgen);
        ClearText t = C.decrypt (sk, cs);

        ret &= (ms == t);
      }

      Test::result_line (pre + " ciphertext ops", ret);
      return ret;
    }
  } /* BICYCL::Test namespace */

  /****************************************************************************/
  namespace Bench
  {
    using std::chrono::steady_clock;
    using s = std::chrono::duration<double>;
    using ms = std::chrono::duration<double, std::milli>;
    using us = std::chrono::duration<double, std::micro>;
    using ns = std::chrono::duration<double, std::nano>;

    template <class unit> struct Unit { static const std::string str; };

    template <> const std::string Unit<s>::str = "s";
    template <> const std::string Unit<ms>::str = "ms";
    template <> const std::string Unit<us>::str = "us";
    template <> const std::string Unit<ns>::str = "ns";

    template <class D1, class D2, class F>
    void one_function (F f, size_t niter, const std::string &fname,
                                          const std::string &pre)
    {
      std::ios_base::fmtflags cout_flags_bak (std::cout.flags());
      auto start = steady_clock::now();
      for (size_t i = 0; i < niter; i++)
      {
            f ();
      }
      auto dt = steady_clock::now() - start;
      double d1 = D1 (dt).count();
      double d2 = D2 (dt).count() / niter;
      std::cout << pre << (pre.size() ? " | " : "")
                << std::setw(15) << std::left << fname.substr(0, 15) << " | "
                << std::setw(5) << std::right << std::fixed << std::setprecision(0)
                << d1 << " " << Unit<D1>::str << " | "
                << std::setw(6) << std::fixed << std::setprecision(2)
                << d2 << " " << Unit<D2>::str << "/iter" << std::endl;

      std::cout.flags (cout_flags_bak);
    }

  } /* BICYCL::Bench namespace */

} /* BICYCL namespace */

#endif /* INTERNALS_HPP__ */
