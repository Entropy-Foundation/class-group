/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PAIR_BLS12381_H
#define PAIR_BLS12381_H

#include "fp12_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "ecp_BLS12381.h"

using namespace core;

namespace BLS12381 {
/* Pairing constants */

extern const B384_58::BIG CURVE_Bnx; /**< BN curve x parameter */
extern const B384_58::BIG CURVE_Cru; /**< BN curve Cube Root of Unity */

extern const B384_58::BIG CURVE_W[2];	 /**< BN curve constant for GLV decomposition */
extern const B384_58::BIG CURVE_SB[2][2]; /**< BN curve constant for GLV decomposition */
extern const B384_58::BIG CURVE_WB[4];	 /**< BN curve constant for GS decomposition */
extern const B384_58::BIG CURVE_BB[4][4]; /**< BN curve constant for GS decomposition */

/* Pairing function prototypes */


/**	@brief Precompute line functions details for fixed G2 value
 *
	@param T array of precomputed FP4 partial line functions
	@param GV a fixed ECP2 instance
 */
extern void PAIR_precomp(BLS12381::FP4 T[], ECP2* GV);

/**	@brief Compute line functions for n-pairing
 *
	@param r array of precomputed FP12 products of line functions
	@param PV ECP2 instance, an element of G2
	@param QV ECP instance, an element of G1

 */
extern void PAIR_another(BLS12381::FP12 r[], ECP2* PV, ECP* QV);


/**	@brief Compute line functions for n-pairing, assuming precomputation on G2
 *
	@param r array of precomputed FP12 products of line functions
	@param T array contains precomputed partial line fucntions from G2
	@param QV ECP instance, an element of G1

 */
extern void PAIR_another_pc(BLS12381::FP12 r[], BLS12381::FP4 T[], ECP *QV);



/**	@brief Calculate Miller loop for Optimal ATE pairing e(P,Q)
 *
	@param r FP12 result of the pairing calculation e(P,Q)
	@param P ECP2 instance, an element of G2
	@param Q ECP instance, an element of G1

 */
extern void PAIR_ate(BLS12381::FP12 *r, ECP2 *P, ECP *Q);
/**	@brief Calculate Miller loop for Optimal ATE double-pairing e(P,Q).e(R,S)
 *
	Faster than calculating two separate pairings
	@param r FP12 result of the pairing calculation e(P,Q).e(R,S), an element of GT
	@param P ECP2 instance, an element of G2
	@param Q ECP instance, an element of G1
	@param R ECP2 instance, an element of G2
	@param S ECP instance, an element of G1
 */
extern void PAIR_double_ate(BLS12381::FP12 *r, ECP2 *P, ECP *Q, ECP2 *R, ECP *S);
/**	@brief Final exponentiation of pairing, converts output of Miller loop to element in GT
 *
	Here p is the internal modulus, and r is the group order
	@param x FP12, on exit = x^((p^12-1)/r)
 */
extern void PAIR_fexp(BLS12381::FP12 *x);
/**	@brief Fast point multiplication of a member of the group G1 by a BIG number
 *
	May exploit endomorphism for speed.
	@param Q ECP member of G1.
	@param b BIG multiplier

 */
extern void PAIR_G1mul(ECP *Q, B384_58::BIG b);
/**	@brief Fast point multiplication of a member of the group G2 by a BIG number
 *
	May exploit endomorphism for speed.
	@param P ECP member of G1.
	@param b BIG multiplier

 */
extern void PAIR_G2mul(ECP2 *P, B384_58::BIG b);



/**	@brief Fast raising of a member of GT to a BIG power
 *
	May exploit endomorphism for speed.
	@param x FP12 member of GT.
	@param b BIG exponent

 */
extern void PAIR_GTpow(BLS12381::FP12 *x, B384_58::BIG b);


/**	@brief Tests ECP for membership of G1
 *
	@param P ECP member of G1
	@return true or false

 */
extern int PAIR_G1member(BLS12381::ECP *P);

/**	@brief Tests ECP2 for membership of G2
 *
	@param P ECP2 member of G2
	@return true or false

 */
extern int PAIR_G2member(BLS12381::ECP2 *P);

/**	@brief Tests FP12 for membership of cyclotomic sub-group
 *
	@param x FP12 instance
	@return true or false

 */
extern int PAIR_GTcyclotomic(BLS12381::FP12 *x);

/**	@brief Tests FP12 for membership of GT
 *
	@param x FP12 instance
	@return true or false

 */
extern int PAIR_GTmember(BLS12381::FP12 *x);

/**	@brief Prepare Ate parameter
 *
	@param n BIG parameter
	@param n3 BIG paramter = 3*n
	@return number of nits in n3

 */
extern int PAIR_nbits(B384_58::BIG n3, B384_58::BIG n);

/**	@brief Initialise structure for multi-pairing
 *
	@param r FP12 array, to be initialised to 1

 */
extern void PAIR_initmp(BLS12381::FP12 r[]);


/**	@brief Miller loop
 *
 	@param res FP12 result
	@param r FP12 precomputed array of accumulated line functions

 */
extern void PAIR_miller(BLS12381::FP12 *res, BLS12381::FP12 r[]);

}

#endif
