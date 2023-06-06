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
#include "arch.h"
#include "fp_BLS24479.h"

namespace BLS24479 {

/* Curve BLS24479 - Pairing friendly BLS curve */

#if CHUNK==16

#error Not supported

#endif

#if CHUNK==32

using namespace B480_29;

const BIG Modulus= {0xA06152B,0x2260B3A,0xB4C36BE,0x5FFC5D0,0xBDB6A64,0x5B78E2E,0x1C1A28CA,0x10E6441B,0x1F244061,0xB4704F0,0x141E5CCD,0x9837504,0x3F2E77E,0xD763740,0x1316EA0E,0xF0079,0x555C};
const BIG ROI= {0xA06152A,0x2260B3A,0xB4C36BE,0x5FFC5D0,0xBDB6A64,0x5B78E2E,0x1C1A28CA,0x10E6441B,0x1F244061,0xB4704F0,0x141E5CCD,0x9837504,0x3F2E77E,0xD763740,0x1316EA0E,0xF0079,0x555C};
const BIG R2modp= {0x8533EA9,0x6A02789,0x183B24DE,0x1E45ECF8,0xC8F8F37,0x10CAD209,0x4C0C4B8,0x9B1FABD,0xDEBE4C0,0xDC353F9,0x18A18E26,0x10F489BB,0x31206A5,0x19673BBF,0x6BE69F9,0xB091169,0x9CD};
const BIG CRu= {0xDD794A9,0x1DE138A3,0x2BCCE90,0xC746127,0x15223DDC,0x1DD8890B,0xED08DB7,0xE24B9F,0xE379CE6,0x37011AC,0x11BAC820,0x1EEFAD01,0x200860F,0x147218A6,0xF16A209,0xF0079,0x555C};
const chunk MConst= 0x95FE7D;
const BIG Fra= {0x1BF96F1D,0xAE53A55,0x31BFEEB,0x183FF17A,0x6237469,0x12A4F4F1,0x12101FE3,0x16E79D94,0xFF59267,0x5EB4EB4,0x78CC49F,0x274BA33,0x149184F3,0x16C6DCBA,0x1C90B694,0x10F729CE,0x4BBC};
const BIG Frb= {0xE0CA60E,0x1740D0E4,0x83037D2,0xDBFD456,0x5B7F5FA,0x1312993D,0xA0A08E6,0x19FEA687,0xF2EADF9,0x55BB63C,0xC91982E,0x70EBAD1,0xF61628B,0x16AF5A85,0x16863379,0xF17D6AA,0x99F};
const BIG SQRTm3= {0x11A91428,0x199C660C,0x1A2D6663,0x12E8FC7D,0x1E691154,0x15F983E8,0x186F2A5,0x10DE5323,0x1D4AF96A,0x1B991E67,0xF573372,0x145BE4FE,0xE24A1,0x1B6DFA0C,0xB165A04,0xF0079,0x555C};
const BIG TWK= {0x16EA62F3,0x52C4905,0x17CF5F35,0x13967138,0x16BCA61B,0xF766FBB,0x9B547D6,0x11625BCD,0x1AFF154D,0xDE4D18C,0xF9C3EF8,0x84619DC,0x15E18EE4,0x1D55B149,0xED04681,0x64CDD9E,0x337A};
#endif

#if CHUNK==64

using namespace B480_56;
// Base Bits= 56
const BIG Modulus= {0x44C1674A06152BL,0xFFE2E82D30DAF8L,0x6F1C5CBDB6A642L,0x3220DF068A328BL,0xE09E1F24406187L,0xBA825079733568L,0x6E803F2E77E4C1L,0x3CCC5BA839AECL,0x555C0078L};
const BIG ROI= {0x44C1674A06152AL,0xFFE2E82D30DAF8L,0x6F1C5CBDB6A642L,0x3220DF068A328BL,0xE09E1F24406187L,0xBA825079733568L,0x6E803F2E77E4C1L,0x3CCC5BA839AECL,0x555C0078L};
const BIG R2modp= {0x6A4A1FE013DF5BL,0xE8E46D4D1BDE65L,0x1F841391F45C67L,0x9148A4516FB28L,0x4398524EDF4C88L,0x41C0E241B6DCE8L,0xE42C208C19411L,0xA7FE6FD73A7B1CL,0xFCCCA76L};
const BIG CRu= {0xBC27146DD794A9L,0x3A30938AF33A43L,0xB112175223DDC6L,0x125CFBB4236DFBL,0x2358E379CE607L,0xD680C6EB20806EL,0x314C200860FF77L,0x3CBC5A88268E4L,0x555C0078L};
const chunk MConst= 0xBD5D7D8095FE7DL;
const BIG Fra= {0x5CA74ABBF96F1DL,0x1FF8BD0C6FFBADL,0x49E9E26237469CL,0x3CECA48407F8E5L,0x69D68FF59267B7L,0x5D199E33127CBDL,0xB97549184F313AL,0x4E77242DA52D8DL,0x4BBC87B9L};
const BIG Frb= {0xE81A1C8E0CA60EL,0xDFEA2B20C0DF4AL,0x25327A5B7F5FA6L,0xF5343A828239A6L,0x76C78F2EADF9CFL,0x5D68B24660B8ABL,0xB50AF61628B387L,0xB555A18CDE6D5EL,0x99F78BEL};
const BIG SQRTm3= {0x338CC191A91428L,0x747E3EE8B5998FL,0xF307D1E6911549L,0xF2991861BCA96BL,0x23CCFD4AF96A86L,0xF27F3D5CCDCB73L,0xF41800E24A1A2DL,0x3CAC5968136DBL,0x555C0078L};
const BIG TWK= {0xA58920B6EA62F3L,0xCB389C5F3D7CD4L,0xECDF776BCA61B9L,0x12DE6A6D51F59EL,0x9A319AFF154D8BL,0xCEE3E70FBE1BCL,0x62935E18EE4423L,0xECF3B411A07AABL,0x337A3266L};
#endif

}
