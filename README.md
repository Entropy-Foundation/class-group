# Class Group DKG

We implement a class-group based DKG (distributed key generation) algorithm using BICYCL library at: https://github.com/Entropy-Foundation/BICYCL.
Our implementation is based on a modified version of BICYCL library and we use Miracl core library at: https://github.com/miracl/core for BLS-12381 curve implementation.
Follow these steps to build and test the library:

Step 1: Install BICYCL library at https://github.com/Entropy-Foundation/BICYCL

Step 2: `mkdir build bin config`

Step 3: `cd build`

Step 4: `cmake ..`

Step 5: `make`

Step 6: `cd ../bin/`

Step 7: `./main`
