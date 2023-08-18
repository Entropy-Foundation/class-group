#include "DKG_Helper.hpp"

int main ()
{

  unsigned int node_count = 100;
  unsigned int threshold = 50;


  std::cout<<"Generating dealing"<<" N= "<<node_count<<" Threshold: "<<threshold<<std::endl;
  DKG_Helper dkg_helper(node_count,threshold);
  DKG_Dealing dealing = dkg_helper.gen_test_dealing();

  std::cout<<"Verifying dealing"<<std::endl;

  if (dkg_helper.verify_dealing(dealing)){
    std::cout<<"Dealing verified successfully!"<<std::endl;
  }
  else {
    std::cout<<"Unable to verify dealing"<<std::endl;

  }

  dkg_helper.compute_benchmarks();


  return EXIT_SUCCESS;
}
