add_executable (bicycl_CL_HSMqk_setup bicycl_CL_HSMqk_setup.cpp)
target_link_libraries (bicycl_CL_HSMqk_setup PUBLIC bicycl)
add_executable (bicycl_CL_HSM2k_setup bicycl_CL_HSM2k_setup.cpp)
target_link_libraries (bicycl_CL_HSM2k_setup PUBLIC bicycl)

install (TARGETS bicycl_CL_HSMqk_setup bicycl_CL_HSM2k_setup
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
