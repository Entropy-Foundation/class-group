set (BICYCL_MAIN_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/bicycl.hpp)
set (BICYCL_INSTALLABLE_HEADERS_AND_INL
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/seclevel.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/gmp_extras.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/gmp_extras.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/qfi.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/qfi.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/CL_HSM_utils.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/CL_HSM_utils.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/CL_HSMqk.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/CL_HSMqk.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/DKG.hpp
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/DKG.inl
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/dealing.pb.h
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/dealing.pb.cc
                      ${CMAKE_CURRENT_SOURCE_DIR}/bicycl/NetworkingManager.hpp
                      )
add_library (bicycl INTERFACE)

# Find required protobuf package
find_package(protobuf CONFIG REQUIRED)

include_directories(/usr/local/include/miracl/)
include_directories(/usr/local/include/CTPL/)
include_directories(/usr/local/include/)
include_directories(/usr/local/lib/)
link_directories(/usr/local/lib/)

target_sources (bicycl INTERFACE ${BICYCL_MAIN_HEADER}
                                    ${BICYCL_INSTALLABLE_HEADERS_AND_INL})
target_include_directories (bicycl INTERFACE
                              $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                              $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries (bicycl INTERFACE gmp::gmp OpenSSL::Crypto core protobuf::libprotobuf)
if (THREADS_FOUND AND CMAKE_USE_PTHREADS_INIT)
  target_link_libraries (bicycl INTERFACE Threads::Threads)
  target_compile_definitions (bicycl INTERFACE BICYCL_WITH_PTHREADS)
endif ()

install (TARGETS bicycl EXPORT bicyclExport
                          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install (FILES ${BICYCL_MAIN_HEADER}
                          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install (FILES ${BICYCL_INSTALLABLE_HEADERS_AND_INL}
                          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bicycl)

