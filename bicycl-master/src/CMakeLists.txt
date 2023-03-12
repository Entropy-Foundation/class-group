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
                      )
add_library (bicycl INTERFACE)
target_sources (bicycl INTERFACE ${BICYCL_MAIN_HEADER}
                                    ${BICYCL_INSTALLABLE_HEADERS_AND_INL})
target_include_directories (bicycl INTERFACE
                              $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                              $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries (bicycl INTERFACE gmp::gmp OpenSSL::Crypto)
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

add_subdirectory (bin)
