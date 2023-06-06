add_custom_target (benchs_build COMMAND ${CMAKE_COMMAND} -E sleep 0)
add_custom_target (benchs COMMAND ${CMAKE_COMMAND} -E sleep 0)
add_dependencies (benchs benchs_build)


set (CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -DNDEBUG")
set (CMAKE_CXX_FLAGS_DEBUG "-O3 -g -Wall -Wextra -DDEBUG")


include_directories(miracl/)
include_directories(/usr/local/lib/)


### List of benchmarks
set (BENCHS_LIST main
                 )

### Automatically create target and test from TESTS_LIST
foreach (bench ${BENCHS_LIST})
  add_executable (${bench}_build ${bench}.cpp)
  set_target_properties (${bench}_build PROPERTIES OUTPUT_NAME ${bench})
  target_link_libraries (${bench}_build bicycl)
  target_link_libraries(${bench}_build core)
  add_custom_target (${bench} COMMAND ${bench}_build COMMENT "Running ${bench}")
  add_dependencies (benchs_build ${bench}_build)
  add_dependencies (benchs ${bench})
endforeach ()
