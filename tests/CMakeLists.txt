add_executable(vaultx_tests test_vaultx.cpp)
target_link_libraries(vaultx_tests PRIVATE vaultx_lib)
add_test(NAME vaultx_tests COMMAND vaultx_tests)
