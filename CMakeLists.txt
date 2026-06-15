cmake_minimum_required(VERSION 3.16)
project(SecureKeygen VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

if(NOT MSVC)
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# --- Library -----------------------------------------------------------------
file(GLOB_RECURSE SECUREKG_SRC CONFIGURE_DEPENDS src/*.cpp)
add_library(securekg STATIC ${SECUREKG_SRC})
target_include_directories(securekg PUBLIC include)
if(WIN32)
  target_link_libraries(securekg PUBLIC bcrypt)
endif()

# --- CLI ---------------------------------------------------------------------
add_executable(securekg-cli tools/securekg_main.cpp)
target_link_libraries(securekg-cli PRIVATE securekg)
set_target_properties(securekg-cli PROPERTIES OUTPUT_NAME securekg)

# --- Tests -------------------------------------------------------------------
enable_testing()
add_executable(securekg_tests tests/test_main.cpp)
target_link_libraries(securekg_tests PRIVATE securekg)
add_test(NAME securekg_tests COMMAND securekg_tests)

# --- Optional fuzz targets (clang + libFuzzer) -------------------------------
option(SECUREKG_FUZZ "Build libFuzzer harnesses (requires clang)" OFF)
if(SECUREKG_FUZZ)
  foreach(f drbg sts encoding)
    add_executable(fuzz_${f} fuzz/fuzz_${f}.cpp)
    target_link_libraries(fuzz_${f} PRIVATE securekg)
    target_compile_options(fuzz_${f} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_${f} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()
