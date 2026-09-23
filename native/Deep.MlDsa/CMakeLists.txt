cmake_minimum_required(VERSION 3.25)

project(DeepMlDsa VERSION 1.0.0 LANGUAGES C)

option(DEEP_MLDSA_BUILD_TESTS "Build the Deep ML-DSA native tests" ON)

set(DEEP_MLDSA_VENDOR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/mldsa-native/mldsa")

add_library(deep_mldsa_provider STATIC "${DEEP_MLDSA_VENDOR}/mldsa_native.c")
add_library(deep_mldsa SHARED src/deep_mldsa_v1.c)

foreach(DEEP_MLDSA_TARGET deep_mldsa_provider deep_mldsa)
  set_target_properties(${DEEP_MLDSA_TARGET} PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    POSITION_INDEPENDENT_CODE YES)
  target_compile_definitions(${DEEP_MLDSA_TARGET} PRIVATE
    MLD_CONFIG_PARAMETER_SET=65
    MLD_CONFIG_NO_RANDOMIZED_API=1)
endforeach()

target_include_directories(deep_mldsa_provider PRIVATE "${DEEP_MLDSA_VENDOR}")
target_include_directories(deep_mldsa PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE "${DEEP_MLDSA_VENDOR}")
target_compile_definitions(deep_mldsa PRIVATE DEEP_MLDSA_BUILD_SHARED=1)
target_link_libraries(deep_mldsa PRIVATE deep_mldsa_provider)
set_target_properties(deep_mldsa PROPERTIES
  OUTPUT_NAME deep_mldsa
  WINDOWS_EXPORT_ALL_SYMBOLS OFF)

if(MSVC)
  set_property(TARGET deep_mldsa_provider deep_mldsa PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded")
  foreach(DEEP_MLDSA_TARGET deep_mldsa_provider deep_mldsa)
    target_compile_options(${DEEP_MLDSA_TARGET} PRIVATE
      /W4 /WX /sdl /GS /guard:cf /Brepro /experimental:deterministic)
  endforeach()
  target_link_options(deep_mldsa PRIVATE
    /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /Brepro /INCREMENTAL:NO
    "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/src/deep_mldsa_v1.def")
  set_property(TARGET deep_mldsa_provider APPEND PROPERTY STATIC_LIBRARY_OPTIONS /Brepro)
else()
  foreach(DEEP_MLDSA_TARGET deep_mldsa_provider deep_mldsa)
    target_compile_options(${DEEP_MLDSA_TARGET} PRIVATE
      -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong
      -fvisibility=hidden -ffunction-sections -fdata-sections)
  endforeach()
  target_link_options(deep_mldsa PRIVATE
    -Wl,--gc-sections -Wl,--no-undefined -Wl,-z,relro,-z,now)
endif()

if(DEEP_MLDSA_BUILD_TESTS)
  enable_testing()
  add_executable(deep_mldsa_tests tests/deep_mldsa_v1_tests.c)
  set_target_properties(deep_mldsa_tests PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
  target_include_directories(deep_mldsa_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
  target_compile_definitions(deep_mldsa_tests PRIVATE DEEP_MLDSA_USE_SHARED=1)
  target_link_libraries(deep_mldsa_tests PRIVATE deep_mldsa)
  if(MSVC)
    set_property(TARGET deep_mldsa_tests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_compile_options(deep_mldsa_tests PRIVATE /W4 /WX /sdl /GS /guard:cf)
  else()
    target_compile_options(deep_mldsa_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME deep_mldsa_v1_native COMMAND deep_mldsa_tests)
endif()
