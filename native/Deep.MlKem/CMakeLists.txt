cmake_minimum_required(VERSION 3.25)

project(DeepMlKem VERSION 1.0.0 LANGUAGES C)

option(DEEP_MLKEM_BUILD_TESTS "Build the Deep ML-KEM native unit executable" ON)

set(DEEP_MLKEM_PROVIDER_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/vendor/mlkem-native")
set(DEEP_MLKEM_PROVIDER_MLKEM "${DEEP_MLKEM_PROVIDER_ROOT}/mlkem")

add_library(deep_mlkem_provider STATIC
  "${DEEP_MLKEM_PROVIDER_MLKEM}/mlkem_native.c")

add_library(deep_mlkem SHARED src/deep_mlkem_v1.c)

target_compile_features(deep_mlkem_provider PRIVATE c_std_11)
set_target_properties(deep_mlkem_provider PROPERTIES
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
  POSITION_INDEPENDENT_CODE YES)

target_compile_features(deep_mlkem PRIVATE c_std_11)
set_target_properties(deep_mlkem PROPERTIES
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
  OUTPUT_NAME deep_mlkem
  POSITION_INDEPENDENT_CODE YES
  WINDOWS_EXPORT_ALL_SYMBOLS OFF)

target_include_directories(deep_mlkem_provider PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${DEEP_MLKEM_PROVIDER_MLKEM}")

target_include_directories(deep_mlkem PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${DEEP_MLKEM_PROVIDER_MLKEM}")

target_compile_definitions(deep_mlkem_provider PRIVATE
  MLK_CONFIG_FILE=\"deep_mlkem_provider_config.h\")
target_compile_definitions(deep_mlkem PRIVATE DEEP_MLKEM_BUILD_SHARED=1)
target_link_libraries(deep_mlkem PRIVATE deep_mlkem_provider)

if(MSVC)
  set_property(TARGET deep_mlkem_provider deep_mlkem PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded")
  file(TO_NATIVE_PATH "${CMAKE_BINARY_DIR}" DEEP_MLKEM_NATIVE_BUILD_DIR)
  foreach(DEEP_MLKEM_TARGET deep_mlkem_provider deep_mlkem)
    target_compile_options(${DEEP_MLKEM_TARGET} PRIVATE
      /W4 /WX /sdl /GS /guard:cf /Brepro /experimental:deterministic
      "/pathmap:${DEEP_MLKEM_NATIVE_BUILD_DIR}=.")
  endforeach()
  target_link_options(deep_mlkem PRIVATE
    /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /Brepro /INCREMENTAL:NO
    "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/src/deep_mlkem_v1.def")
  set_property(TARGET deep_mlkem_provider APPEND PROPERTY STATIC_LIBRARY_OPTIONS /Brepro)
else()
  foreach(DEEP_MLKEM_TARGET deep_mlkem_provider deep_mlkem)
    target_compile_options(${DEEP_MLKEM_TARGET} PRIVATE
      -Wall -Wextra -Wpedantic -Werror
      -fstack-protector-strong
      -fvisibility=hidden
      -ffunction-sections
      -fdata-sections)
  endforeach()
  target_link_options(deep_mlkem PRIVATE
    -Wl,--gc-sections
    -Wl,--no-undefined
    -Wl,-z,relro,-z,now)
endif()

if(DEEP_MLKEM_BUILD_TESTS)
  enable_testing()
  add_executable(deep_mlkem_tests tests/deep_mlkem_v1_tests.c)
  target_compile_features(deep_mlkem_tests PRIVATE c_std_11)
  set_target_properties(deep_mlkem_tests PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO)
  target_compile_definitions(deep_mlkem_tests PRIVATE DEEP_MLKEM_USE_SHARED=1)
  target_include_directories(deep_mlkem_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${DEEP_MLKEM_PROVIDER_ROOT}/test/test_vectors")
  target_link_libraries(deep_mlkem_tests PRIVATE deep_mlkem)
  if(MSVC)
    set_property(TARGET deep_mlkem_tests PROPERTY
      MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_compile_options(deep_mlkem_tests PRIVATE
      /W4 /WX /sdl /GS /guard:cf /Brepro /experimental:deterministic
      "/pathmap:${DEEP_MLKEM_NATIVE_BUILD_DIR}=.")
    target_link_options(deep_mlkem_tests PRIVATE
      /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /Brepro /INCREMENTAL:NO)
  else()
    target_compile_options(deep_mlkem_tests PRIVATE
      -Wall -Wextra -Wpedantic -Werror
      -fstack-protector-strong)
    target_link_options(deep_mlkem_tests PRIVATE
      -Wl,--gc-sections
      -Wl,-z,relro,-z,now)
  endif()
  add_test(NAME deep_mlkem_v1_native COMMAND deep_mlkem_tests)
endif()

install(TARGETS deep_mlkem
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(FILES include/deep_mlkem_v1.h DESTINATION include)
