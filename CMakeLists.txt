# =========================================================================
# Build / import LSPlant
# =========================================================================

cmake_minimum_required(VERSION 3.31)

project(
    dump_dex_payload
    LANGUAGES CXX
)

set(LSPLANT_ROOT
    "${CMAKE_SOURCE_DIR}/third_party/LSPlant"
)

set(LSPLANT_DIR
    "${LSPLANT_ROOT}/lsplant"
)

message(STATUS "============================================================")
message(STATUS "LSPlant configuration")
message(STATUS "LSPLANT_ROOT = ${LSPLANT_ROOT}")
message(STATUS "LSPLANT_DIR  = ${LSPLANT_DIR}")
message(STATUS "============================================================")


# =========================================================================
# Option 1: LSPlant provides CMakeLists.txt
# =========================================================================

if(EXISTS "${LSPLANT_DIR}/CMakeLists.txt")

    message(STATUS "LSPlant CMakeLists.txt found")
    message(STATUS "Using CMake build: ${LSPLANT_DIR}")

    add_subdirectory(
        "${LSPLANT_DIR}"
        "${CMAKE_BINARY_DIR}/lsplant_build"
    )


# =========================================================================
# Option 2: LSPlant is an Android/Gradle module
# =========================================================================

elseif(
    EXISTS "${LSPLANT_ROOT}/gradlew"
    OR
    EXISTS "${LSPLANT_DIR}/gradlew"
)

    message(WARNING
        "LSPlant does not contain CMakeLists.txt. "
        "Falling back to Gradle build."
    )


    # ---------------------------------------------------------------------
    # Find Gradle wrapper
    # ---------------------------------------------------------------------

    if(EXISTS "${LSPLANT_DIR}/gradlew")

        set(GRADLEW_PATH
            "${LSPLANT_DIR}/gradlew"
        )

        set(GRADLE_WORKING_DIR
            "${LSPLANT_DIR}"
        )

        message(STATUS
            "Using module Gradle wrapper: ${GRADLEW_PATH}"
        )

    else()

        set(GRADLEW_PATH
            "${LSPLANT_ROOT}/gradlew"
        )

        set(GRADLE_WORKING_DIR
            "${LSPLANT_ROOT}"
        )

        message(STATUS
            "Using root Gradle wrapper: ${GRADLEW_PATH}"
        )

    endif()


    # ---------------------------------------------------------------------
    # Make gradlew executable
    # ---------------------------------------------------------------------

    execute_process(
        COMMAND chmod +x "${GRADLEW_PATH}"
        WORKING_DIRECTORY "${GRADLE_WORKING_DIR}"
        RESULT_VARIABLE CHMOD_RESULT
    )

    if(NOT CHMOD_RESULT EQUAL 0)
        message(FATAL_ERROR
            "Failed to make Gradle wrapper executable:\n"
            "  ${GRADLEW_PATH}"
        )
    endif()


    # ---------------------------------------------------------------------
    # Verify Ninja before Gradle
    #
    # Gradle's externalNativeBuild/CMake may use Ninja.
    # The GitHub Actions workflow puts Ninja 1.11+ first in PATH.
    # ---------------------------------------------------------------------

    execute_process(
        COMMAND which ninja
        RESULT_VARIABLE NINJA_WHICH_RESULT
        OUTPUT_VARIABLE NINJA_PATH
        ERROR_VARIABLE NINJA_WHICH_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(NINJA_WHICH_RESULT EQUAL 0)

        message(STATUS
            "Ninja found at: ${NINJA_PATH}"
        )

    else()

        message(WARNING
            "Ninja was not found in PATH before Gradle build."
        )

    endif()


    execute_process(
        COMMAND ninja --version
        RESULT_VARIABLE NINJA_VERSION_RESULT
        OUTPUT_VARIABLE NINJA_VERSION
        ERROR_VARIABLE NINJA_VERSION_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(NINJA_VERSION_RESULT EQUAL 0)

        message(STATUS
            "Ninja version: ${NINJA_VERSION}"
        )

    endif()


    # ---------------------------------------------------------------------
    # Build LSPlant through Gradle
    # ---------------------------------------------------------------------

    message(STATUS
        "Building LSPlant through Gradle..."
    )

    execute_process(
        COMMAND
            "${GRADLEW_PATH}"
            :lsplant:assembleRelease
            --no-daemon
            --stacktrace

        WORKING_DIRECTORY
            "${GRADLE_WORKING_DIR}"

        RESULT_VARIABLE
            GRADLE_RESULT

        OUTPUT_VARIABLE
            GRADLE_OUTPUT

        ERROR_VARIABLE
            GRADLE_ERROR

        TIMEOUT
            1200
    )


    if(NOT GRADLE_RESULT EQUAL 0)

        message(FATAL_ERROR
            "============================================================\n"
            "LSPlant Gradle build FAILED\n"
            "============================================================\n"
            "Exit code: ${GRADLE_RESULT}\n\n"
            "STDOUT:\n"
            "${GRADLE_OUTPUT}\n\n"
            "STDERR:\n"
            "${GRADLE_ERROR}\n"
        )

    endif()


    message(STATUS
        "LSPlant Gradle build completed successfully."
    )


    # =========================================================================
    # Search native libraries
    #
    # Android Gradle native outputs can appear in:
    #
    #   build/intermediates/cxx/
    #   build/intermediates/merged_native_libs/
    #   build/intermediates/stripped_native_libs/
    #   build/intermediates/library_jni/
    #   build/outputs/
    # =========================================================================

    set(LSPLANT_BUILD_DIR
        "${LSPLANT_DIR}/build"
    )

    file(GLOB_RECURSE LSPLANT_SO_FILES
        "${LSPLANT_BUILD_DIR}/*.so"
    )


    if(NOT LSPLANT_SO_FILES)

        message(FATAL_ERROR
            "============================================================\n"
            "LSPlant Gradle build succeeded, but no .so was found.\n"
            "============================================================\n"
            "Search directory:\n"
            "  ${LSPLANT_BUILD_DIR}\n"
            "\n"
            "Please inspect the Gradle native output paths."
        )

    endif()


    message(STATUS
        "Found LSPlant native libraries:"
    )


    foreach(LSPLANT_SO IN LISTS LSPLANT_SO_FILES)

        message(STATUS
            "  ${LSPLANT_SO}"
        )

    endforeach()


    # =========================================================================
    # Import native libraries into CMake
    # =========================================================================

    set(LSPLANT_TARGET_FOUND FALSE)


    foreach(LSPLANT_SO IN LISTS LSPLANT_SO_FILES)

        get_filename_component(
            SO_NAME
            "${LSPLANT_SO}"
            NAME_WE
        )

        string(
            REGEX REPLACE
            "^lib"
            ""
            TARGET_NAME
            "${SO_NAME}"
        )

        string(
            REPLACE "-"
            "_"
            TARGET_NAME
            "${TARGET_NAME}"
        )


        # Avoid duplicate target names
        if(NOT TARGET "${TARGET_NAME}")

            add_library(
                "${TARGET_NAME}"
                UNKNOWN
                IMPORTED
            )

            set_target_properties(
                "${TARGET_NAME}"
                PROPERTIES
                IMPORTED_LOCATION
                "${LSPLANT_SO}"
            )

            message(STATUS
                "Imported target '${TARGET_NAME}'"
            )

        endif()


        if(TARGET_NAME STREQUAL "lsplant")

            set(LSPLANT_TARGET_FOUND TRUE)

        endif()

    endforeach()


    # =========================================================================
    # Fallback: create target named "lsplant"
    # =========================================================================

    if(NOT LSPLANT_TARGET_FOUND)

        # Prefer a library whose filename contains "lsplant".
        set(SELECTED_LSPLANT_SO "")

        foreach(LSPLANT_SO IN LISTS LSPLANT_SO_FILES)

            get_filename_component(
                SO_BASENAME
                "${LSPLANT_SO}"
                NAME
            )

            string(
                TOLOWER
                "${SO_BASENAME}"
                SO_BASENAME_LOWER
            )

            if(
                SO_BASENAME_LOWER MATCHES
                "liblsplant.*\\.so"
            )

                set(
                    SELECTED_LSPLANT_SO
                    "${LSPLANT_SO}"
                )

                break()

            endif()

        endforeach()


        # If no liblsplant.so was found, use the first .so.
        if(NOT SELECTED_LSPLANT_SO)

            list(
                GET
                LSPLANT_SO_FILES
                0
                SELECTED_LSPLANT_SO
            )

            message(WARNING
                "liblsplant.so was not found. "
                "Using first native library as fallback:\n"
                "  ${SELECTED_LSPLANT_SO}"
            )

        endif()


        if(NOT TARGET lsplant)

            add_library(
                lsplant
                UNKNOWN
                IMPORTED
            )

            set_target_properties(
                lsplant
                PROPERTIES
                IMPORTED_LOCATION
                "${SELECTED_LSPLANT_SO}"
            )

            message(STATUS
                "Created imported target 'lsplant' from:"
            )

            message(STATUS
                "  ${SELECTED_LSPLANT_SO}"
            )

        endif()

    endif()


# =========================================================================
# Build payload: libdump_dex_payload.so
# =========================================================================

# ---------------------------------------------------------------------
# 1) Generate hook_stub_dex.h from java_stub/HookStub.java
#    HookStub.java -> javac -> .class -> d8 -> .dex -> gen_dex_header.py -> .h
# ---------------------------------------------------------------------

find_program(JAVAC_EXE javac)
if(NOT JAVAC_EXE)
    message(FATAL_ERROR
        "javac was not found in PATH. JDK 17 is required."
    )
endif()

if(NOT ANDROID_D8)
    message(FATAL_ERROR
        "ANDROID_D8 was not provided. Pass -DANDROID_D8=<path-to-d8> from the workflow."
    )
endif()

if(NOT DEFINED ENV{ANDROID_HOME})
    message(FATAL_ERROR
        "ANDROID_HOME is not set. Needed to locate android.jar for d8."
    )
endif()

file(GLOB ANDROID_JAR_LIST "$ENV{ANDROID_HOME}/platforms/android-*/android.jar")
list(LENGTH ANDROID_JAR_LIST ANDROID_JAR_COUNT)
if(ANDROID_JAR_COUNT EQUAL 0)
    message(FATAL_ERROR
        "android.jar not found under $ENV{ANDROID_HOME}/platforms"
    )
endif()
list(GET ANDROID_JAR_LIST 0 ANDROID_JAR)

set(HOOK_STUB_SRC   "${CMAKE_SOURCE_DIR}/java_stub/src/HookStub.java")
set(HOOK_STUB_HDR   "${CMAKE_SOURCE_DIR}/src/hook_stub_dex.h")
set(HOOK_STUB_CLASS "${CMAKE_BINARY_DIR}/hookstub/dump/dex/hook/HookStub.class")
set(HOOK_STUB_DEX   "${CMAKE_BINARY_DIR}/hookstub_dex/classes.dex")

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/hookstub" "${CMAKE_BINARY_DIR}/hookstub_dex")

execute_process(
    COMMAND "${JAVAC_EXE}" -d "${CMAKE_BINARY_DIR}/hookstub" "${HOOK_STUB_SRC}"
    RESULT_VARIABLE JAVAC_RESULT
    ERROR_VARIABLE JAVAC_ERR
)
if(NOT JAVAC_RESULT EQUAL 0)
    message(FATAL_ERROR
        "javac HookStub failed:\n${JAVAC_ERR}"
    )
endif()

execute_process(
    COMMAND "${ANDROID_D8}" --release --min-api 21 --lib "${ANDROID_JAR}"
            --output "${CMAKE_BINARY_DIR}/hookstub_dex" "${HOOK_STUB_CLASS}"
    RESULT_VARIABLE D8_RESULT
    ERROR_VARIABLE D8_ERR
)
if(NOT D8_RESULT EQUAL 0)
    message(FATAL_ERROR
        "d8 HookStub failed:\n${D8_ERR}"
    )
endif()

find_program(PYTHON3_EXE python3 python)
if(NOT PYTHON3_EXE)
    message(FATAL_ERROR "python3 not found in PATH")
endif()

execute_process(
    COMMAND "${PYTHON3_EXE}" "${CMAKE_SOURCE_DIR}/tools/gen_dex_header.py"
            "${HOOK_STUB_DEX}" "${HOOK_STUB_HDR}"
    RESULT_VARIABLE GEN_RESULT
    ERROR_VARIABLE GEN_ERR
)
if(NOT GEN_RESULT EQUAL 0)
    message(FATAL_ERROR
        "gen_dex_header.py failed:\n${GEN_ERR}"
    )
endif()


# ---------------------------------------------------------------------
# 2) Build Dobby (inline hooker for lsplant::Init)
# ---------------------------------------------------------------------

set(DOBBY_DIR "${CMAKE_SOURCE_DIR}/third_party/Dobby")
if(NOT EXISTS "${DOBBY_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "Dobby submodule not initialized. Run:\n"
        "  git submodule update --init --recursive third_party/Dobby"
    )
endif()

add_subdirectory("${DOBBY_DIR}" "dobby" EXCLUDE_FROM_ALL)


# ---------------------------------------------------------------------
# 3) Build the payload shared library
# ---------------------------------------------------------------------

add_library(dump_dex_payload SHARED src/main.cpp)

target_include_directories(dump_dex_payload PRIVATE
    "${CMAKE_SOURCE_DIR}/src"
    "${LSPLANT_DIR}/src/main/jni/include"
    "${DOBBY_DIR}/include"
)

target_link_libraries(dump_dex_payload PRIVATE
    lsplant
    dobby_static
    c++_shared
    log
    dl
)

# Generated hook_stub_dex.h must be regenerated if the Java stub changes.
set_source_files_properties("${CMAKE_SOURCE_DIR}/src/main.cpp" PROPERTIES
    OBJECT_DEPENDS "${HOOK_STUB_HDR}"
)


# =========================================================================
# LSPlant not found
# =========================================================================

else()

    message(FATAL_ERROR
        "============================================================\n"
        "LSPlant was not found or is not buildable.\n"
        "============================================================\n"
        "\n"
        "Expected one of:\n"
        "\n"
        "  ${LSPLANT_DIR}/CMakeLists.txt\n"
        "\n"
        "or:\n"
        "\n"
        "  ${LSPLANT_ROOT}/gradlew\n"
        "  ${LSPLANT_DIR}/gradlew\n"
        "\n"
        "Check that the LSPlant submodule was initialized correctly:\n"
        "\n"
        "  git submodule update --init --recursive third_party/LSPlant\n"
    )

endif()
