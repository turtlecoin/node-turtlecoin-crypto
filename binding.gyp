{
  "targets": [
    {
      "target_name": "turtlecoin-crypto",
      "defines": [
        "NDEBUG"
      ],
      "include_dirs": [
        "include",
        "<!(node -e \"require('nan')\")"
      ],
      "sources": [
        "src/aesb.c",
        "src/blake256.c",
        "src/chacha8.c",
        "src/crypto.cpp",
        "src/crypto-ops.c",
        "src/crypto-ops-data.c",
        "src/groestl.c",
        "src/hash.c",
        "src/hash-extra-blake.c",
        "src/hash-extra-groestl.c",
        "src/hash-extra-jh.c",
        "src/hash-extra-skein.c",
        "src/jh.c",
        "src/keccak.c",
        "src/oaes_lib.c",
        "src/random.cpp",
        "src/skein.c",
        "src/slow-hash.c",
        "src/StringTools.cpp",
        "src/tree-hash.c",
        "src/turtlecoin-crypto.cpp"
      ],
      "cflags!": [
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wpointer-arith",
        "-Wvla",
        "-Wwrite-strings",
        "-Wno-error=extra",
        "-Wno-error=unused-function",
        "-Wno-error=sign-compare",
        "-Wno-error=strict-aliasing",
        "-Wno-error=type-limits",
        "-Wno-error=unused-parameter",
        "-Wno-error=unused-variable",
        "-Wno-error=undef",
        "-Wno-error=uninitialized",
        "-Wno-error=unused-result",
        "-Wlogical-op",
        "-Wno-error=maybe-uninitialized",
        "-Wno-error=clobbered",
        "-Wno-error=unused-but-set-variable",
        "-Waggregate-return",
        "-Wnested-externs",
        "-Wold-style-definition",
        "-Wstrict-prototypes"
      ],
      "cflags_cc": [
        "-std=c++11",
        "-Wall",
        "-Wextra",
        "-Wpointer-arith",
        "-Wvla",
        "-Wwrite-strings",
        "-Wno-error=extra",
        "-Wno-error=unused-function",
        "-Wno-error=sign-compare",
        "-Wno-error=strict-aliasing",
        "-Wno-error=type-limits",
        "-Wno-unused-parameter",
        "-Wno-error=unused-variable",
        "-Wno-error=undef",
        "-Wno-error=uninitialized",
        "-Wno-error=unused-result",
        "-Wlogical-op",
        "-Wno-error=maybe-uninitialized",
        "-Wno-error=clobbered",
        "-Wno-error=unused-but-set-variable",
        "-Wno-reorder",
        "-Wno-missing-field-initializers",
        "-fexceptions"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "include_dirs": [
              "src/platform/msc"
            ],
            "configurations": {
              "Release": {
                "msvs_settings": {
                  "VCCLCompilerTool": {
                    "RuntimeLibrary": 0,
                    "Optimization": 3,
                    "FavorSizeOrSpeed": 1,
                    "InlineFunctionExpansion": 2,
                    "WholeProgramOptimization": "true",
                    "OmitFramePointers": "true",
                    "EnableFunctionLevelLinking": "true",
                    "EnableIntrinsicFunctions": "true",
                    "RuntimeTypeInfo": "false",
                    "ExceptionHandling": "0",
                    "AdditionalOptions": [
                      "/EHsc -D_WIN32_WINNT=0x0501 /bigobj /MP /W3 /D_CRT_SECURE_NO_WARNINGS /wd4996 /wd4345 /D_WIN32_WINNT=0x0600 /DWIN32_LEAN_AND_MEAN /DGTEST_HAS_TR1_TUPLE=0 /D_VARIADIC_MAX=8 /D__SSE4_1__"
                    ]
                  },
                  "VCLibrarianTool": {
                    "AdditionalOptions": [
                      "/LTCG"
                    ]
                  },
                  "VCLinkerTool": {
                    "LinkTimeCodeGeneration": 1,
                    "OptimizeReferences": 2,
                    "EnableCOMDATFolding": 2,
                    "LinkIncremental": 1,
                    "AdditionalLibraryDirectories": []
                  }
                }
              }
            }
          },
          {
            "defines": [
              "NO_AES"
            ]
          }
        ]
      ]
    }
  ]
}