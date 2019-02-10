{
  "targets": [
    {
      "target_name": "turtlecoin-crypto",
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
        "-fno-exceptions"
      ],
      "cflags_cc!": [
        "-fno-exceptions",
        "-fno-rtti"
      ],
      "cflags_cc": [
        "-std=c++17",
        "-Wno-missing-field-initializers",
        "-Wno-unused-function",
        "-Wno-unused-const-variable",
        "-Wno-unused-private-field",
        "-Wno-unused-function",
        "-Wno-unused-but-set-variable"
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
                      "/std:c++17 /MP /EHsc -D_WIN32_WINNT=0x0501"
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
          }
        ]
      ]
    }
  ]
}