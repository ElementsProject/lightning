{
  "targets": [
    {
      "target_name": "deps",
      "sources": [ "src/combined.c", "src/combined_ccan.c", "src/combined_ccan2.c" ],
      "defines": [ "SWIG_JAVASCRIPT_BUILD", "HAVE_CONFIG_H" ],
      "include_dirs": [ "<(platform_include_dirs)", "<(libwally_dir)", "<(libwally_dir)/src", "<(libwally_dir)/src/secp256k1", "<(libwally_dir)/src/secp256k1/src", "<(libwally_dir)/src/ccan" ],
      "type": "static_library"
    },
    {
      "target_name": "wallycore",
      "dependencies": [ "deps" ],
      "sources": [ "nodejs_wrap.cc" ],
      "include_dirs": [ "<(platform_include_dirs)", "<(libwally_dir)/src", "<!(node -e \"require('nan')\")" ],
      "defines": [ "SWIG_JAVASCRIPT_BUILD", "HAVE_CONFIG_H" ],
    }
  ],
  "conditions": [
    [ 'OS=="mac"', {
      "xcode_settings": {
        "CLANG_CXX_LIBRARY": "libc++"
      }
    }],
    [ 'OS=="win"', {
      "variables": {
        "platform_include_dirs": "windows_config",
        "libwally_dir": "<!(echo %LIBWALLY_DIR%)"
      }
    }],
    [ 'OS!="win"', {
      "variables": {
        "platform_include_dirs": "",
        "libwally_dir": "<!(echo $LIBWALLY_DIR)"
      }
    }]
  ]
}
