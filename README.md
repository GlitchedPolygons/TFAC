# TFAC
## 2FA (Two-Factor Authentication) for C using TOTP/HOTP.
Originally, I was gonna call this "Two Fucks Given", but apparently that's not civilized...

[![codecov](https://codecov.io/gh/GlitchedPolygons/TFAC/branch/master/graph/badge.svg?token=CQ3FSRTL6M)](https://app.codecov.io/gh/GlitchedPolygons/TFAC)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/TFAC/tree/master.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/TFAC/tree/master)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/TFAC/blob/master/LICENSE)
[![API Docs](https://img.shields.io/badge/api-docs-informational.svg)](https://glitchedpolygons.github.io/TFAC/tfac_8h.html)

### How to clone

`git clone https://github.com/GlitchedPolygons/TFAC.git`

### How to use

Just add TFAC as a git submodule to your project (e.g. into some `lib/` or `deps/` folder inside your project's repo; `{repo_root}/lib/` is used here in the following example).

```
git submodule add https://github.com/GlitchedPolygons/TFAC.git lib/TFAC
git submodule update --init --recursive
```

If you don't want to use git submodules, you can also start vendoring a specific version of TFAC by copying its full repo content into the folder where you keep your project's external libraries/dependencies.

### Compiling

There are pre-built binaries for every major platform for you to download inside the [GitHub Releases page](https://github.com/GlitchedPolygons/TFAC/releases). Thanks for downloading, and I hope you enjoy!

Oh, you're still here :) You really want to compile it yourself, huh. 
Cool. 

Look, just execute the following command and you'll have your TFAC comfortably built and packaged for you automatically into a _.tar.gz_ file that you will find inside the `build/` folder.

```bash
bash build.sh
```
This works on Windows too: just use the [Git Bash for Windows](https://git-scm.com/download/win) CLI!

### Linking

#### CMake

If you use [CMake](https://cmake.org) you can just `add_subdirectory(path_to_submodule)` and then `target_link_libraries(your_project PRIVATE TFAC)` inside your CMakeLists.txt file. Done! You can now include [the TFAC header](https://github.com/GlitchedPolygons/TFAC/blob/master/src/tfac.h) in your code and be done with it.
This is equivalent to static linking by default, but much more pleasant than the manual variant.

#### Dynamic linking

* To dynamically link TFAC into your application on Windows, you need to `#define TFAC_DLL` before including the [tfac.h](https://github.com/GlitchedPolygons/TFAC/blob/master/src/tfac.h) header in your code! (Or, alternatively, add the `TFAC_DLL` pre-processor definition inside your build script/solution config)
* * This will add the `__declspec(dllexport)` declaration that is needed on Windows to the various TFAC functions.
* If you did not grab the pre-built DLL, you need to define/pass the pre-processor macro `TFAC_BUILD_DLL` before compiling TFAC!
* * Your consuming code should then only `#define TFAC_DLL` (as stated above).
* For shared libs: always have the TFAC shared library reachable inside your `$PATH`, or copy it into the same directory where your application's executable resides.

#### Static linking

Linking statically feels best when done directly via CMake's `add_subdirectory(path_to_submodule)` command as seen above, but if you still want to build TFAC as a static lib
yourself and link statically against it, you need to manually create some `build/` directory, `cd` into it and run `cmake -DBUILD_SHARED_LIBS=Off .. && cmake --build . --config Release`.

### Examples

#### Generating a 2FA secret

```c
const struct tfac_secret my_tfa_secret = tfac_generate_secret();
```

#### Generating a TOTP

```c
const struct tfac_secret my_tfa_secret = tfac_generate_secret();
const struct tfac_token my_totp = tfac_totp(my_tfa_secret.secret_key_base32, TFAC_DEFAULT_DIGITS, TFAC_DEFAULT_STEPS, TFAC_DEFAULT_HASH_ALGO);
```

#### Validating a TOTP

TFAC comes with a built-in TOTP validator: re-using tokens successfully fails validation using a pre-allocated obliteration table 
(you can change its size according to your needs and expected traffic via the `TFAC_OBLITERATION_TABLE_SIZE` pre-processor constant).

For the HOTPs: those you'd need to keep track of yourself (TFAC doesn't keep track of your counters, you'd need to sync and store those yourself).

```c
const struct tfac_secret my_tfa_secret = tfac_generate_secret();
const struct tfac_token my_totp = tfac_totp(my_tfa_secret.secret_key_base32, TFAC_DEFAULT_DIGITS, TFAC_DEFAULT_STEPS, TFAC_DEFAULT_HASH_ALGO);

if (tfac_verify_totp(my_tfa_secret.secret_key_base32, my_totp.string, TFAC_DEFAULT_STEPS, TFAC_DEFAULT_HASH_ALGO)) {
    printf("Hurray!");
}
```
