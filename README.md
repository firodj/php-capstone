## Compile Capstone:

```
$ mkdir capstone/build
$ cd capstone/build
$ cmake ..
$ cmake --build . --config Release
```

### For Win64

CMake Need to adjust with adding these lines with `TARGET_NAME` are each
`add_executable` and `add_library`.

```
set_target_properties(${TARGET_NAME} PROPERTIES STATIC_LIBRARY_FLAGS "/machine:x64")
```

```
$ cmake -G "Visual Studio 14 2015 Win64" ..
```

## Compile Capstone PHP on Windows:

Resource:

* http://blog.benoitblanchon.fr/build-php-extension-on-windows/
* https://wiki.php.net/internals/windows/stepbystepbuild

Step:

1. Install **Visual Studio 2015**.
2. Open **VS2015 x86 Native Tools Command Prompt**.
3. The PHP binary tools SDK is located in `C:\php-sdk`
4. Create build directory once:
   ```
   $ cd c:\php-sdk\
   $ bin\phpsdk_buildtree.bat phpdev
   ``` 
   
   Copy `C:\php-sdk\phpdev\vc9` to `C:\php-sdk\phpdev\vc14`.

5. The PHP source code is located in `C:\php-sdk\phpdev\vc14\x86\php-7.0.14-src`
6. Put libraries on which PHP depends in `C:\php-sdk\phpdev\vc14\x86\deps`
6. Clone this repo in `C:\php-exts\capstone`
7. Setup environment:

   ```
   $ cd c:\php-sdk\
   $ bin\phpsdk_setvars.bat
   ```

7. Build config as **phpize**:
   
   ```
   $ cd C:\php-sdk\phpdev\vc14\x86\php-7.0.14-src
   $ buildconf.bat --add-modules-dir=C:\php-exts
   ```

5. Configure:

   ```
   $ cd C:\php-sdk\phpdev\vc14\x86\php-7.0.14-src
   $ configure.bat --disable-all --enable-cli --enable-capstone
   ```

6. Make:

   ```
   $ cd C:\php-sdk\phpdev\vc14\x86\php-7.0.14-src
   $ nmake php_capstone.dll
   ```

The generated file will be in `.\Release_TS` and `.\x64\Relase_TS` for Win64.

### Testing:

```
$ echo extension=php_capstone.dll >> Release_TS\php.ini
$ nmake test TESTS=C:\php-exts\capstone\tests
```

## Compile Capstone PHP on Linux/Mac:

```
$ phpize --clean
$ phpize
$ ./configure
```

### Patch (C++ only) on Mac:

If you get error regarding `__ZNSt8ios_base4InitD1Ev` it is because the `libtool`
using `gcc` instead `g++` compiler in which it doesn't link to `libstdc++`.
Change the command produced in `Makefile` from `--mode=link $(CC)` into `--mode=link $(CXX)`
on the rule `./capstone.la` (bottom).

### Build:
```
$ make
```

Make sure the `modules/capstone.so` linked with `libstdc++` (C++ only):
```
$ otool -L modules/capstone.so
```

### Test:
```
$ make test
```

### Install:
```
$ make install
$ echo "extension=capstone.so" > /usr/local/etc/php/7.0/conf.d/ext-capstone.ini
$ brew services restart php70
```

