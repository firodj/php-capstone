Compile Capstone:

```
$ mkdir capstone/build
$ cd capstone/build
$ cmake ..
$ cmake --build . --config Release
```

Resource:

* http://blog.benoitblanchon.fr/build-php-extension-on-windows/
* https://wiki.php.net/internals/windows/stepbystepbuild

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

Testing:

```
$ Release_TS\php.exe -dextension=Release_TS\php_capstone.dll -r "echo capstone_test();"
```