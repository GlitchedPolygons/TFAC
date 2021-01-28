SET i=%CD%
SET repo=%~dp0
SET out="%repo%\build"
SET projname=TFAC

if exist %out% ( rd /s /q %out% )
mkdir %out% && cd %out%

cmake -DBUILD_SHARED_LIBS=Off "-D%projname%_ENABLE_TESTS=On" ..

cmake --build . --config Release

call Release\run_tests.exe

cd %i%