SET i=%CD%
SET repo=%~dp0
SET out="%repo%\build"
SET projname=TFAC

if exist %out% ( rd /s /q %out% )
mkdir %out% && cd %out%

cmake -DBUILD_SHARED_LIBS=On "-D%projname%_BUILD_DLL=On" "-D%projname%_PACKAGE=On" -DCMAKE_BUILD_TYPE=Release .. 

cmake --build . --config Release

cd %i%
