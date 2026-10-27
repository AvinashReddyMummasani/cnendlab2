@echo off
echo Compiling Modular Data Link Layer Simulation...
g++ -std=c++14 -Wall -Wextra main.cpp utils.cpp hamming.cpp csma_ca.cpp go_back_n.cpp -o data_link_layer.exe
if %ERRORLEVEL% EQU 0 (
    echo Compilation Successful!
    echo Run: .\data_link_layer.exe
) else (
    echo Compilation Failed!
)
