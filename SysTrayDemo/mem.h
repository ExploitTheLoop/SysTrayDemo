#pragma once
#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <Psapi.h>
#include <cstring>
#include <thread>
#include <iterator>
#include <math.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <filesystem>
#include <stdio.h>
#include <string>

using namespace std;

void AOBREP(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers, int header);
void AOBREP2(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers, int startaddr);
void AOBREP3(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers, int startaddr);
//int getAowProcID();
void cmdd(string text);
void AOBREP4(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers);
void AOBREPSILENT(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers, int header);
int SINGLEAOBSCAN(BYTE BypaRep[], SIZE_T size);
int SINGLEAOBSCAN2(BYTE BypaRep[], SIZE_T size);
void AOBREPSILENT2(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers);
bool patcher(long addr, BYTE write[], SIZE_T sizee);




