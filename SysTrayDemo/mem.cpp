#include "stdafx.h"
#include "mem.h"

#include "memory.h"

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <Psapi.h>
#include <cstring>
#include <thread>
#include <iterator>
#include <math.h>
#include "maincode.h"
#include "SysTrayDemo.h"
#include <fstream>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <filesystem>
#include <stdio.h>
#include <string>

using namespace std;


#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

typedef struct _MEMORY_REGION {
	DWORD_PTR dwBaseAddr;
	DWORD_PTR dwMemorySize;
}MEMORY_REGION;

struct FRotator {
	float Pitch;
	float Yaw;
	float Roll;
};

extern struct Vector3 {
	float x = 0;
	float y = 0;
	float z = 0;
};

struct MinimalViewInfo {
	Vector3 Location;
	Vector3 LocationLocalSpace;
	FRotator Rotation;
	float FOV;
};

struct CameraCacheEntry {
	float TimeStamp;
	char chunks[0xC];
	MinimalViewInfo POV;
};


//DWORD pid;
HANDLE ProcessHandle;

/*int getAowProcID() {
	int pid = 0;
	int threadCount = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnap, &pe);
	while (Process32Next(hSnap, &pe)) {
		if (strcmp(pe.szExeFile, "aow_exe.exe") == 0) {
			if ((int)pe.cntThreads > threadCount) {
				threadCount = pe.cntThreads;
				pid = pe.th32ProcessID;
			}
		}
	}

	return pid;
}*/



int emuu = 69;





/*DWORD dGet(DWORD base) {
	DWORD val;
	ReadProcessMemory(ProcessHandle, (void*)(base), &val, sizeof(val), NULL);
	return val;
}
float fGet(DWORD base) {
	float val;
	ReadProcessMemory(ProcessHandle, (void*)(base), &val, sizeof(val), NULL);
	return val;
}
int iGet(DWORD base) {
	int val;
	ReadProcessMemory(ProcessHandle, (void*)(base), &val, sizeof(val), NULL);
	return val;
}

bool WriteMemory(long addr, SIZE_T siz, DWORD write) {
	WriteProcessMemory(ProcessHandle, (void*)addr, &write, siz, NULL);
	return true;
}

bool replaced(long addr, BYTE write) {
	WriteProcessMemory(ProcessHandle, (void*)addr, &write, 1, NULL);
	return true;
}*/

bool patcher(long addr, BYTE write[], SIZE_T sizee) {
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (void*)addr, sizee, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (void*)addr, write, sizee, NULL);
	VirtualProtectEx(phandle, (void*)addr, sizee, OldProtect, NULL);
	return true;
}

bool patcher2(long addr, SIZE_T sizee) {
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (void*)addr, sizee, PAGE_EXECUTE_READWRITE, &OldProtect);
	return true;
}

template<typename T>
T read(uintptr_t ptrAddress)
{
	T val = T();
	ReadProcessMemory(ProcessHandle, (void*)ptrAddress, &val, sizeof(T), NULL);
	return val;
}


template<typename T>
T read(uintptr_t ptrAddress, T val)
{
	ReadProcessMemory(ProcessHandle, (void*)ptrAddress, &val, sizeof(val), NULL);
	return val;
}


template<typename T>
bool write(uintptr_t ptrAddress, LPVOID value)
{
	return WriteProcessMemory(ProcessHandle, (LPVOID)ptrAddress, &value, sizeof(T), NULL);
}


std::string exec(const char* cmd)
{
	char buffer[128]; std::string result = "";
	FILE* pipe = _popen(cmd, "r");
	if (!pipe)
		throw std::runtime_error("popen() failed!");
	try {
		while (fgets(buffer, sizeof buffer, pipe) != NULL)
		{
			result += buffer;
		}
	}
	catch (...)
	{
		_pclose(pipe);
		throw;
	}
	_pclose(pipe);
	return result;
}

std::string removeSpaces(std::string str)
{
	str.erase(remove(str.begin(), str.end(), ' '), str.end());
	return str;
}

std::vector<DWORD> MagicBulletList;
uintptr_t MagicBulletHook;
BYTE realCode[7];
unsigned char ShellCode[96]
{
	0x89, 0x15, 0x00, 0x00, 0x00, 0x00, //mov DWORD PTR ds:0x0,edx
	0x8B, 0x55, 0x34, //mov edx,DWORD PTR [ebp+0x34]
	0xA2, 0x00, 0x00, 0x00, 0x00, //mov ds:0x0,al
	0x8A, 0x82, 0xE0, 0xFD, 0xFF, 0xFF, //mov al,BYTE PTR [edx-0x220]
	0xA2, 0x00, 0x00, 0x00, 0x00, //mov ds:0x0,al
	0x8A, 0x82, 0xE1, 0xFD, 0xFF, 0xFF, //mov al,BYTE PTR [edx-0x21f]
	0xA2, 0x00, 0x00, 0x00, 0x00, //mov ds:0x0,al
	0xA0, 0x00, 0x00, 0x00, 0x00, //mov al,ds:0x0
	0x81, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //cmp DWORD PTR ds:0x0,0x0
	0x74, 0x0E, //je 0x43
	0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, //mov edx,DWORD PTR ds:0x0
	0xC7, 0x45, 0x68, 0x00, 0x00, 0x00, 0x00, //mov DWORD PTR [ebp+0x68],0x0
	0xC3, //ret
	0x81, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //cmp DWORD PTR ds:0x0,0x0
	0x74, 0x02, //je 0x51
	0xEB, 0xE4, //jmp 0x35
	0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, //mov DWORD PTR [edx],0x0
	0xC7, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00, //mov DWORD PTR [edx+0x4],0x0
	0xEB, 0xD5 //jmp 0x35
};



int MemFind(BYTE* buffer, int dwBufferSize, BYTE* bstr, DWORD dwStrLen)
{
	if (dwBufferSize < 0)
	{
		return -1;
	}
	DWORD  i, j;
	for (i = 0; i < dwBufferSize; i++)
	{
		for (j = 0; j < dwStrLen; j++)
		{
			if (buffer[i + j] != bstr[j] && bstr[j] != '?')
				break;
		}
		if (j == dwStrLen)
			return i;
	}
	return -1;
}

int SundaySearch(BYTE* bStartAddr, int dwSize, BYTE* bSearchData, DWORD dwSearchSize)
{
	if (dwSize < 0)
	{
		return -1;
	}
	int iIndex[256] = { 0 };
	int i, j;
	DWORD k;

	for (i = 0; i < 256; i++)
	{
		iIndex[i] = -1;
	}

	j = 0;
	for (i = dwSearchSize - 1; i >= 0; i--)
	{
		if (iIndex[bSearchData[i]] == -1)
		{
			iIndex[bSearchData[i]] = dwSearchSize - i;
			if (++j == 256)
				break;
		}
	}
	i = 0;
	BOOL bFind = FALSE;
	//j=dwSize-dwSearchSize+1;
	j = dwSize - dwSearchSize + 1;
	while (i < j)
	{
		for (k = 0; k < dwSearchSize; k++)
		{
			if (bStartAddr[i + k] != bSearchData[k])
				break;
		}
		if (k == dwSearchSize)
		{
			//ret=bStartAddr+i;
			bFind = TRUE;
			break;
		}
		if (i + dwSearchSize >= dwSize)
		{

			return -1;
		}
		k = iIndex[bStartAddr[i + dwSearchSize]];
		if (k == -1)
			i = i + dwSearchSize + 1;
		else
			i = i + k;
	}
	if (bFind)
	{
		return i;
	}
	else
		return -1;

}

BOOL MemSearch(BYTE* bSearchData, int nSearchSize, DWORD_PTR dwStartAddr, DWORD_PTR dwEndAddr, BOOL bIsCurrProcess, int iSearchMode, std::vector<DWORD_PTR>& vRet)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	BYTE* pCurrMemoryData = NULL;
	MEMORY_BASIC_INFORMATION	mbi;
	std::vector<MEMORY_REGION> m_vMemoryRegion;
	mbi.RegionSize = 0x1000;
	DWORD dwAddress = dwStartAddr;



	while (VirtualQueryEx(phandle, (LPCVOID)dwAddress, &mbi, sizeof(mbi)) && (dwAddress < dwEndAddr) && ((dwAddress + mbi.RegionSize) > dwAddress))
	{

		if ((mbi.State == MEM_COMMIT) && ((mbi.Protect & PAGE_GUARD) == 0) && (mbi.Protect != PAGE_NOACCESS) && ((mbi.AllocationProtect & PAGE_NOCACHE) != PAGE_NOCACHE))
		{

			MEMORY_REGION mData = { 0 };
			mData.dwBaseAddr = (DWORD_PTR)mbi.BaseAddress;
			mData.dwMemorySize = mbi.RegionSize;
			m_vMemoryRegion.push_back(mData);

		}
		dwAddress = (DWORD)mbi.BaseAddress + mbi.RegionSize;

	}


	std::vector<MEMORY_REGION>::iterator it;
	for (it = m_vMemoryRegion.begin(); it != m_vMemoryRegion.end(); it++)
	{
		MEMORY_REGION mData = *it;


		DWORD_PTR dwNumberOfBytesRead = 0;

		if (bIsCurrProcess)
		{
			pCurrMemoryData = (BYTE*)mData.dwBaseAddr;
			dwNumberOfBytesRead = mData.dwMemorySize;
		}
		else
		{

			pCurrMemoryData = new BYTE[mData.dwMemorySize];
			ZeroMemory(pCurrMemoryData, mData.dwMemorySize);
			ReadProcessMemory(phandle, (LPCVOID)mData.dwBaseAddr, pCurrMemoryData, mData.dwMemorySize, &dwNumberOfBytesRead);

			if ((int)dwNumberOfBytesRead <= 0)
			{
				delete[] pCurrMemoryData;
				continue;
			}
		}
		if (iSearchMode == 0)
		{
			DWORD_PTR dwOffset = 0;
			int iOffset = MemFind(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);
			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}
		}
		else if (iSearchMode == 1)
		{

			DWORD_PTR dwOffset = 0;
			int iOffset = SundaySearch(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);

			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}

		}

		if (!bIsCurrProcess && (pCurrMemoryData != NULL))
		{
			delete[] pCurrMemoryData;
			pCurrMemoryData = NULL;
		}

	}
	return TRUE;
}


void cmdd(string text)
{
	string prim = "/c " + text;
	const char* primm = prim.c_str();
	ShellExecute(0, "open", "cmd.exe", primm, 0, SW_HIDE);
}

void SafeExit()
{
	cmdd("adb kill-server");
	cmdd("adb devices");
	cmdd("adb shell am kill com.tencent.ig");
	cmdd("adb shell am force-stop com.tencent.ig");
}

HWND main_hwndd = nullptr;




void AOBREP(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers, int header)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	int endaddr = header + 0x7090000;
	MemSearch(BypaRep, size, header, endaddr, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		int changedVal;
		ReadProcessMemory(phandle, (BYTE*)Bypassdo[0], &changedVal, sizeof(changedVal), nullptr);
		int prem = changedVal;
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}



		ReadProcessMemory(phandle, (BYTE*)Bypassdo[0], &changedVal, sizeof(changedVal), nullptr);
		if (changedVal == prem)
		{
			string pidd = to_string(long long(pid));
			string resumeprocess = "suspend.sys -r " + pidd;
			cmdd(resumeprocess);
			SafeExit();
			system("echo couldn't write memory & pause");
			exit(43);
		}

	}
}

void AOBREPSILENT(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers, int header)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	int endaddr = header + 0x7090000;
	MemSearch(BypaRep, size, header, endaddr, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}

	}
}

void AOBREPSILENT2(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x10000000, 0xB0000000, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}

	}
}

void AOBREP2(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers, int startaddr)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	int endaddr = startaddr + 0x360000;
	MemSearch(BypaRep, size, startaddr, endaddr, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		int changedVal;
		ReadProcessMemory(phandle, (BYTE*)Bypassdo[0], &changedVal, sizeof(changedVal), nullptr);
		int prem = changedVal;
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}

		ReadProcessMemory(phandle, (BYTE*)Bypassdo[0], &changedVal, sizeof(changedVal), nullptr);
		if (changedVal == prem)
		{
			string pidd = to_string(long long(pid));
			string resumeprocess = "suspend.sys -r " + pidd;
			cmdd(resumeprocess);
			SafeExit();
			system("echo couldn't write memory tersafe & pause");
		}

	}
}


void AOBREP3(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers, int startaddr)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	int endaddr = startaddr + 0x360000;
	MemSearch(BypaRep, size, startaddr, endaddr, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		int changedVal;
		ReadProcessMemory(phandle, (BYTE*)Bypassdo[0], &changedVal, sizeof(changedVal), nullptr);
		int prem = changedVal;
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}

		ReadProcessMemory(phandle, (BYTE*)Bypassdo[0], &changedVal, sizeof(changedVal), nullptr);
		if (changedVal == prem)
		{
			//cout << "couldn't write mem" << endl;
		}

	}
}

void AOBREP4(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x45000000, 0x50000000, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		int changedVal;
		ReadProcessMemory(phandle, (BYTE*)Bypassdo[0], &changedVal, sizeof(changedVal), nullptr);
		int prem = changedVal;
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}

		ReadProcessMemory(phandle, (BYTE*)Bypassdo[0], &changedVal, sizeof(changedVal), nullptr);
		if (changedVal == prem)
		{
			//cout << "couldn't write mem" << endl;
		}

	}
}

int SINGLEAOBSCAN(BYTE BypaRep[], SIZE_T size)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x26000000, 0xB0000000, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		return Bypassdo[0];
	}
}

int SINGLEAOBSCAN2(BYTE BypaRep[], SIZE_T size)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0, 0xB0000000, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		return Bypassdo[0];
	}
}


string DwordToString(DWORD val)
{
	string cur_str = to_string(long long(val));
	return cur_str;
}


