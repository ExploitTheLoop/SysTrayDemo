#include "stdafx.h"
#include "maincode.h"

// detectSplashActivity.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "stdc++.h"
#include <Psapi.h>
#include "syscall.h"
#include "mem.h"
#include <array>
#include "SysTrayDemo.h"

using namespace std;

auto NtWriteVirtualMemory = makesyscall<bool>("NtWriteVirtualMemory");
auto NtReadVirtualMemory = makesyscall<bool>("NtReadVirtualMemory");

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);

typedef LONG(WINAPI* RtlAdjustPrivilege)(DWORD, BOOL, INT, PBOOL);

void suspend(DWORD processId)
{
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
        GetModuleHandleA("ntdll"), "NtSuspendProcess");

    pfnNtSuspendProcess(processHandle);
    CloseHandle(processHandle);
}

typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);

typedef LONG(WINAPI* RtlAdjustPrivilege)(DWORD, BOOL, INT, PBOOL);

void resume(DWORD processId)
{
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(
        GetModuleHandleA("ntdll"), "NtResumeProcess");

    pfnNtResumeProcess(processHandle);
    CloseHandle(processHandle);
}

int getue4header()
{
    int libue4header = 0;
    BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x24, 0x16, 0x08, 0x07, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x28, 0x00 };
    libue4header = SINGLEAOBSCAN(ue4head, sizeof(ue4head));
    return libue4header;
}

int gettersafeheader()
{
    int libtersafeheader = 0;
    BYTE tersafehead[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0xAC, 0x19, 0x35, 0x00, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x08, 0x00, 0x28, 0x00 };
    libtersafeheader = SINGLEAOBSCAN2(tersafehead, sizeof(tersafehead));
    return libtersafeheader;
}

int getswappyheader()
{
    int libswappyheader = 0;
    BYTE swappy[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0xF4, 0x14, 0x0B, 0x00, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x08, 0x00, 0x28, 0x00 };
    libswappyheader = SINGLEAOBSCAN2(swappy, sizeof(swappy));
    return libswappyheader;
}

void offsetsearch(int offset, int header)
{
    
    DWORD pid = getProcId();
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    int addr = header + offset;
    BYTE write[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
    unsigned long OldProtect;
    unsigned long OldProtect2;
    VirtualProtectEx(phandle, (BYTE*)addr, 8, PAGE_EXECUTE_READWRITE, &OldProtect);
    NtWriteVirtualMemory(phandle, (BYTE*)addr, write, 8, NULL);
    VirtualProtectEx(phandle, (BYTE*)addr, 8, OldProtect, NULL);
}

void offsetsearch2(int offset, BYTE write[], SIZE_T size, int header)
{
    DWORD pid = getProcId();
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    int addr = header + offset;
    unsigned long OldProtect;
    unsigned long OldProtect2;
    VirtualProtectEx(phandle, (BYTE*)addr, size, PAGE_EXECUTE_READWRITE, &OldProtect);
    NtWriteVirtualMemory(phandle, (BYTE*)addr, write, size, NULL);
    VirtualProtectEx(phandle, (BYTE*)addr, size, OldProtect, NULL);
}

inline bool FileExist(const std::string& name) {
    if (FILE* file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    }
    else {
        return false;
    }
}

void WriteResToDisk(std::string PathFile, LPCSTR File_WITHARG)
{
    HRSRC myResource = ::FindResource(NULL, File_WITHARG, RT_RCDATA);
    unsigned int myResourceSize = ::SizeofResource(NULL, myResource);
    HGLOBAL myResourceData = ::LoadResource(NULL, myResource);
    void* pMyExecutable = ::LockResource(myResourceData);
    std::ofstream f(PathFile, std::ios::out | std::ios::binary);
    f.write((char*)pMyExecutable, myResourceSize);
    f.close();
}

std::string executee(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

int getTencentpid()
{
    string line = executee("adb shell \"ps | grep com.tencent.ig\"");
    if (line == "")
    {
        return 0;
    }
    else
    {
        vector <string> tokens;

        // stringstream class check1
        stringstream check1(line);

        string intermediate;
        char prem = ' ';
        // Tokenizing w.r.t. space ' '
        while (getline(check1, intermediate, prem))
        {
            tokens.push_back(intermediate);
        }
        string mainpart = tokens[4];
        stringstream geek(mainpart);

        // The object has the value 12345 and stream
        // it to the integer x
        int x = 0;
        geek >> x;
        return x;
    }

}

long int get_module_base(const char* module_name)
{
    int ipid = getTencentpid();
    string ipidstr = to_string(long long(ipid));
    string modulename = module_name;
    string initialcommand = "adb shell \"cat /proc/" + ipidstr + "/maps | grep " + modulename + "\"";
    const char* command = initialcommand.c_str();
    string line = executee(command);
    if (line == "")
    {
        return 0;
    }
    else
    {
        vector <string> tokens;
        stringstream check1(line);
        string intermediate;
        char prem = '-';
        while (getline(check1, intermediate, prem))
        {
            tokens.push_back(intermediate);
        }
        string premm = tokens[0];
        unsigned int x;
        std::stringstream ss;
        ss << std::hex << premm;
        ss >> x;
        return x;
    }
}

/*void patch(int size, int headeraddr)
{
    int pid = getProcId();
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    unsigned long OldProtect;
    unsigned long OldProtect2;
    VirtualProtectEx(phandle, (BYTE*)headeraddr, size, PAGE_EXECUTE_READWRITE, &OldProtect);
    VirtualProtectEx(phandle, (BYTE*)headeraddr, size, OldProtect, NULL);
    BYTE swappy[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    for (int i = 0; i < (size / 100); i++)
    {
        int write = headeraddr + i;
        NtWriteVirtualMemory(phandle, (BYTE*)write, swappy, sizeof(swappy), NULL);
    }
}*/

void action()
{

    system("adb.exe shell  rm -rf /data/data/com.tencent.ig/files");
    system("adb.exe shell  rm -rf /data/user/0/com.tencent.ig/files");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SrcVersion.ini");
    system("adb.exe push C:\\Windows\\SrcVersion.ini /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SrcVersion.ini");
    system("adb.exe shell  touch /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Paks/core_patch_1.4.0.99999.pak");
    system("adb.exe shell  touch /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Paks/game_patch_1.4.0.99999.pak");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/StatEventReportedFlag");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/GameErrorNoRecords");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/afd");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs0");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs1");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ams");
    system("adb shell rm -rf mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
    system("adb push C:\\Windows\\updater.ini mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SrcVersion.ini");
    system("adb.exe push C:\\Windows\\SrcVersion.ini /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SrcVersion.ini");
    system("adb.exe shell  touch /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Paks/core_patch_1.4.0.99999.pak");
    system("adb.exe shell  touch /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Paks/game_patch_1.4.0.99999.pak");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/StatEventReportedFlag");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/GameErrorNoRecords");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/afd");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs0");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs1");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ams");
    system("adb shell rm -rf mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
    system("adb push C:\\Windows\\updater.ini mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
    system("adb.exe kill-server");
    system("adb devices");
    system("adb.exe shell  rm -rf /data/data/com.tencent.ig/files");
    system("adb.exe shell  rm -rf /data/user/0/com.tencent.ig/files");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SrcVersion.ini");
    system("adb.exe push C:\\Windows\\SrcVersion.ini /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SrcVersion.ini");
    system("adb.exe shell  touch /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Paks/core_patch_1.4.0.99999.pak");
    system("adb.exe shell  touch /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Paks/game_patch_1.4.0.99999.pak");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/StatEventReportedFlag");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/GameErrorNoRecords");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/afd");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs0");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs1");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir");
    system("adb.exe shell  rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ams");
    system("adb shell rm -rf mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
    system("adb push C:\\Windows\\updater.ini mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SrcVersion.ini");
    system("adb.exe push C:\\Windows\\SrcVersion.ini /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SrcVersion.ini");
    system("adb.exe shell  touch /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Paks/core_patch_1.4.0.99999.pak");
    system("adb.exe shell  touch /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Paks/game_patch_1.4.0.99999.pak");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/StatEventReportedFlag");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/GameErrorNoRecords");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/afd");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs0");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs1");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir");
    system("adb.exe shell  rm -rf /storage/emulated/0/Android/data/com.tencent.ams");
    system("adb shell rm -rf mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
    system("adb push C:\\Windows\\updater.ini mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");

}

int getEmuID() {
    int pid = 0;
    int threadCount = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnap, &pe);
    while (Process32Next(hSnap, &pe)) {
        if (strcmp(pe.szExeFile, "AndroidEmulator.exe") == 0) {
            if ((int)pe.cntThreads > threadCount) {
                threadCount = pe.cntThreads;
                pid = pe.th32ProcessID;
            }
        }
    }

    return pid;
}

int getEmuID2() {
    int pid = 0;
    int threadCount = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnap, &pe);
    while (Process32Next(hSnap, &pe)) {
        if (strcmp(pe.szExeFile, "ProjectTitan.exe") == 0) {
            if ((int)pe.cntThreads > threadCount) {
                threadCount = pe.cntThreads;
                pid = pe.th32ProcessID;
            }
        }
    }

    return pid;
}

int getEmuProcID()
{
    int pid = 0;
    int gameloop = getEmuID();
    int smartgaga = getEmuID2();
    if (smartgaga == 0 || smartgaga == 1)
    {
        return gameloop;
    }
    else
    {
        return smartgaga;
    }
}

int isSubstring(string s1, string s2)
{
    int M = s1.length();
    int N = s2.length();
    for (int i = 0; i <= N - M; i++) {
        int j;
        for (j = 0; j < M; j++)
            if (s2[i + j] != s1[j])
                break;

        if (j == M)
            return i;
    }

    return -1;
}



void detectemu()
{
    //These four lines hides the console
    HWND window;
    AllocConsole();
    window = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(window, 0);
entrypoint:
    //system("cls");
    //cout << "Status : N/A" << endl;
    while (true)
    {
        int pid = getEmuProcID();
        if (pid == 0 || pid == 1)
        {
            ///
        }
        else
        {
            //system("cls");
            system("adb kill-server");
            system("adb devices");
            string output = executee("adb devices");
            string substring = "emulator";
            int checks = isSubstring(substring, output);
            if (checks != -1)
            {
                system("cls");
                //Sleep(5000);
                cout << "emu found" << endl;
                //MessageBoxA(0, "action", 0, 0);
                action();
                while (true)
                {
                    int pid2 = getEmuProcID();
                    if (pid2 != pid || pid == 0 || pid == 1)
                    {
                        system("cls");
                        cout << "emulator has been closed, relooping.." << endl;
                        goto entrypoint;
                        Sleep(3000);
                    }
                    else
                    {
                        //continue;
                    }
                    Sleep(3000);
                }
            }
            else
            {
                system("cls");
                cout << "Loading emulator..." << endl;
            }
            if (output == "")
            {
                Sleep(3000);
                goto entrypoint;
            }
        }
        Sleep(3000);
    }
}

void maincodes()
{
    int pid = getProcId();
    string pidd = to_string(long long(pid));
    //system("cls");
    //std::cout << "Game found" << std::endl;
    //std::cout << "PID : " + pidd << std::endl;
    //cout << "Obtaining base addr..." << endl;
    //system("adb kill-server & adb devices");
header:
    Sleep(3000);
    suspend(pid);
    int libue4header = getue4header();
    int libtersafeheader = gettersafeheader();
    
    if (libue4header == 0 || libtersafeheader == 0)
    {
        ///
    }
    else
    {
    memorywriting:
        
        BYTE a1[] = { 0x00, 0x00, 0x00, 0x00, 0x28, 0x29, 0xA9, 0x06, 0x17, 0x00, 0x00, 0x00, 0x2C, 0x29, 0xA9, 0x06 };
        offsetsearch2(7480204, a1, sizeof(a1), libue4header);
        BYTE zerofour[] = { 0x00, 0x00, 0x00, 0x00 };
        int py1 = 0x4774FC;
        int py2 = 0x476834;
        int py3 = 0x476584;
        int py4 = 0x47634C;
        int py5 = 0x4762F0;
        int py6 = 0x47602C;
        int py7 = 0x476020;
        int py8 = 0x476018;
        offsetsearch2(py1, zerofour, sizeof(zerofour), libue4header);
        offsetsearch2(py2, zerofour, sizeof(zerofour), libue4header);
        offsetsearch2(py3, zerofour, sizeof(zerofour), libue4header);
        offsetsearch2(py4, zerofour, sizeof(zerofour), libue4header);
        offsetsearch2(py5, zerofour, sizeof(zerofour), libue4header);
        offsetsearch2(py6, zerofour, sizeof(zerofour), libue4header);
        offsetsearch2(py7, zerofour, sizeof(zerofour), libue4header);
        offsetsearch2(py8, zerofour, sizeof(zerofour), libue4header);

        //tersafe
        BYTE aj[] = { 0x05, 0x46, 0x00, 0xE0, 0x3D, 0x46, 0x18, 0x23 };
        BYTE aj1[] = { 0x38, 0x46, 0x7A, 0x44, 0xCD, 0xE9, 0x00, 0x45 };
        BYTE aj2[] = { 0x20, 0x6C, 0x29, 0x6C, 0x31, 0xF0, 0x67, 0xFA };
        BYTE aj3[] = { 0xBD, 0xE8, 0xF0, 0x8F, 0x2D, 0xE9, 0xF7, 0x43 };
        offsetsearch2(0x2D45EC, aj, sizeof(aj), libtersafeheader);
        offsetsearch2(0x27E0F0, aj1, sizeof(aj1), libtersafeheader);
        offsetsearch2(0x24636C, aj2, sizeof(aj2), libtersafeheader);
        offsetsearch2(0x246184, aj3, sizeof(aj3), libtersafeheader);

        //new shits
        BYTE sMKfn[] = { 0x70, 0x47, 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(286098, sMKfn, sizeof(sMKfn), libtersafeheader);
        BYTE UbpNF[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(366656, UbpNF, sizeof(UbpNF), libtersafeheader);
        BYTE eJJzw[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(527920, eJJzw, sizeof(eJJzw), libtersafeheader);
        BYTE CieXa[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(154116, CieXa, sizeof(CieXa), libtersafeheader);
        BYTE fsBZP[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(370708, fsBZP, sizeof(fsBZP), libtersafeheader);
        BYTE frgIB[] = { 0x70, 0x47, 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(461842, frgIB, sizeof(frgIB), libtersafeheader);
        BYTE Gmhir[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(461854, Gmhir, sizeof(Gmhir), libtersafeheader);
        BYTE SvCsx[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(461854, SvCsx, sizeof(SvCsx), libtersafeheader);
        BYTE pOsre[] = { 0x70, 0x47, 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(461864, pOsre, sizeof(pOsre), libtersafeheader);
        BYTE iHFkx[] = { 0x70, 0x47, 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(461896, iHFkx, sizeof(iHFkx), libtersafeheader);
        BYTE CeNir[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(159660, CeNir, sizeof(CeNir), libtersafeheader);
        BYTE Idejt[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(175148, Idejt, sizeof(Idejt), libtersafeheader);
        BYTE wHWsR[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(197788, wHWsR, sizeof(wHWsR), libtersafeheader);
        BYTE kGBaS[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(246876, kGBaS, sizeof(kGBaS), libtersafeheader);
        BYTE irRqH[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(286812, irRqH, sizeof(irRqH), libtersafeheader);
        BYTE lmnWB[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(76616, lmnWB, sizeof(lmnWB), libtersafeheader);
        BYTE IMOYo[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(85660, IMOYo, sizeof(IMOYo), libtersafeheader);
        BYTE zOPBG[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(146260, zOPBG, sizeof(zOPBG), libtersafeheader);
        BYTE RmNhM[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(163624, RmNhM, sizeof(RmNhM), libtersafeheader);
        BYTE tBYUz[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(426842, tBYUz, sizeof(tBYUz), libtersafeheader);
        BYTE BktGm[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(70628, BktGm, sizeof(BktGm), libtersafeheader);
        BYTE Nrukq[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(70764, Nrukq, sizeof(Nrukq), libtersafeheader);
        BYTE Hrrue[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(70816, Hrrue, sizeof(Hrrue), libtersafeheader);
        BYTE jDSeJ[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(76352, jDSeJ, sizeof(jDSeJ), libtersafeheader);
        BYTE YiMoU[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(76460, YiMoU, sizeof(YiMoU), libtersafeheader);
        BYTE GiyMY[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(70628, GiyMY, sizeof(GiyMY), libtersafeheader);
        BYTE dELLt[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(70764, dELLt, sizeof(dELLt), libtersafeheader);
        BYTE BWYmR[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(70816, BWYmR, sizeof(BWYmR), libtersafeheader);
        BYTE mwDrT[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(76352, mwDrT, sizeof(mwDrT), libtersafeheader);
        BYTE tJmWR[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(76460, tJmWR, sizeof(tJmWR), libtersafeheader);
        BYTE kJVCV[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(90912, kJVCV, sizeof(kJVCV), libtersafeheader);
        BYTE LqgeS[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(204922, LqgeS, sizeof(LqgeS), libtersafeheader);
        BYTE CmJhO[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(207560, CmJhO, sizeof(CmJhO), libtersafeheader);
        BYTE pmhdE[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(227544, pmhdE, sizeof(pmhdE), libtersafeheader);
        BYTE YuWCa[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(231012, YuWCa, sizeof(YuWCa), libtersafeheader);


        //old shits
        BYTE gkqR[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(1059372, gkqR, sizeof(gkqR), libtersafeheader);
        BYTE GmBI[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(1061536, GmBI, sizeof(GmBI), libtersafeheader);
        BYTE pmXP[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(1061744, pmXP, sizeof(pmXP), libtersafeheader);
        BYTE frJm[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(1071476, frJm, sizeof(frJm), libtersafeheader);
        BYTE hmto[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(1071616, hmto, sizeof(hmto), libtersafeheader);
        BYTE pQyW[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(1079348, pQyW, sizeof(pQyW), libtersafeheader);
        BYTE nzbp[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(1093804, nzbp, sizeof(nzbp), libtersafeheader);
        BYTE GAJB[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(1239048, GAJB, sizeof(GAJB), libtersafeheader);
        BYTE AAeR[] = { 0x00, 0xF0, 0x20, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1, 0x00, 0xF0, 0x20, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1032, AAeR, sizeof(AAeR), libtersafeheader);
        BYTE mtHD[] = { 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF };
        offsetsearch2(69750, mtHD, sizeof(mtHD), libtersafeheader);
        BYTE YMUH[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(79940, YMUH, sizeof(YMUH), libtersafeheader);
        BYTE jTEQ[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(108900, jTEQ, sizeof(jTEQ), libtersafeheader);
        BYTE BboC[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(110324, BboC, sizeof(BboC), libtersafeheader);
        BYTE SpUo[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(216964, SpUo, sizeof(SpUo), libtersafeheader);
        BYTE phJl[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(361128, phJl, sizeof(phJl), libtersafeheader);
        BYTE ulmD[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(2170604, ulmD, sizeof(ulmD), libtersafeheader);
        BYTE jYDb[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(2172144, jYDb, sizeof(jYDb), libtersafeheader);
        BYTE oIwG[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(512611, oIwG, sizeof(oIwG), libtersafeheader);
        BYTE VKWe[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(523963, VKWe, sizeof(VKWe), libtersafeheader);
        BYTE prtB[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(524467, prtB, sizeof(prtB), libtersafeheader);
        BYTE nwpo[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(364623, nwpo, sizeof(nwpo), libtersafeheader);
        BYTE UhQv[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(556707, UhQv, sizeof(UhQv), libtersafeheader);
        BYTE OImn[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(365159, OImn, sizeof(OImn), libtersafeheader);
        BYTE idms[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(366715, idms, sizeof(idms), libtersafeheader);
        BYTE FttB[] = { 0x70, 0x47, 0x70, 0x47 };
        offsetsearch2(288432, FttB, sizeof(FttB), libtersafeheader);
        BYTE FsmD[] = { 0x02, 0xB4, 0x04, 0xBC, 0x00, 0x78, 0x99, 0x2 };
        offsetsearch2(90708, FsmD, sizeof(FsmD), libtersafeheader);
        BYTE Dnto[] = { 0x02, 0xB4, 0x04, 0xBC, 0x00, 0x78, 0x99, 0x2 };
        offsetsearch2(90736, Dnto, sizeof(Dnto), libtersafeheader);
        BYTE FzKF[] = { 0x02, 0xB4, 0x04, 0xBC, 0x00, 0x78, 0x99, 0x2 };
        offsetsearch2(90764, FzKF, sizeof(FzKF), libtersafeheader);
        BYTE OfnZ[] = { 0xBF, 0x00, 0xBF };
        offsetsearch2(108391, OfnZ, sizeof(OfnZ), libtersafeheader);
        BYTE yJZh[] = { 0xBF, 0x00, 0xBF };
        offsetsearch2(108945, yJZh, sizeof(yJZh), libtersafeheader);
        BYTE EsCW[] = { 0xBF, 0x00, 0xBF };
        offsetsearch2(110369, EsCW, sizeof(EsCW), libtersafeheader);
        BYTE UrnK[] = { 0xBF, 0x00, 0xBF };
        offsetsearch2(111805, UrnK, sizeof(UrnK), libtersafeheader);
        BYTE saNr[] = { 0xBF, 0x00, 0xBF };
        offsetsearch2(109691, saNr, sizeof(saNr), libtersafeheader);
        BYTE jtxF[] = { 0xBF, 0x00, 0xBF };
        offsetsearch2(111135, jtxF, sizeof(jtxF), libtersafeheader);
        BYTE xwDr[] = { 0xBF, 0x00, 0xBF };
        offsetsearch2(112531, xwDr, sizeof(xwDr), libtersafeheader);
        BYTE PRyE[] = { 0x00, 0xBF };
        offsetsearch2(184168, PRyE, sizeof(PRyE), libtersafeheader);
        BYTE pmry[] = { 0x00, 0xBF };
        offsetsearch2(184214, pmry, sizeof(pmry), libtersafeheader);
        BYTE ijIx[] = { 0x00, 0xBF };
        offsetsearch2(184438, ijIx, sizeof(ijIx), libtersafeheader);
        BYTE vciB[] = { 0x00, 0xBF };
        offsetsearch2(364816, vciB, sizeof(vciB), libtersafeheader);
        BYTE lIat[] = { 0x00 };
        offsetsearch2(285884, lIat, sizeof(lIat), libtersafeheader);
        BYTE QGrg[] = { 0x00 };
        offsetsearch2(652436, QGrg, sizeof(QGrg), libtersafeheader);
        BYTE GIOG[] = { 0x00 };
        offsetsearch2(151240, GIOG, sizeof(GIOG), libtersafeheader);
        BYTE mCiW[] = { 0x00 };
        offsetsearch2(174754, mCiW, sizeof(mCiW), libtersafeheader);
        BYTE gfMn[] = { 0x00 };
        offsetsearch2(208126, gfMn, sizeof(gfMn), libtersafeheader);
        BYTE LKRO[] = { 0x00 };
        offsetsearch2(225642, LKRO, sizeof(LKRO), libtersafeheader);
        BYTE lcsm[] = { 0x00 };
        offsetsearch2(250778, lcsm, sizeof(lcsm), libtersafeheader);
        BYTE spoh[] = { 0x00 };
        offsetsearch2(323416, spoh, sizeof(spoh), libtersafeheader);
        BYTE BfoA[] = { 0x00 };
        offsetsearch2(331496, BfoA, sizeof(BfoA), libtersafeheader);
        BYTE iavh[] = { 0x00 };
        offsetsearch2(365258, iavh, sizeof(iavh), libtersafeheader);
        BYTE bUzy[] = { 0x00 };
        offsetsearch2(524488, bUzy, sizeof(bUzy), libtersafeheader);
        BYTE arQs[] = { 0x00 };
        offsetsearch2(533282, arQs, sizeof(arQs), libtersafeheader);
        BYTE imoK[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(220792, imoK, sizeof(imoK), libtersafeheader);
        BYTE kmeT[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(220806, kmeT, sizeof(kmeT), libtersafeheader);
        BYTE oajh[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(221952, oajh, sizeof(oajh), libtersafeheader);
        BYTE Opit[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(540068, Opit, sizeof(Opit), libtersafeheader);
        BYTE OrZn[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(268348, OrZn, sizeof(OrZn), libtersafeheader);
        BYTE hodV[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(329340, hodV, sizeof(hodV), libtersafeheader);
        BYTE OXbW[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(541492, OXbW, sizeof(OXbW), libtersafeheader);
        BYTE txBD[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(595944, txBD, sizeof(txBD), libtersafeheader);
        BYTE cGuW[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(751816, cGuW, sizeof(cGuW), libtersafeheader);
        BYTE zODC[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(222050, zODC, sizeof(zODC), libtersafeheader);
        BYTE TVqE[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(387444, TVqE, sizeof(TVqE), libtersafeheader);
        BYTE eicC[] = { 0x00, 0xBF, 0x00, 0xBF };
        offsetsearch2(356708, eicC, sizeof(eicC), libtersafeheader);
        BYTE umGG[] = { 0x00, 0xBF, 0x00, 0xBF };
        offsetsearch2(364782, umGG, sizeof(umGG), libtersafeheader);
        BYTE BhRo[] = { 0x00, 0xBF, 0x00, 0xBF };
        offsetsearch2(433844, BhRo, sizeof(BhRo), libtersafeheader);
        BYTE fDtE[] = { 0x00, 0xBF, 0x00, 0xBF };
        offsetsearch2(433894, fDtE, sizeof(fDtE), libtersafeheader);
        BYTE iZEl[] = { 0x00, 0xBF, 0x00, 0xBF };
        offsetsearch2(291150, iZEl, sizeof(iZEl), libtersafeheader);
        BYTE IRKp[] = { 0x00, 0xBF, 0x00, 0xBF };
        offsetsearch2(548344, IRKp, sizeof(IRKp), libtersafeheader);
        BYTE GpDc[] = { 0x00, 0xBF, 0x00, 0xBF };
        offsetsearch2(753038, GpDc, sizeof(GpDc), libtersafeheader);
        BYTE dAKU[] = { 0x00, 0x21, 0x00, 0x28, 0x01, 0xD1 };
        offsetsearch2(338888, dAKU, sizeof(dAKU), libtersafeheader);
        BYTE onhU[] = { 0x00, 0xBF, 0x00, 0xBF, 0x00, 0xBF };
        offsetsearch2(365818, onhU, sizeof(onhU), libtersafeheader);
        BYTE sFpX[] = { 0xBF, 0x00, 0xBF };
        offsetsearch2(366693, sFpX, sizeof(sFpX), libtersafeheader);
        BYTE RciC[] = { 0xBF };
        offsetsearch2(433367, RciC, sizeof(RciC), libtersafeheader);
        BYTE tTCs[] = { 0x00, 0xBF };
        offsetsearch2(433386, tTCs, sizeof(tTCs), libtersafeheader);
        BYTE MKfn[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(158316, MKfn, sizeof(MKfn), libtersafeheader);
        BYTE UbpN[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(754876, UbpN, sizeof(UbpN), libtersafeheader);
        BYTE FeJJ[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(755684, FeJJ, sizeof(FeJJ), libtersafeheader);
        BYTE zwCi[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(756316, zwCi, sizeof(zwCi), libtersafeheader);
        BYTE eXaf[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(759476, eXaf, sizeof(eXaf), libtersafeheader);
        BYTE sBZP[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(760788, sBZP, sizeof(sBZP), libtersafeheader);
        BYTE frgI[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(761960, frgI, sizeof(frgI), libtersafeheader);
        BYTE BGmh[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(762584, BGmh, sizeof(BGmh), libtersafeheader);
        BYTE irSv[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(763156, irSv, sizeof(irSv), libtersafeheader);
        BYTE Csxp[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(763936, Csxp, sizeof(Csxp), libtersafeheader);
        BYTE Osre[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(757380, Osre, sizeof(Osre), libtersafeheader);
        BYTE iHFk[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(757432, iHFk, sizeof(iHFk), libtersafeheader);
        BYTE xCeN[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1232320, xCeN, sizeof(xCeN), libtersafeheader);
        BYTE irId[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1235136, irId, sizeof(irId), libtersafeheader);
        BYTE ejtw[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(789496, ejtw, sizeof(ejtw), libtersafeheader);
        BYTE HWsR[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(801488, HWsR, sizeof(HWsR), libtersafeheader);
        BYTE kGBa[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(758092, kGBa, sizeof(kGBa), libtersafeheader);
        BYTE SirR[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(758160, SirR, sizeof(SirR), libtersafeheader);
        BYTE qHlm[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(854832, qHlm, sizeof(qHlm), libtersafeheader);
        BYTE nWBI[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(794732, nWBI, sizeof(nWBI), libtersafeheader);
        BYTE MOYo[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(796256, MOYo, sizeof(MOYo), libtersafeheader);
        BYTE zOPB[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(795704, zOPB, sizeof(zOPB), libtersafeheader);
        BYTE GRmN[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(797424, GRmN, sizeof(GRmN), libtersafeheader);
        BYTE hMtB[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(778684, hMtB, sizeof(hMtB), libtersafeheader);
        BYTE YUzB[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(879924, YUzB, sizeof(YUzB), libtersafeheader);
        BYTE ktGm[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(793399, ktGm, sizeof(ktGm), libtersafeheader);
        BYTE Nruk[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(802235, Nruk, sizeof(Nruk), libtersafeheader);
        BYTE qHrr[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(803807, qHrr, sizeof(qHrr), libtersafeheader);
        BYTE uejD[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(852467, uejD, sizeof(uejD), libtersafeheader);
        BYTE SeJY[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1231303, SeJY, sizeof(SeJY), libtersafeheader);
        BYTE iMoU[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1865519, iMoU, sizeof(iMoU), libtersafeheader);
        BYTE GiyM[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(782011, GiyM, sizeof(GiyM), libtersafeheader);
        BYTE YdEL[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(905827, YdEL, sizeof(YdEL), libtersafeheader);
        BYTE LtBW[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1234323, LtBW, sizeof(LtBW), libtersafeheader);
        BYTE YmRm[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1242799, YmRm, sizeof(YmRm), libtersafeheader);
        BYTE wDrT[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1068759, wDrT, sizeof(wDrT), libtersafeheader);
        BYTE tJmW[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1365559, tJmW, sizeof(tJmW), libtersafeheader);
        BYTE RkJV[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1409727, RkJV, sizeof(RkJV), libtersafeheader);
        BYTE CVLq[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(1849319, CVLq, sizeof(CVLq), libtersafeheader);
        BYTE geSC[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(157848, geSC, sizeof(geSC), libtersafeheader);
        BYTE mJhO[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(158036, mJhO, sizeof(mJhO), libtersafeheader);
        BYTE pmhd[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(158320, pmhd, sizeof(pmhd), libtersafeheader);
        BYTE EYuW[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(759480, EYuW, sizeof(EYuW), libtersafeheader);
        BYTE Caiz[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(760792, Caiz, sizeof(Caiz), libtersafeheader);
        BYTE OezX[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(761964, OezX, sizeof(OezX), libtersafeheader);
        BYTE RsSl[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(762588, RsSl, sizeof(RsSl), libtersafeheader);
        BYTE EhgB[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(763160, EhgB, sizeof(EhgB), libtersafeheader);
        BYTE sIeo[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(763940, sIeo, sizeof(sIeo), libtersafeheader);
        BYTE IQmY[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(764720, IQmY, sizeof(IQmY), libtersafeheader);
        BYTE AIrE[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(156236, AIrE, sizeof(AIrE), libtersafeheader);
        BYTE HPtD[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(157416, HPtD, sizeof(HPtD), libtersafeheader);
        BYTE jQgm[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(159288, jQgm, sizeof(jQgm), libtersafeheader);
        BYTE TEbS[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(159388, TEbS, sizeof(TEbS), libtersafeheader);
        BYTE homn[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(759196, homn, sizeof(homn), libtersafeheader);
        BYTE Nftm[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(767576, Nftm, sizeof(Nftm), libtersafeheader);
        BYTE zpwi[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(768128, zpwi, sizeof(zpwi), libtersafeheader);
        BYTE ZOnB[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(775472, ZOnB, sizeof(ZOnB), libtersafeheader);
        BYTE tFAg[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(776384, tFAg, sizeof(tFAg), libtersafeheader);
        BYTE CZlC[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(776540, CZlC, sizeof(CZlC), libtersafeheader);
        BYTE LhCk[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(61416, LhCk, sizeof(LhCk), libtersafeheader);
        BYTE omcb[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(156308, omcb, sizeof(omcb), libtersafeheader);
        BYTE mgpv[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(754040, mgpv, sizeof(mgpv), libtersafeheader);
        BYTE oErZ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(755636, oErZ, sizeof(oErZ), libtersafeheader);
        BYTE QRYA[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(755772, QRYA, sizeof(QRYA), libtersafeheader);
        BYTE aTzb[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(756960, aTzb, sizeof(aTzb), libtersafeheader);
        BYTE fPmy[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(759988, fPmy, sizeof(fPmy), libtersafeheader);
        BYTE wVJL[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(761228, wVJL, sizeof(wVJL), libtersafeheader);
        BYTE QUXm[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(762384, QUXm, sizeof(QUXm), libtersafeheader);
        BYTE UVvo[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(762948, UVvo, sizeof(UVvo), libtersafeheader);
        BYTE OZDq[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(763580, OZDq, sizeof(OZDq), libtersafeheader);
        BYTE XRWR[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(764300, XRWR, sizeof(XRWR), libtersafeheader);
        BYTE bilS[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(765140, bilS, sizeof(bilS), libtersafeheader);
        BYTE sFlZ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(765704, sFlZ, sizeof(sFlZ), libtersafeheader);
        BYTE Oaki[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(766344, Oaki, sizeof(Oaki), libtersafeheader);
        BYTE wkeZ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(766908, wkeZ, sizeof(wkeZ), libtersafeheader);
        BYTE ehSz[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(767676, ehSz, sizeof(ehSz), libtersafeheader);
        BYTE Qkok[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(768228, Qkok, sizeof(Qkok), libtersafeheader);
        BYTE nEox[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(768912, nEox, sizeof(nEox), libtersafeheader);
        BYTE fWHe[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(769496, fWHe, sizeof(fWHe), libtersafeheader);
        BYTE zEFA[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(772828, zEFA, sizeof(zEFA), libtersafeheader);
        BYTE tlqz[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(776436, tlqz, sizeof(tlqz), libtersafeheader);
        BYTE sgpP[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(777124, sgpP, sizeof(sgpP), libtersafeheader);
        BYTE tvMv[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(781024, tvMv, sizeof(tvMv), libtersafeheader);
        BYTE IoVT[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(785584, IoVT, sizeof(IoVT), libtersafeheader);
        BYTE SueC[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(786968, SueC, sizeof(SueC), libtersafeheader);
        BYTE pijM[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(789884, pijM, sizeof(pijM), libtersafeheader);
        BYTE slbg[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(790456, slbg, sizeof(slbg), libtersafeheader);
        BYTE Mmtp[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(791916, Mmtp, sizeof(Mmtp), libtersafeheader);
        BYTE gnrD[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(791956, gnrD, sizeof(gnrD), libtersafeheader);
        BYTE tgXF[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(793640, tgXF, sizeof(tgXF), libtersafeheader);
        BYTE GxdS[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(793736, GxdS, sizeof(GxdS), libtersafeheader);
        BYTE iIHd[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(794000, iIHd, sizeof(iIHd), libtersafeheader);
        BYTE lNOZ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(794560, lNOZ, sizeof(lNOZ), libtersafeheader);
        BYTE VbUg[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(797908, VbUg, sizeof(VbUg), libtersafeheader);
        BYTE BhHm[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(798064, BhHm, sizeof(BhHm), libtersafeheader);
        BYTE lqDK[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(800628, lqDK, sizeof(lqDK), libtersafeheader);
        BYTE hXeU[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(804384, hXeU, sizeof(hXeU), libtersafeheader);
        BYTE rIMt[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807112, rIMt, sizeof(rIMt), libtersafeheader);
        BYTE xHjd[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807296, xHjd, sizeof(xHjd), libtersafeheader);
        BYTE PMeK[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807316, PMeK, sizeof(PMeK), libtersafeheader);
        BYTE MpUM[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807412, MpUM, sizeof(MpUM), libtersafeheader);
        BYTE mGTx[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807608, mGTx, sizeof(mGTx), libtersafeheader);
        BYTE ByiM[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(823264, ByiM, sizeof(ByiM), libtersafeheader);
        BYTE iwVG[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(823952, iwVG, sizeof(iwVG), libtersafeheader);
        BYTE tXYk[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(832348, tXYk, sizeof(tXYk), libtersafeheader);
        BYTE iTer[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(833036, iTer, sizeof(iTer), libtersafeheader);
        BYTE Qjuq[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(837928, Qjuq, sizeof(Qjuq), libtersafeheader);
        BYTE SucM[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(841220, SucM, sizeof(SucM), libtersafeheader);
        BYTE JDZF[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(841908, JDZF, sizeof(JDZF), libtersafeheader);


        //extended end
        BYTE oiono[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(61416, oiono, sizeof(oiono), libtersafeheader);
        BYTE gVTIx[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(156308, gVTIx, sizeof(gVTIx), libtersafeheader);
        BYTE gGGcz[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(754040, gGGcz, sizeof(gGGcz), libtersafeheader);
        BYTE BgtVl[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(755636, BgtVl, sizeof(BgtVl), libtersafeheader);
        BYTE zULcK[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(755772, zULcK, sizeof(zULcK), libtersafeheader);
        BYTE snWjM[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(756960, snWjM, sizeof(snWjM), libtersafeheader);
        BYTE YvFeC[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(759988, YvFeC, sizeof(YvFeC), libtersafeheader);
        BYTE FDMKy[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(761228, FDMKy, sizeof(FDMKy), libtersafeheader);
        BYTE rEarC[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(762384, rEarC, sizeof(rEarC), libtersafeheader);
        BYTE peqBb[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(762948, peqBb, sizeof(peqBb), libtersafeheader);
        BYTE mCQic[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(763580, mCQic, sizeof(mCQic), libtersafeheader);
        BYTE EwTnl[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(764300, EwTnl, sizeof(EwTnl), libtersafeheader);
        BYTE yMbKV[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(765140, yMbKV, sizeof(yMbKV), libtersafeheader);
        BYTE twzaZ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(765704, twzaZ, sizeof(twzaZ), libtersafeheader);
        BYTE pSrkM[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(766344, pSrkM, sizeof(pSrkM), libtersafeheader);
        BYTE ocVtt[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(766908, ocVtt, sizeof(ocVtt), libtersafeheader);
        BYTE snzXx[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(767676, snzXx, sizeof(snzXx), libtersafeheader);
        BYTE iqAcn[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(768228, iqAcn, sizeof(iqAcn), libtersafeheader);
        BYTE APjOQ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(768912, APjOQ, sizeof(APjOQ), libtersafeheader);
        BYTE Llypr[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(769496, Llypr, sizeof(Llypr), libtersafeheader);
        BYTE ZocxB[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(772828, ZocxB, sizeof(ZocxB), libtersafeheader);
        BYTE CWite[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(776436, CWite, sizeof(CWite), libtersafeheader);
        BYTE hiepp[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(777124, hiepp, sizeof(hiepp), libtersafeheader);
        BYTE puSoo[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(781024, puSoo, sizeof(puSoo), libtersafeheader);
        BYTE sAeDi[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(785584, sAeDi, sizeof(sAeDi), libtersafeheader);
        BYTE LubWt[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(786968, LubWt, sizeof(LubWt), libtersafeheader);
        BYTE SpHWT[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(789884, SpHWT, sizeof(SpHWT), libtersafeheader);
        BYTE cpcrF[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(790456, cpcrF, sizeof(cpcrF), libtersafeheader);
        BYTE OMqaU[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(791916, OMqaU, sizeof(OMqaU), libtersafeheader);
        BYTE mOHwW[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(791956, mOHwW, sizeof(mOHwW), libtersafeheader);
        BYTE TjswZ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(793640, TjswZ, sizeof(TjswZ), libtersafeheader);
        BYTE lrZVk[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(793736, lrZVk, sizeof(lrZVk), libtersafeheader);
        BYTE dTOrV[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(794000, dTOrV, sizeof(dTOrV), libtersafeheader);
        BYTE vjhZG[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(794560, vjhZG, sizeof(vjhZG), libtersafeheader);
        BYTE rVLNJ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(797908, rVLNJ, sizeof(rVLNJ), libtersafeheader);
        BYTE DomJh[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(798064, DomJh, sizeof(DomJh), libtersafeheader);
        BYTE FojUl[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(800628, FojUl, sizeof(FojUl), libtersafeheader);
        BYTE pNLvN[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(804384, pNLvN, sizeof(pNLvN), libtersafeheader);
        BYTE gbMGt[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807112, gbMGt, sizeof(gbMGt), libtersafeheader);
        BYTE veptO[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807296, veptO, sizeof(veptO), libtersafeheader);
        BYTE IMmMK[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807316, IMmMK, sizeof(IMmMK), libtersafeheader);
        BYTE OoiTS[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807412, OoiTS, sizeof(OoiTS), libtersafeheader);
        BYTE sZMeB[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(807608, sZMeB, sizeof(sZMeB), libtersafeheader);
        BYTE kvmWK[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(823264, kvmWK, sizeof(kvmWK), libtersafeheader);
        BYTE jsqxa[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(823952, jsqxa, sizeof(jsqxa), libtersafeheader);
        BYTE manxF[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(832348, manxF, sizeof(manxF), libtersafeheader);
        BYTE ArasW[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(833036, ArasW, sizeof(ArasW), libtersafeheader);
        BYTE KtLan[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(837928, KtLan, sizeof(KtLan), libtersafeheader);
        BYTE sWpcK[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(841220, sWpcK, sizeof(sWpcK), libtersafeheader);
        BYTE Wobsg[] = { 0x00, 0x00, 0xA0, 0xE3 };
        
        offsetsearch2(841908, Wobsg, sizeof(Wobsg), libtersafeheader);
        BYTE PCNjc[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(846904, PCNjc, sizeof(PCNjc), libtersafeheader);
        BYTE mrusn[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(850788, mrusn, sizeof(mrusn), libtersafeheader);
        BYTE iLVPs[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(851304, iLVPs, sizeof(iLVPs), libtersafeheader);
        BYTE swciT[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(851728, swciT, sizeof(swciT), libtersafeheader);
        BYTE UqABG[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(855188, UqABG, sizeof(UqABG), libtersafeheader);
        BYTE GOUUa[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(865136, GOUUa, sizeof(GOUUa), libtersafeheader);
        BYTE oHEHs[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(868684, oHEHs, sizeof(oHEHs), libtersafeheader);
        BYTE VTWUe[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(872532, VTWUe, sizeof(VTWUe), libtersafeheader);
        BYTE yegXX[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(873548, yegXX, sizeof(yegXX), libtersafeheader);
        BYTE meAQI[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(874164, meAQI, sizeof(meAQI), libtersafeheader);
        BYTE pIwXO[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(874284, pIwXO, sizeof(pIwXO), libtersafeheader);
        BYTE GerGe[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(876544, GerGe, sizeof(GerGe), libtersafeheader);
        BYTE gxxAK[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(878524, gxxAK, sizeof(gxxAK), libtersafeheader);
        BYTE rDleR[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(878812, rDleR, sizeof(rDleR), libtersafeheader);
        BYTE jdKql[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(880072, jdKql, sizeof(jdKql), libtersafeheader);
        BYTE xstXd[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(880796, xstXd, sizeof(xstXd), libtersafeheader);
        BYTE HzhRV[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(883012, HzhRV, sizeof(HzhRV), libtersafeheader);
        BYTE cMpNj[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(883288, cMpNj, sizeof(cMpNj), libtersafeheader);
        BYTE QmXrN[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(883588, QmXrN, sizeof(QmXrN), libtersafeheader);
        BYTE UppvS[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(885360, UppvS, sizeof(UppvS), libtersafeheader);
        BYTE lAmtJ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(885636, lAmtJ, sizeof(lAmtJ), libtersafeheader);
        BYTE tCODI[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(885900, tCODI, sizeof(tCODI), libtersafeheader);
        BYTE LgwmK[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(889688, LgwmK, sizeof(LgwmK), libtersafeheader);
        BYTE BWLeH[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(889920, BWLeH, sizeof(BWLeH), libtersafeheader);
        BYTE urhwn[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(897280, urhwn, sizeof(urhwn), libtersafeheader);
        BYTE RoREP[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(897968, RoREP, sizeof(RoREP), libtersafeheader);
        BYTE ruUmH[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(901304, ruUmH, sizeof(ruUmH), libtersafeheader);
        BYTE eUtzW[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(907520, eUtzW, sizeof(eUtzW), libtersafeheader);
        BYTE lhkHi[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(909300, lhkHi, sizeof(lhkHi), libtersafeheader);
        BYTE npXAr[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(909552, npXAr, sizeof(npXAr), libtersafeheader);
        BYTE aaBMf[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(909976, aaBMf, sizeof(aaBMf), libtersafeheader);
        BYTE lmIzY[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(910856, lmIzY, sizeof(lmIzY), libtersafeheader);
        BYTE ZokIj[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(911152, ZokIj, sizeof(ZokIj), libtersafeheader);
        BYTE sDeZQ[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(911620, sDeZQ, sizeof(sDeZQ), libtersafeheader);
        BYTE fjRub[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(918260, fjRub, sizeof(fjRub), libtersafeheader);
        BYTE wjGcY[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(922784, wjGcY, sizeof(wjGcY), libtersafeheader);
        BYTE sjBlU[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(922924, sjBlU, sizeof(sjBlU), libtersafeheader);
        BYTE MCLyY[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(923568, MCLyY, sizeof(MCLyY), libtersafeheader);
        BYTE jwxkn[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(925400, jwxkn, sizeof(jwxkn), libtersafeheader);
        BYTE VGKsV[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(925940, VGKsV, sizeof(VGKsV), libtersafeheader);
        BYTE rlGwE[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(929548, rlGwE, sizeof(rlGwE), libtersafeheader);
        BYTE hvRSx[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(930324, hvRSx, sizeof(hvRSx), libtersafeheader);
        BYTE lchjn[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(934560, lchjn, sizeof(lchjn), libtersafeheader);
        BYTE ArBhf[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(935248, ArBhf, sizeof(ArBhf), libtersafeheader);
        BYTE ntxYv[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(938444, ntxYv, sizeof(ntxYv), libtersafeheader);
        BYTE ldSbG[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(939132, ldSbG, sizeof(ldSbG), libtersafeheader);
        BYTE cZrrc[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(942696, cZrrc, sizeof(cZrrc), libtersafeheader);
        BYTE nsrdp[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(943384, nsrdp, sizeof(nsrdp), libtersafeheader);
        BYTE mhuXy[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(947328, mhuXy, sizeof(mhuXy), libtersafeheader);
        BYTE cCBis[] = { 0x00, 0x00, 0xA0, 0xE3 };
        offsetsearch2(947532, cCBis, sizeof(cCBis), libtersafeheader);

        //reverse patch
        BYTE gkqRG[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x37ec374, gkqRG, sizeof(gkqRG), libue4header);
        BYTE mBIpm[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x5a50829, mBIpm, sizeof(mBIpm), libue4header);
        BYTE XPfrJ[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x4b8836c, XPfrJ, sizeof(XPfrJ), libue4header);
        BYTE mhmto[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x4b89ff0, mhmto, sizeof(mhmto), libue4header);
        BYTE pQyWn[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x4b8a79c, pQyWn, sizeof(pQyWn), libue4header);
        BYTE zbpGA[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x4b8b7dc, zbpGA, sizeof(zbpGA), libue4header);
        BYTE JBAAe[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x4b8dca8, JBAAe, sizeof(JBAAe), libue4header);
        BYTE RmtHD[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0xfdaa48, RmtHD, sizeof(RmtHD), libue4header);
        BYTE YMUHj[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x486c5b0, YMUHj, sizeof(YMUHj), libue4header);
        BYTE TEQBb[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x4baa424, TEQBb, sizeof(TEQBb), libue4header);
        BYTE oCSpU[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x4baf8b8, oCSpU, sizeof(oCSpU), libue4header);
        BYTE ophJl[] = { 0x00, 0x20, 0x70, 0x47 };
        offsetsearch2(0x4baf8be, ophJl, sizeof(ophJl), libue4header);
        BYTE ulmDj[] = { 0x00, 0xBF };
        offsetsearch2(0x410d98, ulmDj, sizeof(ulmDj), libue4header);
        BYTE YDboI[] = { 0x00 };
        offsetsearch2(0x48050ba, YDboI, sizeof(YDboI), libue4header);
        BYTE wGVKW[] = { 0x00 };
        offsetsearch2(0x48143f8, wGVKW, sizeof(wGVKW), libue4header);
        BYTE eprtB[] = { 0x00 };
        offsetsearch2(0x48222d8, eprtB, sizeof(eprtB), libue4header);
        BYTE nwpoU[] = { 0x00 };
        offsetsearch2(0x4822404, nwpoU, sizeof(nwpoU), libue4header);
        BYTE hQvOI[] = { 0x00 };
        offsetsearch2(0x48ac006, hQvOI, sizeof(hQvOI), libue4header);
        BYTE mnidm[] = { 0x00 };
        offsetsearch2(0x48ba02c, mnidm, sizeof(mnidm), libue4header);
        BYTE sFttB[] = { 0x00 };
        offsetsearch2(0x48bfcda, sFttB, sizeof(sFttB), libue4header);
        BYTE FsmDD[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(0x4827aa8, FsmDD, sizeof(FsmDD), libue4header);
        BYTE ntoFz[] = { 0x00, 0x00, 0x00, 0x00 };
        offsetsearch2(0x482c320, ntoFz, sizeof(ntoFz), libue4header);
        BYTE KFOfn[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xb97bc0, KFOfn, sizeof(KFOfn), libue4header);
        BYTE ZyJZh[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xb983d0, ZyJZh, sizeof(ZyJZh), libue4header);
        BYTE EsCWU[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xb99e20, EsCWU, sizeof(EsCWU), libue4header);
        BYTE rnKsa[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xb9b450, rnKsa, sizeof(rnKsa), libue4header);
        BYTE Nrjtx[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xb9bfa0, Nrjtx, sizeof(Nrjtx), libue4header);
        BYTE FxwDr[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xb9e460, FxwDr, sizeof(FxwDr), libue4header);
        BYTE PRyEp[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xba34b0, PRyEp, sizeof(PRyEp), libue4header);
        BYTE mryij[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xba6e10, mryij, sizeof(mryij), libue4header);
        BYTE Ixvci[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xba9a00, Ixvci, sizeof(Ixvci), libue4header);
        BYTE BlIat[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xbac1e0, BlIat, sizeof(BlIat), libue4header);
        BYTE QGrgG[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0x17b1f4c, QGrgG, sizeof(QGrgG), libue4header);
        BYTE IOGmC[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0x17bed28, IOGmC, sizeof(IOGmC), libue4header);
        BYTE iWgfM[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0x1be729c, iWgfM, sizeof(iWgfM), libue4header);
        BYTE nLKRO[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0x2da2fe8, nLKRO, sizeof(nLKRO), libue4header);
        BYTE lcsms[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdeddf4, lcsms, sizeof(lcsms), libue4header);
        BYTE pohBf[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdedfc8, pohBf, sizeof(pohBf), libue4header);
        BYTE oAiav[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdee1a4, oAiav, sizeof(oAiav), libue4header);
        BYTE ue4patch[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(36985112, ue4patch, sizeof(ue4patch), libue4header);
        offsetsearch2(36987420, ue4patch, sizeof(ue4patch), libue4header);
        offsetsearch2(36989104, ue4patch, sizeof(ue4patch), libue4header);
        offsetsearch2(37172364, ue4patch, sizeof(ue4patch), libue4header);
        offsetsearch2(37255084, ue4patch, sizeof(ue4patch), libue4header);
        offsetsearch2(37258292, ue4patch, sizeof(ue4patch), libue4header);

        offsetsearch2(37259472, ue4patch, sizeof(ue4patch), libue4header);

        offsetsearch2(31596320, ue4patch, sizeof(ue4patch), libue4header);
        offsetsearch2(32279116, ue4patch, sizeof(ue4patch), libue4header);
        offsetsearch2(32345764, ue4patch, sizeof(ue4patch), libue4header);
        BYTE hbUzy[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdee380, hbUzy, sizeof(hbUzy), libue4header);
        BYTE arQsi[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdee55c, arQsi, sizeof(arQsi), libue4header);
        BYTE moKkm[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdee738, moKkm, sizeof(moKkm), libue4header);
        BYTE eToaj[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdee914, eToaj, sizeof(eToaj), libue4header);
        BYTE hOpit[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdeeaf0, hOpit, sizeof(hOpit), libue4header);
        BYTE OrZnh[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdeecd0, OrZnh, sizeof(OrZnh), libue4header);
        BYTE odVOX[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xdeeeac, odVOX, sizeof(odVOX), libue4header);
        BYTE bWtxB[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xd57c00, bWtxB, sizeof(bWtxB), libue4header);
        BYTE DcGuW[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xd8a720, DcGuW, sizeof(DcGuW), libue4header);
        BYTE zODCT[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xd8a764, zODCT, sizeof(zODCT), libue4header);
        BYTE VqEei[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xecfc20, VqEei, sizeof(VqEei), libue4header);
        BYTE cCumG[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xed0760, cCumG, sizeof(cCumG), libue4header);
        BYTE GBhRo[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xed07a4, GBhRo, sizeof(GBhRo), libue4header);
        BYTE fDtEi[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xed07e8, fDtEi, sizeof(fDtEi), libue4header);
        BYTE ZElIR[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xed082c, ZElIR, sizeof(ZElIR), libue4header);
        BYTE KpGpD[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xed0870, KpGpD, sizeof(KpGpD), libue4header);
        BYTE cdAKU[] = { 0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1 };
        offsetsearch2(0xed08b4, cdAKU, sizeof(cdAKU), libue4header);

        

        ////////////////////////////////////////////////////////////////////////////////////////////////
        //nullbytes
        /*offsetsearch(18982492, libue4header);
        offsetsearch(18981852, libue4header);
        offsetsearch(23316648, libue4header);
        offsetsearch(18982904, libue4header);
        offsetsearch(70703780, libue4header);
        offsetsearch(18983884, libue4header);
        offsetsearch(18985832, libue4header);
        offsetsearch(19012208, libue4header);
        offsetsearch(18986360, libue4header);
        offsetsearch(19012736, libue4header);
        offsetsearch(18987308, libue4header);
        offsetsearch(43966980, libue4header);
        offsetsearch(18955264, libue4header);
        offsetsearch(18961500, libue4header);
        offsetsearch(18961676, libue4header);
        offsetsearch(26700960, libue4header);
        offsetsearch(18961988, libue4header);
        offsetsearch(18963124, libue4header);
        offsetsearch(18963868, libue4header);
        offsetsearch(19016596, libue4header);
        offsetsearch(20243172, libue4header);
        offsetsearch(18964304, libue4header);
        offsetsearch(20732035, libue4header);
        offsetsearch(39085011, libue4header);
        offsetsearch(19129112, libue4header);
        offsetsearch(30301044, libue4header);
        offsetsearch(18783920, libue4header);
        offsetsearch(18784336, libue4header);
        offsetsearch(30234572, libue4header);
        offsetsearch(18786724, libue4header);


        offsetsearch(18402827, libue4header);
        offsetsearch(19728591, libue4header);
        offsetsearch(19013696, libue4header);
        offsetsearch(19026780, libue4header);
        offsetsearch(21060540, libue4header);
        offsetsearch(24787664, libue4header);
        offsetsearch(19014928, libue4header);
        offsetsearch(19016136, libue4header);
        offsetsearch(19017004, libue4header);
        offsetsearch(19018180, libue4header);
        offsetsearch(18775296, libue4header);
        offsetsearch(22911932, libue4header);
        offsetsearch(19022960, libue4header);
        offsetsearch(19023376, libue4header);
        offsetsearch(19131416, libue4header);
        offsetsearch(19023768, libue4header);
        offsetsearch(19024724, libue4header);*/
        /*BYTE cxor[] = {0x02, 0x0D, 0x02, 0x00};
        BYTE cxor1[] = { 0x02, 0x12, 0x20, 0x00 };
        BYTE cxor2[] = { 0x03, 0x0A, 0x02, 0x00 };
        BYTE cxorrep[] = { 0x03, 0x03, 0x02, 0x02 };
        AOBREPSILENT2(cxor, cxorrep, sizeof(cxor), sizeof(cxorrep), 6969);
        AOBREPSILENT2(cxor1, cxorrep, sizeof(cxor1), sizeof(cxorrep), 6969);
        AOBREPSILENT2(cxor2, cxorrep, sizeof(cxor2), sizeof(cxorrep), 6969);*/

        
        resume(pid);
        /*Sleep(10000);
        BYTE abc[] = { 0x01, 0x03, 0x04, 0x04 };
        BYTE abc1[] = { 0xFF, 0xFF, 0x01, 0x00 };
        BYTE abc2[] = { 0x04, 0x04, 0x00, 0x04 };
        BYTE abc3[] = { 0x12, 0x00, 0x0B, 0x00 };
        BYTE abc4[] = { 0x03, 0x34, 0x02, 0x00 };
        BYTE abc5[] = { 0x01, 0x03, 0x01, 0x04 };
        BYTE abcrep[] = { 0x01, 0x03, 0x00, 0x04 };
        AOBREPSILENT2(abc, abcrep, 4, 4, 100);
        //AOBREPSILENT2(abc1, abcrep, 4, 4, 100);
        AOBREPSILENT2(abc2, abcrep, 4, 4, 100);
        //AOBREPSILENT2(abc3, abcrep, 4, 4, 100);
        AOBREPSILENT2(abc4, abcrep, 4, 4, 100);
        //AOBREPSILENT2(abc5, abcrep, 4, 4, 100);*/
        /* //swappy baby
         patch(0xB192B, libswappyheader);
         Sleep(25000);
         //useless libs
         int libbuglyheader = get_module_base("libBugly");
         int libcubehawk = get_module_base("libcubehawk");
         int libgamemaster = get_module_base("libgamemaster");
         int libgcloudarch = get_module_base("libgcloudarch");
         int libigshare = get_module_base("libigshare");
         int libIMSDK = get_module_base("libIMSDK");
         int libnppsjni = get_module_base("libnpps-jni");
         int libstengine = get_module_base("libst-engine");
         int libTDataMaster = get_module_base("libTDataMaster");
         int libtprt = get_module_base("libtprt");
         //patch(0x276FF, libbuglyheader);
         patch(0xD3D3F, libcubehawk);
         //patch(0x787E3, libgamemaster);
         //patch(0x348B, libgcloudarch);
         //patch(0x358F, libigshare);
         //patch(0x196E7, libIMSDK);
         //patch(0x765F, libnppsjni);
         //patch(0x84953, libstengine);
         //patch(0x8A857, libTDataMaster);
         //patch(0x754D7, libtprt);
         //cout << "Bypassed! " << endl;*/
    }
}

string readFile(string location)
{
    string myText;
    ifstream MyReadFile(location);
    while (getline(MyReadFile, myText)) {
        cout << myText;
    }
    MyReadFile.close();
    return myText;
}

void fuckingentrypoint()
{
    //These four lines hides the console
    HWND window;
    AllocConsole();
    window = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(window, 0);
    /*system("del C:\\Windows\\integrity.ini");
    system("curl https://pastebin.com/raw/ikW6xy8e >> C:\\Windows\\integrity.ini");
    Sleep(1000);
    string checks = readFile("C:\\Windows\\integrity.ini");
    if (checks == "anarchistwashot")
    {
        ////
    }
    else
    {
        MessageBoxA(0, "integrity check failed", 0, MB_OK);
        exit(43);
    }*/
    if (!FileExist("C:\\Windows\\SrcVersion.ini"))
    {
        WriteResToDisk("C:\\Windows\\SrcVersion.ini", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA5));
    }
    if (!FileExist("C:\\Windows\\updater.ini"))
    {
        WriteResToDisk("C:\\Windows\\updater.ini", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA6));
    }
    if (!FileExist("C:\\hookdrv.sys"))
    {
        WriteResToDisk("C:\\hookdrv.sys", MAKEINTRESOURCE(IDR_RCDATA2));
    }
    if (!FileExist("C:\\Windows\\adb.exe"))
    {
        WriteResToDisk("C:\\Windows\\adb.exe", MAKEINTRESOURCE(IDR_RCDATA3));
    }
    if (!FileExist("C:\\Windows\\AdbWinApi.dll"))
    {
        WriteResToDisk("C:\\Windows\\AdbWinApi.dll", MAKEINTRESOURCE(IDR_RCDATA4));
    }
    std::string dri = "sc create anarchist binPath= \"C:\\hookdrv.sys\" type=filesys";
    string startdri = "sc start anarchist";
    cmdd(dri);
    cmdd(startdri);
entrypoint:
    cout << "Status : N/A" << endl;
    while (true)
    {
        int pid = getProcId();
        if (pid == 0 || pid == 1)
        {
            //std::cout << "No New Splash Activity\n";
        }
        else
        {
            maincodes();
            while (true)
            {
                int newpid = getProcId();
                if (newpid != pid)
                {
                    //system("cls");
                    //cout << "game has been closed, relooping.." << endl;
                    goto entrypoint;
                    break;
                }
                else
                {
                    //cout << "Game is still running" << endl;
                }
                Sleep(3000);
            }
        }
        Sleep(1000);
    }
}

