// SysTrayDemo.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "SysTrayDemo.h"
#include "maincode.h"
#include <Psapi.h>
#include <iostream>
#include <TlHelp32.h>
#include <thread>
#pragma comment(lib,"psapi.lib") //added
#define MAX_LOADSTRING 100
#define	WM_USER_SHELLICON WM_USER + 1
using namespace std;
// Global Variables:
HINSTANCE hInst;	// current instance
NOTIFYICONDATA nidApp;
HMENU hPopMenu;
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name
TCHAR szApplicationToolTip[MAX_LOADSTRING];	    // the main window class name
BOOL bDisable = FALSE;							// keep application state
BOOL bEnable = FALSE;

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);


int getAowProcId()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (strcmp(ProcEntry.szExeFile, "aow_exe.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 300000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}

	CloseHandle(snapshot);
}

int getGagaProcId()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (strcmp(ProcEntry.szExeFile, "AndroidProcess.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 300000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}

	CloseHandle(snapshot);
}

int getLDProcId()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (strcmp(ProcEntry.szExeFile, "LdBoxHeadless.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 300000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}

	CloseHandle(snapshot);
}

int getLDDProcId()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (strcmp(ProcEntry.szExeFile, "LdVBoxHeadless.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 300000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}

	CloseHandle(snapshot);
}

int getProcId()
{
	int aow = getAowProcId();
	int gaga = getGagaProcId();
	int ld = getLDProcId();
	int ld2 = getLDDProcId();
	if (gaga == 0 || gaga == 1)
	{
		if (aow == 0 || aow == 1)
		{
			return 0;
		}
		else
		{
			return aow;
		}
	}
	else
	{
		return gaga;
	}
}

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

 	// TODO: Place code here.
	MSG msg;
	HACCEL hAccelTable;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_SYSTRAYDEMO, szWindowClass, MAX_LOADSTRING);
	
	MyRegisterClass(hInstance);

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_SYSTRAYDEMO));

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage are only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SYSTRAYDEMO));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_SYSTRAYDEMO);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
// 
// 
//

std::thread t1;
std::thread t2;

void isitwhatiwanted()
{
	std::thread t1(&fuckingentrypoint);
	t1.detach();

}

void isitwhatiwanted2()
{
	std::thread t2(&detectemu);
	t2.detach();

}

void terminatethread()
{
	t1.~thread();

}

void terminatethread2()
{
	t2.~thread();

}
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;
   HICON hMainIcon;

   hInst = hInstance; // Store instance handle in our global variable

   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }

   hMainIcon = LoadIcon(hInstance,(LPCTSTR)MAKEINTRESOURCE(IDI_SYSTRAYDEMO)); 

   nidApp.cbSize = sizeof(NOTIFYICONDATA); // sizeof the struct in bytes 
   nidApp.hWnd = (HWND) hWnd;              //handle of the window which will process this app. messages 
   nidApp.uID = IDI_SYSTRAYDEMO;           //ID of the icon that willl appear in the system tray 
   nidApp.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; //ORing of all the flags 
   nidApp.hIcon = hMainIcon; // handle of the Icon to be displayed, obtained from LoadIcon 
   nidApp.uCallbackMessage = WM_USER_SHELLICON; 
   LoadString(hInstance, IDS_APPTOOLTIP,nidApp.szTip,MAX_LOADSTRING);
   Shell_NotifyIcon(NIM_ADD, &nidApp); 

   return TRUE;
}

void Init()
{
	// user defined message that will be sent as the notification message to the Window Procedure 
}
//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
    POINT lpClickPoint;

	switch (message)
	{

	case WM_USER_SHELLICON: 
		// systray msg callback 
		switch(LOWORD(lParam)) 
		{   
			case WM_RBUTTONDOWN: 
				UINT uFlag = MF_BYPOSITION|MF_STRING;
				UINT uFlag2 = MF_BYPOSITION | MF_STRING;
				GetCursorPos(&lpClickPoint);
				hPopMenu = CreatePopupMenu();
				
				if ( bEnable == TRUE )
				{
					uFlag |= MF_CHECKED;
				}
				//InsertMenu(hPopMenu, 0xFFFFFFFF, MF_SEPARATOR, IDM_SEP, _T("SEP"));
				//InsertMenu(hPopMenu,0xFFFFFFFF,uFlag,IDM_TEST2,_T("Test 2")); // Test 2
				InsertMenu(hPopMenu,0xFFFFFFFF,uFlag,IDM_TEST1,_T("Enable")); // Test 1		
				InsertMenu(hPopMenu, 0xFFFFFFFF, uFlag2, IDM_TEST2, _T("Disable"));
				//InsertMenu(hPopMenu,0xFFFFFFFF,MF_SEPARATOR,IDM_SEP,_T("SEP"));				
				if ( bDisable == TRUE )
				{
					//InsertMenu(hPopMenu,0xFFFFFFFF,MF_BYPOSITION|MF_STRING,IDM_ENABLE,_T("Disable"));
					uFlag2 |= MF_CHECKED;
				}
				else 
				{
					//				
				}
				InsertMenu(hPopMenu,0xFFFFFFFF,MF_SEPARATOR,IDM_SEP,_T("SEP"));
				InsertMenu(hPopMenu, 0xFFFFFFFF, MF_BYPOSITION | MF_STRING, IDM_ABOUT, _T("About"));
				InsertMenu(hPopMenu,0xFFFFFFFF,MF_BYPOSITION|MF_STRING,IDM_EXIT,_T("Exit"));
									
				SetForegroundWindow(hWnd);
				TrackPopupMenu(hPopMenu,TPM_LEFTALIGN|TPM_LEFTBUTTON|TPM_BOTTOMALIGN,lpClickPoint.x, lpClickPoint.y,0,hWnd,NULL);
				return TRUE; 

		}
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
			case IDM_ABOUT:
				DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
				break;
			case IDM_TEST1:
				isitwhatiwanted();
				isitwhatiwanted2();
				MessageBox(NULL,_T("Enabled."),_T("Anarchy"),MB_OK);
				bEnable = TRUE;
				break;
			case IDM_TEST2:
				terminatethread();
				terminatethread2();
				MessageBox(NULL,_T("Disabled."),_T("Anarchy"),MB_OK);
				bDisable = TRUE;
				bEnable = FALSE;
				break;
			case IDM_DISABLE:
				bDisable = TRUE;
				break;
			case IDM_ENABLE:
				bEnable = FALSE;
				break;
			case IDM_EXIT:
				Shell_NotifyIcon(NIM_DELETE,&nidApp);
				DestroyWindow(hWnd);
				break;
			default:
				return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
		/*
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		// TODO: Add any drawing code here...
		EndPaint(hWnd, &ps);
		break;*/
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
