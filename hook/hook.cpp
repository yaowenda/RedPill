#include "pch.h"
#include "framework.h"
#include "detours.h"
#include "stdio.h"
#include "stdarg.h"
#include "windows.h"
#include <iostream>
#include <string>
#include <stdlib.h>
#include <unordered_map>
#include <WinSock2.h>
#pragma comment(lib, "detours.lib")
#pragma comment (lib, "ws2_32.lib")  //���� ws2_32.dll
#pragma comment(lib, "ntdll.lib")
#include <shlobj.h>
#include <winuser.h>
#include <winternl.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <Windows.h>
#include <WinDef.h>
using namespace std;
SYSTEMTIME st;
#define MESSAGEBOXA              1  // ����
#define MESSAGEBOXW              2  // ����
#define WRITEFILE                3  // д�ļ�
#define READFILE                 4  // ���ļ�
#define CREATEFILEA              5  // �򿪻򴴽��ļ�
#define CREATEFILEW              6  // �򿪻򴴽��ļ�
#define DELETEFILEA              7  // ɾ���ļ�
#define DELETEFILEW              8  // ɾ���ļ�
#define GETFILEATTRIBUTESW       9  // ��ȡ�ļ�����
#define GETFILESIZE             10  // ��ȡ�ļ���С
#define MOVEFILEW               11  // �ƶ����������ļ�
#define MOVEFILEEXW             12  // �ƶ��ļ���֧�ָ���ѡ�
#define SEND                    13  // ��������
#define SENDTO                  14  // �������ݵ�ָ����ַ
#define WSASEND                 15  // ��������
#define RECV                    16  // ��������
#define RECVFROM                17  // ����Զ������
#define WSARECV                 18  // ��������
#define CONNECT                 19  // ��������
#define WSACONNECT              20  // ��������
#define GETHOSTBYNAME           21  // ��������
#define GETADDRINFO             22  // ����/IP����
#define SOCKET_CREATE           23  // �����׽���
#define SOCKET_CLOSE            24  // �ر��׽���
#define CREATEPROCESSA          25  // �������̣�ANSI�汾��
#define CREATEPROCESSW          26  // �������̣�Unicode�汾��
#define SHELLEXECUTEW           27  // ִ��shell���Unicode�汾��
#define CREATETHREAD            28  // �����߳�
#define EXITTHREAD              29  // ��ֹ�߳�
#define LOADLIBRARYA            30  // ���ض�̬�⣨ANSI�汾��
#define LOADLIBRARYW            31  // ���ض�̬�⣨Unicode�汾��
#define LOADLIBRARYEXW          32  // ���ض�̬�⣨��չ������Unicode�汾��
#define GETPROCADDRESS          33  // ��ȡ������ַ
#define VIRTUALALLOCEX          34  // ��Զ�̽����з����ڴ�
#define WRITEPROCESSMEMORY      35  // ��Զ�̽���д���ڴ�
#define CREATEREMOTETHREAD      36  // ��Զ�̽����д����߳�
#define CREATEWINDOWEXA         37  // �������ڣ���չ��ʽ��ANSI�汾��
#define CREATEWINDOWEXW         38  // �������ڣ���չ��ʽ��Unicode�汾��
#define REGISTERCLASSA          39  // ע�ᴰ���ࣨANSI�汾��
#define REGISTERCLASSW          40  // ע�ᴰ���ࣨUnicode�汾��
#define SETWINDOWLONGA          41  // ���ô������ԣ�ANSI�汾��
#define SETWINDOWLONGW          42  // ���ô������ԣ�Unicode�汾��
#define SHOWWINDOW              43  // ��ʾ����
#define DESTROYWINDOW           44  // ���ٴ���
#define GETASYNCKEYSTATE        45  // ���ĳ���������»����ͷ�
#define GETKEYSTATE             46  // ��ȡָ���������״̬
#define REGISTERHOTKEY          47  // ע��һ��ϵͳ��Χ���ȼ���ȫ�ֿ�ݼ���
#define SETWINDOWSHOOKEXA       48  // �ú������ڰ�װһ�����ӣ����������ز�����������͵������¼���������Ϣ��
#define GETCURSORPOS            49  // ��ȡ���������
#define SETCURSORPOS            50  // ������ƶ���ָ��λ��
#define VIRTUALFREE             51  // �����ͷŻ�ȡ�����������������ڴ�
#define NTQUERYSYSTEMINFORMATION 52 // ��ȡϵͳ�������Ϣ��������б��߳��б������ȣ�
#define NTREADVIRTUALMEMORY     53  // ��ָ�����̵������ַ�ռ��ж�ȡ�ڴ�����





struct info {
	int type, argNum;
	SYSTEMTIME st;
	char argName[10][30];
	char argValue[10][50];
};

enum HookType {
	SOCKETCREATE,
	SOCKETCLOSE,

};

info sendInfo;

// ��һ����ΪmySemaphore�������ź�����ʵ�������ӵ���һ�������Ѿ������õ��ź�����֮�����ʹ������ź�����PV����
HANDLE hSemaphore = OpenSemaphore(EVENT_ALL_ACCESS, FALSE, L"mySemaphore");
// ��һ����ΪShareMemory���ڴ�ӳ���ļ���ʵ�������ӵ�һ���Ѿ����������̴����Ĺ����ڴ�������ʵ�����ݽ���
HANDLE hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, NULL, L"ShareMemory");
// �� hMapFile ָ��Ĺ����ڴ��ļ�ӳ�䵽��ǰ���̵������ַ�ռ��У�������һ��ָ�����ڴ��׵�ַ��ָ�� lpBase���Ա��д���ݡ�
LPVOID lpBase = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(info));

/*
* ------------------------------------------------------------------------------------------------------
  ----------------------------------------------- ���� -------------------------------------------------
  ------------------------------------------------------------------------------------------------------
*/

//���ļ�
static HANDLE(WINAPI* OldCreateFileA)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	) = CreateFileA;

extern "C" __declspec(dllexport) HANDLE WINAPI NewCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	HANDLE hFile = OldCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	if (GetFileType(hFile) == FILE_TYPE_DISK) {
		sendInfo.argNum = 7;

		// ������
		sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");
		sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "dwDesiredAccess");
		sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwShareMode");
		sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpSecurityAttributes");
		sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "dwCreationDisposition");
		sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "dwFlagsAndAttributes");
		sprintf_s(sendInfo.argName[6], sizeof(sendInfo.argName[6]), "hTemplateFile");

		// ����ֵ��ANSI�ַ���ֱ�Ӹ�ֵ��
		if (lpFileName) {
			strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), lpFileName, _TRUNCATE);
		}
		else {
			strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
		}

		sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", dwDesiredAccess);
		sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", dwShareMode);
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", (DWORD_PTR)lpSecurityAttributes);
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%08X", dwCreationDisposition);
		sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "%08X", dwFlagsAndAttributes);
		sprintf_s(sendInfo.argValue[6], sizeof(sendInfo.argValue[6]), "%08X", (DWORD_PTR)hTemplateFile);

		sendInfo.type = CREATEFILEA;
		GetLocalTime(&(sendInfo.st));

		memcpy(lpBase, &sendInfo, sizeof(sendInfo));
		ReleaseSemaphore(hSemaphore, 1, NULL);
		sendInfo.argNum = 0;
	}

	return hFile;
}

static HANDLE(WINAPI* OldCreateFileW)(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	) = CreateFileW;

extern "C" __declspec(dllexport) HANDLE WINAPI NewCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	HANDLE hFile = OldCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	if (GetFileType(hFile) == FILE_TYPE_DISK) {
		sendInfo.argNum = 7;

		// ������
		sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");
		sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "dwDesiredAccess");
		sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwShareMode");
		sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpSecurityAttributes");
		sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "dwCreationDisposition");
		sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "dwFlagsAndAttributes");
		sprintf_s(sendInfo.argName[6], sizeof(sendInfo.argName[6]), "hTemplateFile");

		// ����ֵ�����ַ�תANSI��
		char temp[256] = { 0 };
		if (lpFileName) {
			WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, temp, sizeof(temp) - 1, NULL, NULL);
			strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp, _TRUNCATE);
		}
		else {
			strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
		}

		sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", dwDesiredAccess);
		sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", dwShareMode);
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", (DWORD_PTR)lpSecurityAttributes);
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%08X", dwCreationDisposition);
		sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "%08X", dwFlagsAndAttributes);
		sprintf_s(sendInfo.argValue[6], sizeof(sendInfo.argValue[6]), "%08X", (DWORD_PTR)hTemplateFile);

		sendInfo.type = CREATEFILEW;
		GetLocalTime(&(sendInfo.st));

		memcpy(lpBase, &sendInfo, sizeof(sendInfo));
		ReleaseSemaphore(hSemaphore, 1, NULL);
		sendInfo.argNum = 0;
	}

	return hFile;
}


//���ļ�

// ����ԭʼ������ַ
static BOOL(WINAPI* OldReadFile)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
	) = ReadFile;

// ���ļ�
extern "C" __declspec(dllexport) BOOL WINAPI NewReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
) {
	// ������Ϣ����
	sendInfo.type = READFILE;
	sendInfo.argNum = 5;
	GetLocalTime(&(sendInfo.st));

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "hFile");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpBuffer");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "nNumberOfBytesToRead");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpNumberOfBytesRead");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "lpOverlapped");

	// ����ֵ��תʮ������ָ��/��ֵ��
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (DWORD_PTR)hFile);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", (DWORD_PTR)lpBuffer);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", nNumberOfBytesToRead);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", (DWORD_PTR)lpNumberOfBytesRead);
	sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%08X", (DWORD_PTR)lpOverlapped);

	// д�빲���ڴ沢�ͷ��ź���
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	sendInfo.argNum = 0;

	// ����ԭʼ ReadFile
	return OldReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}


// д�ļ�
static BOOL(WINAPI* OldWriteFile)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	) = WriteFile;

extern "C" __declspec(dllexport)BOOL WINAPI NewWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	if (GetFileType(hFile) == FILE_TYPE_DISK) {
		sendInfo.argNum = 5;
		// ������
		sprintf(sendInfo.argName[0], "hFile");
		sprintf(sendInfo.argName[1], "lpBuffer");
		sprintf(sendInfo.argName[2], "nNumberOfBytesToWrite");
		sprintf(sendInfo.argName[3], "lpNumberOfBytesWritten");
		sprintf(sendInfo.argName[4], "lpOverlapped");
		// ����ֵ
		sprintf(sendInfo.argValue[0], "%08X", hFile);
		sprintf(sendInfo.argValue[1], "%08X", lpBuffer);
		sprintf(sendInfo.argValue[2], "%08X", nNumberOfBytesToWrite);
		sprintf(sendInfo.argValue[3], "%08X", lpNumberOfBytesWritten);
		sprintf(sendInfo.argValue[4], "%08X", lpOverlapped);

		sendInfo.type = WRITEFILE;
		GetLocalTime(&(sendInfo.st));
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	return OldWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

//ɾ���ļ�{messageA)
static BOOL(WINAPI* OldDeleteFileA)(LPCSTR lpFileName) = DeleteFileA;

extern "C" __declspec(dllexport) BOOL WINAPI NewDeleteFileA(LPCSTR lpFileName)
{
	BOOL result = OldDeleteFileA(lpFileName);

	sendInfo.argNum = 1;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");

	// ����ֵ��ANSI�ַ�����ֱ�Ӹ��ƣ�
	if (lpFileName) {
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), lpFileName, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
	}

	sendInfo.type = DELETEFILEA;
	GetLocalTime(&(sendInfo.st));

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//ɾ���ļ�(messageW)
static BOOL(WINAPI* OldDeleteFileW)(LPCWSTR lpFileName) = DeleteFileW;

extern "C" __declspec(dllexport) BOOL WINAPI NewDeleteFileW(LPCWSTR lpFileName)
{
	BOOL result = OldDeleteFileW(lpFileName);

	sendInfo.argNum = 1;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");

	// ����ֵ�����ַ�ת��Ϊ ANSI��
	char temp[256] = { 0 };
	if (lpFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
	}

	sendInfo.type = DELETEFILEW;
	GetLocalTime(&(sendInfo.st));

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//�ļ�����
static DWORD(WINAPI* OldGetFileAttributesW)(LPCWSTR lpFileName) = GetFileAttributesW;

extern "C" __declspec(dllexport) DWORD WINAPI NewGetFileAttributesW(LPCWSTR lpFileName)
{
	DWORD result = OldGetFileAttributesW(lpFileName);

	sendInfo.type = GETFILEATTRIBUTESW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");

	// ����ֵ�����ַ�ת��Ϊ ANSI��
	char temp[256] = { 0 };
	if (lpFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
	}

	// д�빲���ڴ沢֪ͨ
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//�ļ���С
static DWORD(WINAPI* OldGetFileSize)(
	HANDLE hFile,
	LPDWORD lpFileSizeHigh
	) = GetFileSize;

extern "C" __declspec(dllexport) DWORD WINAPI NewGetFileSize(
	HANDLE hFile,
	LPDWORD lpFileSizeHigh
)
{
	DWORD result = OldGetFileSize(hFile, lpFileSizeHigh);

	sendInfo.type = GETFILESIZE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 2;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "hFile");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpFileSizeHigh");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (DWORD)hFile);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", (DWORD)lpFileSizeHigh);

	// д�빲���ڴ沢֪ͨ
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//���ƶ�/�������ļ�
static BOOL(WINAPI* OldMoveFileW)(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
	) = MoveFileW;

extern "C" __declspec(dllexport) BOOL WINAPI NewMoveFileW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
)
{
	char temp[100] = { 0 };

	sendInfo.type = MOVEFILEW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 2;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpExistingFileName");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpNewFileName");

	// ����ֵ�����ַ�ת���ֽڣ�
	if (lpExistingFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpExistingFileName, -1, temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
	}

	memset(temp, 0, sizeof(temp));
	if (lpNewFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpNewFileName, sizeof(lpNewFileName), temp, sizeof(temp), NULL, NULL);
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);
	}

	// д�빲���ڴ沢�ͷ��ź���
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldMoveFileW(lpExistingFileName, lpNewFileName);
}

//֧���滻���ӳ١����Ƶȸ߼��ƶ�����
static BOOL(WINAPI* OldMoveFileExW)(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	DWORD dwFlags
	) = MoveFileExW;

extern "C" __declspec(dllexport) BOOL WINAPI NewMoveFileExW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	DWORD dwFlags
)
{
	char temp[100] = { 0 };

	sendInfo.type = MOVEFILEEXW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 3;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpExistingFileName");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpNewFileName");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwFlags");

	// ����ֵ
	if (lpExistingFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpExistingFileName, -1, temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
	}

	memset(temp, 0, sizeof(temp));
	if (lpNewFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpNewFileName, -1, temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);
	}

	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", dwFlags);

	// д�빲���ڴ沢�ͷ��ź���
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldMoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
}

//send(ͨ��һ�� �ѽ������ӵ��׽��֣�SOCK_STREAM���� TCP�� �������ݡ�)
static int (WINAPI* OldSend)(SOCKET s, const char* buf, int len, int flags) = send;

extern "C" __declspec(dllexport) int WINAPI NewSend(SOCKET s, const char* buf, int len, int flags) {
	sendInfo.argNum = 4;
	sendInfo.type = SEND;
	GetLocalTime(&(sendInfo.st));

	strcpy_s(sendInfo.argName[0], "s");
	strcpy_s(sendInfo.argName[1], "buf");
	strcpy_s(sendInfo.argName[2], "len");
	strcpy_s(sendInfo.argName[3], "flags");

	sprintf_s(sendInfo.argValue[0], "%08X", s);
	if (buf && len > 0) {
		strncpy_s(sendInfo.argValue[1], buf, min(len, 255));
		sendInfo.argValue[1][min(len, 255)] = '\0';
	}
	else {
		strcpy_s(sendInfo.argValue[1], "(null)");
	}
	sprintf_s(sendInfo.argValue[2], "%d", len);
	sprintf_s(sendInfo.argValue[3], "%08X", flags);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldSend(s, buf, len, flags);
}

//sendto(����ͨ��һ���׽��֣������� UDP ��δ���ӵ� TCP����ָ����ַ�������ݣ�������������Э�飨�� UDP����
static int (WINAPI* OldSendTo)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) = sendto;

extern "C" __declspec(dllexport) int WINAPI NewSendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
	sendInfo.argNum = 6;
	sendInfo.type = SENDTO;
	GetLocalTime(&(sendInfo.st));

	strcpy_s(sendInfo.argName[0], "s");
	strcpy_s(sendInfo.argName[1], "buf");
	strcpy_s(sendInfo.argName[2], "len");
	strcpy_s(sendInfo.argName[3], "flags");
	strcpy_s(sendInfo.argName[4], "to");
	strcpy_s(sendInfo.argName[5], "tolen");

	sprintf_s(sendInfo.argValue[0], "%08X", s);
	if (buf && len > 0) {
		strncpy_s(sendInfo.argValue[1], buf, min(len, 255));
		sendInfo.argValue[1][min(len, 255)] = '\0';
	}
	else {
		strcpy_s(sendInfo.argValue[1], "(null)");
	}
	sprintf_s(sendInfo.argValue[2], "%d", len);
	sprintf_s(sendInfo.argValue[3], "%08X", flags);
	sprintf_s(sendInfo.argValue[4], "%08X", to ? to : 0);
	sprintf_s(sendInfo.argValue[5], "%d", tolen);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldSendTo(s, buf, len, flags, to, tolen);
}


//WSAsend(WSASend �� send ����ǿ�汾��֧���첽/�ص� I/O �Ͷ�����������ͣ�ͨ�����ڸ������ܻ��첽�������С�
static int (WINAPI* OldWSASend)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSASend;

extern "C" __declspec(dllexport) int WINAPI NewWSASend(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	sendInfo.argNum = 7;
	sendInfo.type = WSASEND;
	GetLocalTime(&(sendInfo.st));

	strcpy_s(sendInfo.argName[0], "s");
	strcpy_s(sendInfo.argName[1], "lpBuffers");
	strcpy_s(sendInfo.argName[2], "dwBufferCount");
	strcpy_s(sendInfo.argName[3], "lpNumberOfBytesSent");
	strcpy_s(sendInfo.argName[4], "dwFlags");
	strcpy_s(sendInfo.argName[5], "lpOverlapped");
	strcpy_s(sendInfo.argName[6], "lpCompletionRoutine");

	sprintf_s(sendInfo.argValue[0], "%08X", s);
	if (lpBuffers && dwBufferCount > 0 && lpBuffers[0].buf && lpBuffers[0].len > 0) {
		strncpy_s(sendInfo.argValue[1], lpBuffers[0].buf, min(lpBuffers[0].len, 255));
		sendInfo.argValue[1][min(lpBuffers[0].len, 255)] = '\0';
	}
	else {
		strcpy_s(sendInfo.argValue[1], "(null)");
	}
	sprintf_s(sendInfo.argValue[2], "%d", dwBufferCount);
	sprintf_s(sendInfo.argValue[3], "%08X", lpNumberOfBytesSent ? lpNumberOfBytesSent : 0);
	sprintf_s(sendInfo.argValue[4], "%08X", dwFlags);
	sprintf_s(sendInfo.argValue[5], "%08X", lpOverlapped ? lpOverlapped : 0);
	sprintf_s(sendInfo.argValue[6], "%08X", lpCompletionRoutine ? lpCompletionRoutine : 0);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}


//��������recv
static int (WINAPI* OldRecv)(SOCKET s, char* buf, int len, int flags) = recv;

extern "C" __declspec(dllexport) int WINAPI NewRecv(SOCKET s, char* buf, int len, int flags)
{
	sendInfo.type = RECV;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "Socket");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Buffer");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "Length");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "Flags");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (unsigned int)s);
	// ֻ��¼bufǰ�沿��������ʾ������ֹ����
	if (buf && len > 0) {
		int copyLen = min(len, 64);
		char tmpBuf[65] = { 0 };
		memcpy(tmpBuf, buf, copyLen);
		tmpBuf[copyLen] = '\0';
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), tmpBuf, _TRUNCATE);
	}
	else {
		strcpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)");
	}
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%d", len);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", flags);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldRecv(s, buf, len, flags);
}

//recvfrom
static int (WINAPI* OldRecvFrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) = recvfrom;

extern "C" __declspec(dllexport) int WINAPI NewRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
	sendInfo.type = RECVFROM;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "Socket");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Buffer");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "Length");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "Flags");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "From");
	sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "FromLen");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (unsigned int)s);

	if (buf && len > 0) {
		int copyLen = min(len, 64);
		char tmpBuf[65] = { 0 };
		memcpy(tmpBuf, buf, copyLen);
		tmpBuf[copyLen] = '\0';
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), tmpBuf, _TRUNCATE);
	}
	else {
		strcpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)");
	}

	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%d", len);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", flags);

	// ��ӡ from ��ַ��IPv4 ʾ����
	if (from && fromlen && *fromlen >= sizeof(sockaddr_in)) {
		sockaddr_in* addr_in = (sockaddr_in*)from;
		char ip[16] = { 0 };
		sprintf_s(ip, sizeof(ip), "%d.%d.%d.%d",
			addr_in->sin_addr.S_un.S_un_b.s_b1,
			addr_in->sin_addr.S_un.S_un_b.s_b2,
			addr_in->sin_addr.S_un.S_un_b.s_b3,
			addr_in->sin_addr.S_un.S_un_b.s_b4);
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%s:%d", ip, ntohs(addr_in->sin_port));
	}
	else {
		strcpy_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "(null)");
	}

	if (fromlen) {
		sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "%d", *fromlen);
	}
	else {
		strcpy_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "(null)");
	}

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldRecvFrom(s, buf, len, flags, from, fromlen);
}

//WSARecv
static int (WINAPI* OldWSARecv)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSARecv;

extern "C" __declspec(dllexport) int WINAPI NewWSARecv(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	sendInfo.type = WSARECV;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 5;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "Socket");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Buffers");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "BufferCount");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "Flags");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "Overlapped");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (unsigned int)s);

	// �򵥴�ӡ��һ��������������
	if (lpBuffers && dwBufferCount > 0 && lpBuffers[0].buf && lpBuffers[0].len > 0) {
		int copyLen = min(lpBuffers[0].len, 64);
		char tmpBuf[65] = { 0 };
		memcpy(tmpBuf, lpBuffers[0].buf, copyLen);
		tmpBuf[copyLen] = '\0';
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), tmpBuf, _TRUNCATE);
	}
	else {
		strcpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)");
	}

	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%d", dwBufferCount);
	if (lpFlags) {
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", *lpFlags);
	}
	else {
		strcpy_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "(null)");
	}

	sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%08X", (unsigned int)lpOverlapped);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

//connect(����ͨ��һ��δ���ӵ��׽��֣�SOCK_STREAM���� TCP�����ӵ�ָ����ַ��ͨ�����ڽ��� TCP ���ӡ�
static int (WINAPI* OldConnect)(
	SOCKET s,
	const struct sockaddr* name,
	int namelen
	) = connect;

extern "C" __declspec(dllexport) int WINAPI NewConnect(
	SOCKET s,
	const struct sockaddr* name,
	int namelen
)

{
	sendInfo.argNum = 3;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "s");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "name");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "namelen");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", s);
	if (name && namelen >= sizeof(sockaddr_in)) {
		const sockaddr_in* addr = (const sockaddr_in*)name;
		sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%s:%d",
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	}
	else {
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);
	}
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%d", namelen);

	sendInfo.type = CONNECT;
	GetLocalTime(&sendInfo.st);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldConnect(s, name, namelen);
}

//WSAConnect(����ͨ��һ��δ���ӵ��׽��֣�SOCK_STREAM���� TCP�����ӵ�ָ����ַ��ͨ�����ڽ��� TCP ���ӡ�
static int (WINAPI* OldWSAConnect)(
	SOCKET s,
	const struct sockaddr* name,
	int namelen,
	LPWSABUF lpCallerData,
	LPWSABUF lpCalleeData,
	LPQOS lpSQOS,
	LPQOS lpGQOS
	) = WSAConnect;

extern "C" __declspec(dllexport) int WINAPI NewWSAConnect(
	SOCKET s,
	const struct sockaddr* name,
	int namelen,
	LPWSABUF lpCallerData,
	LPWSABUF lpCalleeData,
	LPQOS lpSQOS,
	LPQOS lpGQOS
)

{
	sendInfo.argNum = 7;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "s");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "name");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "namelen");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpCallerData");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "lpCalleeData");
	sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "lpSQOS");
	sprintf_s(sendInfo.argName[6], sizeof(sendInfo.argName[6]), "lpGQOS");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", s);
	if (name && namelen >= sizeof(sockaddr_in)) {
		const sockaddr_in* addr = (const sockaddr_in*)name;
		sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%s:%d",
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	}
	else {
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);
	}
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%d", namelen);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", lpCallerData);
	sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%08X", lpCalleeData);
	sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "%08X", lpSQOS);
	sprintf_s(sendInfo.argValue[6], sizeof(sendInfo.argValue[6]), "%08X", lpGQOS);

	sendInfo.type = WSACONNECT;
	GetLocalTime(&sendInfo.st);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

//IPv4 ������������ API
static struct hostent* (WINAPI* Old_gethostbyname)(const char* name) = gethostbyname;

extern "C" __declspec(dllexport)
struct hostent* WINAPI New_gethostbyname(const char* name)
{
	sendInfo.type = GETHOSTBYNAME;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;

	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "name");
	if (name)
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), name, _TRUNCATE);
	else
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return Old_gethostbyname(name);
}

//IPv4/IPv6 ͳһ�����ӿ�
static int (WINAPI* Old_getaddrinfo)(
	PCSTR pNodeName,
	PCSTR pServiceName,
	const ADDRINFOA* pHints,
	PADDRINFOA* ppResult
	) = getaddrinfo;

extern "C" __declspec(dllexport)
int WINAPI New_getaddrinfo(
	PCSTR pNodeName,
	PCSTR pServiceName,
	const ADDRINFOA * pHints,
	PADDRINFOA * ppResult
)
{
	sendInfo.type = GETADDRINFO;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;

	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "pNodeName");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "pServiceName");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "pHints");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "ppResult");

	if (pNodeName)
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), pNodeName, _TRUNCATE);
	else
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);

	if (pServiceName)
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), pServiceName, _TRUNCATE);
	else
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);

	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", pHints);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%p", ppResult);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return Old_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}


// ����socket
static SOCKET(WINAPI* OldSocket)(
	int af,
	int type,
	int protocol
	) = socket;

extern "C" __declspec(dllexport) SOCKET WINAPI NewSocket(
	int af,
	int type,
	int protocol
) {
	sendInfo.argNum = 3;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "af");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "type");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "protocol");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", af);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", type);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", protocol);

	sendInfo.type = SOCKETCREATE;
	GetLocalTime(&(sendInfo.st));

	memcpy(lpBase, &sendInfo, sizeof(info));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldSocket(af, type, protocol);
}

// �ر�socket
static int (WINAPI* OldCloseSocket)(SOCKET s) = closesocket;

// Hook ����ʵ��
extern "C" __declspec(dllexport) int WINAPI NewCloseSocket(SOCKET s) {
	sendInfo.argNum = 1;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "s");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", s);

	sendInfo.type = SOCKETCLOSE;
	GetLocalTime(&(sendInfo.st));

	memcpy(lpBase, &sendInfo, sizeof(info));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldCloseSocket(s);
}

/*
* ------------------------------------------------------------------------------------------------------
  ----------------------------------------------- ����ͮ -------------------------------------------------
  ------------------------------------------------------------------------------------------------------
*/

// ԭʼ����
static BOOL(WINAPI* OldCreateProcessW)(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
	) = CreateProcessW;

// ����Hook����
extern "C" __declspec(dllexport) BOOL WINAPI NewCreateProcessW(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation)
{
	char temp[256] = { 0 };

	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = CREATEPROCESSW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 10;

	// ������
	const char* paramNames[] = {
		"lpApplicationName", "lpCommandLine", "lpProcessAttributes",
		"lpThreadAttributes", "bInheritHandles", "dwCreationFlags",
		"lpEnvironment", "lpCurrentDirectory", "lpStartupInfo",
		"lpProcessInformation"
	};
	for (int i = 0; i < 10; i++) {
		strcpy(sendInfo.argName[i], paramNames[i]);
	}

	// ����ֵ����
	//  lpApplicationName
	if (lpApplicationName) {
		WideCharToMultiByte(CP_ACP, 0, lpApplicationName, -1, temp, sizeof(temp), NULL, NULL);
		strcpy(sendInfo.argValue[0], temp);
	}
	else {
		strcpy(sendInfo.argValue[0], "NULL");
	}

	// lpCommandLine 
	if (lpCommandLine) {
		WideCharToMultiByte(CP_ACP, 0, lpCommandLine, -1, temp, sizeof(temp), NULL, NULL);
		strcpy(sendInfo.argValue[1], temp);
	}
	else {
		strcpy(sendInfo.argValue[1], "NULL");
	}

	sprintf(sendInfo.argValue[2], "%p", lpProcessAttributes);
	sprintf(sendInfo.argValue[3], "%p", lpThreadAttributes);
	sprintf(sendInfo.argValue[4], "%d", bInheritHandles);
	sprintf(sendInfo.argValue[5], "%08X", dwCreationFlags);
	sprintf(sendInfo.argValue[6], "%p", lpEnvironment);
	if (lpCurrentDirectory) {
		WideCharToMultiByte(CP_ACP, 0, lpCurrentDirectory, -1, temp, sizeof(temp), NULL, NULL);
		strcpy(sendInfo.argValue[7], temp);
	}
	else {
		strcpy(sendInfo.argValue[7], "NULL");
	}

	sprintf(sendInfo.argValue[8], "%p", lpStartupInfo);
	sprintf(sendInfo.argValue[9], "%p", lpProcessInformation);

	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// ����ԭʼ����
	return OldCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
		lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment, lpCurrentDirectory, lpStartupInfo,
		lpProcessInformation);
}

// ԭʼ����
static BOOL(WINAPI* OldCreateProcessA)(
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
	) = CreateProcessA;

// Hook����
extern "C" __declspec(dllexport) BOOL WINAPI NewCreateProcessA(
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation)
{
	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(sendInfo));
	sendInfo.type = CREATEPROCESSA;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 10;

	// ������
	const char* paramNames[] = {
		"lpApplicationName", "lpCommandLine", "lpProcessAttributes",
		"lpThreadAttributes", "bInheritHandles", "dwCreationFlags",
		"lpEnvironment", "lpCurrentDirectory", "lpStartupInfo",
		"lpProcessInformation"
	};

	for (int i = 0; i < 10; i++) {
		strcpy_s(sendInfo.argName[i], sizeof(sendInfo.argName[i]), paramNames[i]);
	}

	// ����ֵ����
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%.255s",
		lpApplicationName ? lpApplicationName : "NULL");

	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%.255s",
		lpCommandLine ? lpCommandLine : "NULL");

	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", lpProcessAttributes);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%p", lpThreadAttributes);
	sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%d", bInheritHandles);
	sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "%08X", dwCreationFlags);

	if (lpEnvironment) {
		char hexBuf[512] = { 0 };
		size_t envLen = min(128, (int)strlen((char*)lpEnvironment));
		for (size_t i = 0; i < envLen; i++) {
			char temp[10];
			sprintf_s(temp, sizeof(temp), "%02X ", ((BYTE*)lpEnvironment)[i]);
			strcat_s(hexBuf, sizeof(hexBuf), temp);
		}
		sprintf_s(sendInfo.argValue[6], sizeof(sendInfo.argValue[6]),
			"EnvData[%p]: %s", lpEnvironment, hexBuf);
	}
	else {
		strcpy_s(sendInfo.argValue[6], sizeof(sendInfo.argValue[6]), "NULL");
	}

	sprintf_s(sendInfo.argValue[7], sizeof(sendInfo.argValue[7]), "%.260s",
		lpCurrentDirectory ? lpCurrentDirectory : "NULL");

	if (lpStartupInfo) {
		sprintf_s(sendInfo.argValue[8], sizeof(sendInfo.argValue[8]),
			"StartupInfo{Title=%.50s, Desktop=%.50s, Flags=%X}",
			lpStartupInfo->lpTitle ? lpStartupInfo->lpTitle : "NULL",
			lpStartupInfo->lpDesktop ? lpStartupInfo->lpDesktop : "NULL",
			lpStartupInfo->dwFlags);
	}
	else {
		strcpy_s(sendInfo.argValue[8], sizeof(sendInfo.argValue[8]), "NULL");
	}

	if (lpProcessInformation) {
		sprintf_s(sendInfo.argValue[9], sizeof(sendInfo.argValue[9]),
			"ProcessInfo{ hProcess=%p, hThread=%p }",
			lpProcessInformation->hProcess, lpProcessInformation->hThread);
	}
	else {
		strcpy_s(sendInfo.argValue[9], sizeof(sendInfo.argValue[9]), "NULL");
	}

	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(sendInfo));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	sendInfo.argNum = 0;  // �����������

	return OldCreateProcessA(
		lpApplicationName, lpCommandLine, lpProcessAttributes,
		lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment, lpCurrentDirectory, lpStartupInfo,
		lpProcessInformation);
}


// ԭʼ����
static HINSTANCE(WINAPI* OldShellExecuteW)(
	_In_opt_ HWND hwnd,
	_In_opt_ LPCWSTR lpOperation,
	_In_ LPCWSTR lpFile,
	_In_opt_ LPCWSTR lpParameters,
	_In_opt_ LPCWSTR lpDirectory,
	_In_ INT nShowCmd
	) = ShellExecuteW;

// Hook����
extern "C" __declspec(dllexport) HINSTANCE WINAPI NewShellExecuteW(
	_In_opt_ HWND hwnd,
	_In_opt_ LPCWSTR lpOperation,
	_In_ LPCWSTR lpFile,
	_In_opt_ LPCWSTR lpParameters,
	_In_opt_ LPCWSTR lpDirectory,
	_In_ INT nShowCmd)
{
	char temp[256] = { 0 };

	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = SHELLEXECUTEW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;

	// ������
	const char* paramNames[] = {
		"hwnd", "lpOperation", "lpFile",
		"lpParameters", "lpDirectory", "nShowCmd"
	};
	for (int i = 0; i < 6; i++) {
		strcpy_s(sendInfo.argName[i], paramNames[i]);
	}
	sprintf(sendInfo.argValue[0], "%p", hwnd);
	if (lpOperation) {
		WideCharToMultiByte(CP_ACP, 0, lpOperation, -1, temp, sizeof(temp), NULL, NULL);
		sprintf(sendInfo.argValue[1], "%.100s", temp);
	}
	else {
		strcpy(sendInfo.argValue[1], "NULL");
	}
	WideCharToMultiByte(CP_ACP, 0, lpFile, -1, temp, sizeof(temp), NULL, NULL);
	sprintf(sendInfo.argValue[2], "%.200s", temp);
	if (lpParameters) {
		WideCharToMultiByte(CP_ACP, 0, lpParameters, -1, temp, sizeof(temp), NULL, NULL);
		sprintf(sendInfo.argValue[3], "%.200s", temp);
	}
	else {
		strcpy(sendInfo.argValue[3], "NULL");
	}

	if (lpDirectory) {
		WideCharToMultiByte(CP_ACP, 0, lpDirectory, -1, temp, sizeof(temp), NULL, NULL);
		sprintf(sendInfo.argValue[4], "%.260s", temp);
	}
	else {
		strcpy(sendInfo.argValue[4], "NULL");
	}
	const char* showCmdStr = "UNKNOWN";
	switch (nShowCmd) {
	case SW_HIDE: showCmdStr = "HIDE"; break;
	case SW_SHOW: showCmdStr = "SHOW"; break;
	default: sprintf_s(temp, "%d", nShowCmd); showCmdStr = temp;
	}
	sprintf(sendInfo.argValue[5], "%s", showCmdStr);

	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	return OldShellExecuteW(hwnd, lpOperation, lpFile,
		lpParameters, lpDirectory, nShowCmd);
}

// ԭʼ����
static HANDLE(WINAPI* OldCreateThread)(
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	) = CreateThread;

// Hook����
extern "C" __declspec(dllexport) HANDLE WINAPI NewCreateThread(
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId)
{
	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = CREATETHREAD;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;

	// ������
	const char* paramNames[] = {
		"lpThreadAttributes", "dwStackSize", "lpStartAddress",
		"lpParameter", "dwCreationFlags", "lpThreadId"
	};
	for (int i = 0; i < 6; i++) {
		strcpy(sendInfo.argName[i], paramNames[i]);
	}
	sprintf(sendInfo.argValue[0], "%p", lpThreadAttributes);
	sprintf(sendInfo.argValue[1], "%zu", dwStackSize);
	sprintf(sendInfo.argValue[2], "%p", lpStartAddress);
	sprintf(sendInfo.argValue[3], "%p", lpParameter);
	char flagsStr[100] = { 0 };
	if (dwCreationFlags & CREATE_SUSPENDED) strcat(flagsStr, "SUSPENDED|");
	if (dwCreationFlags & STACK_SIZE_PARAM_IS_A_RESERVATION) strcat(flagsStr, "STACK_RESERVE|");
	if (strlen(flagsStr) > 0) {
		flagsStr[strlen(flagsStr) - 1] == '\0';
	}
	
	sprintf(sendInfo.argValue[4], "%08X (%s)", dwCreationFlags, strlen(flagsStr) ? flagsStr : "DEFAULT");
	sprintf(sendInfo.argValue[5], "%p", lpThreadId);
	DWORD callerPid = GetCurrentProcessId();
	DWORD callerTid = GetCurrentThreadId();
	sprintf(sendInfo.argValue[6], "CallerPID:%d/TID:%d", callerPid, callerTid);
	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// ����ԭʼ����
	HANDLE hThread = OldCreateThread(
		lpThreadAttributes, dwStackSize, lpStartAddress,
		lpParameter, dwCreationFlags, lpThreadId);

	// ��¼ʵ�ʴ������߳�ID
	if (hThread && lpThreadId) {
		char extraInfo[50] = { 0 };
		sprintf_s(extraInfo, "ActualTID:%d", *lpThreadId);
		strcat_s(sendInfo.argValue[6], extraInfo);
		memcpy(lpBase, &sendInfo, sizeof(info));
	}

	return hThread;
}

// ԭʼ����
static VOID(WINAPI* OldExitThread)(_In_ DWORD dwExitCode) = ExitThread;

// Hook����
extern "C" __declspec(dllexport) VOID WINAPI NewExitThread(_In_ DWORD dwExitCode)
{
	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = EXITTHREAD;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 2;
	strcpy(sendInfo.argName[0], "dwExitCode");
	strcpy(sendInfo.argName[1], "CallerInfo");
	sprintf(sendInfo.argValue[0], "%08X", dwExitCode);
	DWORD tid = GetCurrentThreadId();
	DWORD pid = GetCurrentProcessId();
	sprintf(sendInfo.argValue[1], "PID:%d/TID:%d", pid, tid);

	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	// ����ԭʼ����
	OldExitThread(dwExitCode);

}


// ԭʼ����
static HMODULE(WINAPI* OldLoadLibraryW)(_In_ LPCWSTR lpLibFileName) = LoadLibraryW;

// Hook����
extern "C" __declspec(dllexport) HMODULE WINAPI NewLoadLibraryW(_In_ LPCWSTR lpLibFileName)
{
	char temp[MAX_PATH] = { 0 };

	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = LOADLIBRARYW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 3;

	// ������
	strcpy(sendInfo.argName[0], "lpLibFileName");
	strcpy(sendInfo.argName[1], "CallerPID");
	strcpy(sendInfo.argName[2], "CallerTID");

	// ����ֵ����
	if (lpLibFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpLibFileName, -1, temp, sizeof(temp), NULL, NULL);
		// ��ȡ���ļ�����ȥ��·����
		char* fileName = strrchr(temp, '\\');
		fileName = fileName ? fileName + 1 : temp;
		sprintf(sendInfo.argValue[0], "%s", fileName);
	}
	else {
		strcpy(sendInfo.argValue[0], "NULL");
	}

	// ��������Ϣ
	sprintf(sendInfo.argValue[1], "%d", GetCurrentProcessId());
	sprintf(sendInfo.argValue[2], "%d", GetCurrentThreadId());

	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// ����ԭʼ����
	HMODULE hModule = OldLoadLibraryW(lpLibFileName);

	// ��¼���ؽ��
	if (hModule) {
		char modInfo[50] = { 0 };
		sprintf(modInfo, "BaseAddr:%p", hModule);
		strcat(sendInfo.argValue[0], modInfo);
		memcpy(lpBase, &sendInfo, sizeof(info)); // ������Ϣ
	}

	return hModule;
}

// ԭʼ����
static HMODULE(WINAPI* OldLoadLibraryExW)(
	_In_ LPCWSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags
	) = LoadLibraryExW;

// Hook������
extern "C" __declspec(dllexport) HMODULE WINAPI NewLoadLibraryExW(
	_In_ LPCWSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags)
{
	char temp[MAX_PATH] = { 0 };
	char flagsStr[100] = { 0 };

	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = LOADLIBRARYEXW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 5;  // ����+��������Ϣ

	// ������
	strcpy(sendInfo.argName[0], "lpLibFileName");
	strcpy(sendInfo.argName[1], "dwFlags");
	strcpy(sendInfo.argName[2], "hFile");
	strcpy(sendInfo.argName[3], "CallerPID");
	strcpy(sendInfo.argName[4], "CallerTID");

	// ����ֵ����
	if (lpLibFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpLibFileName, -1, temp, sizeof(temp), NULL, NULL);
		sprintf_s(sendInfo.argValue[0], "%s", temp);
	}
	else {
		strcpy(sendInfo.argValue[0], "NULL");
	}

	// ������־λ
	if (dwFlags & DONT_RESOLVE_DLL_REFERENCES) strcat_s(flagsStr, "NO_RESOLVE|");
	if (dwFlags & LOAD_LIBRARY_AS_DATAFILE) strcat_s(flagsStr, "AS_DATAFILE|");
	if (strlen(flagsStr) > 0) {
		flagsStr[strlen(flagsStr) - 1] = '\0';
	}
	sprintf(sendInfo.argValue[1], "0x%08X (%s)", dwFlags,
			strlen(flagsStr) ? flagsStr : "DEFAULT");

	sprintf(sendInfo.argValue[2], "%p", hFile);
	sprintf(sendInfo.argValue[3], "%d", GetCurrentProcessId());
	sprintf(sendInfo.argValue[4], "%d", GetCurrentThreadId());

	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// ����ԭʼ����
	return OldLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

// ԭʼ����ָ������
static FARPROC(WINAPI* OldGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	) = GetProcAddress;

// Hook����
extern "C" __declspec(dllexport) FARPROC WINAPI NewGetProcAddress(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName)
{
	char modName[MAX_PATH] = { 0 };

	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = GETPROCADDRESS;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;

	// ������
	strcpy(sendInfo.argName[0], "hModule");
	strcpy(sendInfo.argName[1], "lpProcName");
	strcpy(sendInfo.argName[2], "CallerPID");
	strcpy(sendInfo.argName[3], "CallerTID");

	// ����ֵ����
	sprintf(sendInfo.argValue[0], "%p", hModule);

	// ��ȡģ���ļ���
	if (hModule && GetModuleFileNameA(hModule, modName, MAX_PATH)) {
		char* fileName = strrchr(modName, '\\');
		fileName = fileName ? fileName + 1 : modName;
		sprintf(sendInfo.argValue[0], "%p (%s)", hModule, fileName);
	}

	// ������������������ţ�
	if (IS_INTRESOURCE(lpProcName)) {
		sprintf(sendInfo.argValue[1], "#%d", (DWORD)lpProcName);
	}
	else {
		sprintf(sendInfo.argValue[1], "%s", lpProcName ? lpProcName : "NULL");
	}

	// ��������Ϣ
	sprintf(sendInfo.argValue[2], "%d", GetCurrentProcessId());
	sprintf(sendInfo.argValue[3], "%d", GetCurrentThreadId());

	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// ����ԭʼ����
	FARPROC proc = OldGetProcAddress(hModule, lpProcName);

	// ��ѡ����¼��ȡ���
	if (proc) {
		char procInfo[50] = { 0 };
		sprintf(procInfo, "->%p", proc);
		strcat(sendInfo.argValue[1], procInfo);
		memcpy(lpBase, &sendInfo, sizeof(info)); // ������Ϣ
	}

	return proc;
}

// ԭʼ����
static LPVOID(WINAPI* OldVirtualAllocEx)(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	) = VirtualAllocEx;

// �������Խ�������
const char* GetMemoryProtectionString(DWORD protect) {
	static char buffer[128];
	ZeroMemory(buffer, sizeof(buffer));

	// ������������
	switch (protect & 0xFF) {
	case PAGE_NOACCESS:
		strcpy_s(buffer, "NOACCESS");
		break;
	case PAGE_READONLY:
		strcpy_s(buffer, "READONLY");
		break;
	case PAGE_READWRITE:
		strcpy_s(buffer, "READWRITE");
		break;
	case PAGE_WRITECOPY:
		strcpy_s(buffer, "WRITECOPY");
		break;
	case PAGE_EXECUTE:
		strcpy_s(buffer, "EXECUTE");
		break;
	case PAGE_EXECUTE_READ:
		strcpy_s(buffer, "EXECUTE_READ");
		break;
	case PAGE_EXECUTE_READWRITE:
		strcpy_s(buffer, "EXECUTE_READWRITE");
		break;
	case PAGE_EXECUTE_WRITECOPY:
		strcpy_s(buffer, "EXECUTE_WRITECOPY");
		break;
	default:
		sprintf_s(buffer, "UNKNOWN(0x%02X)", protect & 0xFF);
	}

	// ��������
	if (protect & PAGE_GUARD)
		strcat_s(buffer, " | GUARD");
	if (protect & PAGE_NOCACHE)
		strcat_s(buffer, " | NOCACHE");
	if (protect & PAGE_WRITECOMBINE)
		strcat_s(buffer, " | WRITECOMBINE");

	return buffer;
}

// Hook����
extern "C" __declspec(dllexport) LPVOID WINAPI NewVirtualAllocEx(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect)
{
	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = VIRTUALALLOCEX;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;  // 5����+��������Ϣ

	// ������
	const char* paramNames[] = {
		"hProcess", "lpAddress", "dwSize",
		"flAllocationType", "flProtect", "CallerInfo"
	};
	for (int i = 0; i < 6; i++) {
		strcpy(sendInfo.argName[i], paramNames[i]);
	}

	// ����ֵ����
	DWORD targetPid = GetProcessId(hProcess);
	sprintf(sendInfo.argValue[0], "%p (PID:%d)", hProcess, targetPid);
	sprintf(sendInfo.argValue[1], "%p", lpAddress);
	sprintf(sendInfo.argValue[2], "%zu bytes", dwSize);

	// �����ڴ��������
	char allocType[128] = { 0 };
	if (flAllocationType & MEM_COMMIT) strcat(allocType, "COMMIT|");
	if (flAllocationType & MEM_RESERVE) strcat(allocType, "RESERVE|");
	if (flAllocationType & MEM_RESET) strcat(allocType, "RESET|");
	if (flAllocationType & MEM_RESET_UNDO) strcat(allocType, "RESET_UNDO|");
	if (flAllocationType & MEM_LARGE_PAGES) strcat(allocType, "LARGE_PAGES|");
	if (flAllocationType & MEM_PHYSICAL) strcat(allocType, "PHYSICAL|");
	if (flAllocationType & MEM_TOP_DOWN) strcat(allocType, "TOP_DOWN|");

	if (strlen(allocType) > 0) {
		allocType[strlen(allocType) - 1] = '\0'; // �Ƴ�ĩβ��|
	}
	else {
		strcpy(allocType, "DEFAULT");
	}
	sprintf(sendInfo.argValue[3], "0x%08X (%s)", flAllocationType, allocType);
	// �����������Խ���
	sprintf(sendInfo.argValue[4], "0x%08X (%s)", flProtect, GetMemoryProtectionString(flProtect));
	// ��������Ϣ
	sprintf(sendInfo.argValue[5], "CallerPID:%d", GetCurrentProcessId());
	// ���������
	if ((flProtect & PAGE_EXECUTE_READWRITE) ||
		(flProtect & PAGE_EXECUTE_WRITECOPY)) {
		strcat(sendInfo.argValue[4], " [EXECUTABLE]");
	}
	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	// ����ԭʼ����
	LPVOID result = OldVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	// ��¼������
	if (result) {
		char resultInfo[128] = { 0 };
		sprintf_s(resultInfo, "-> Allocated at %p", result);
		strcat_s(sendInfo.argValue[2], resultInfo);

		// ���¹����ڴ�
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(info));
		}
	}
	return result;
}

// ԭʼ����ָ������
static BOOL(WINAPI* OldWriteProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesWritten
	) = WriteProcessMemory;

// Hook����
extern "C" __declspec(dllexport) BOOL WINAPI NewWriteProcessMemory(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesWritten)
{
	// ��ʼ����־�ṹ��
	ZeroMemory(&sendInfo, sizeof(sendInfo));
	sendInfo.type = WRITEPROCESSMEMORY;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;  // 5����+��������Ϣ

	// ������
	const char* paramNames[] = {
		"hProcess", "lpBaseAddress", "nSize",
		"lpBuffer", "lpBytesWritten", "CallerInfo"
	};
	for (int i = 0; i < 6; i++) {
		strcpy_s(sendInfo.argName[i], sizeof(sendInfo.argName[i]), paramNames[i]);
	}

	// ����ֵ����
	DWORD targetPid = 0;
	if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE) {
		targetPid = GetProcessId(hProcess);
	}
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p (PID:%d)", hProcess, targetPid);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", lpBaseAddress);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%zu bytes", nSize);

	// �������ݴ������Ƽ�¼���ȣ�
	if (lpBuffer && nSize > 0) {
		char hexDump[512] = { 0 };
		size_t dumpLen = min(nSize, (SIZE_T)16);  // ֻ��¼ǰ16�ֽ�
		for (size_t i = 0; i < dumpLen; i++) {
			char temp[10];
			sprintf_s(temp, sizeof(temp), "%02X ", ((BYTE*)lpBuffer)[i]);
			strcat_s(hexDump, sizeof(hexDump), temp);
		}
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "[%s...] @%p", hexDump, lpBuffer);
	}
	else {
		strcpy_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "NULL");
	}

	sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%p", lpNumberOfBytesWritten);
	sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "CallerPID:%d", GetCurrentProcessId());

	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(sendInfo));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// ����ԭʼ����
	BOOL ret = OldWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

	// ��ѡ����¼ʵ��д���ֽ���
	if (ret && lpNumberOfBytesWritten) {
		char writeInfo[100] = { 0 };
		sprintf_s(writeInfo, sizeof(writeInfo), "-> ActualWrite:%zu", *lpNumberOfBytesWritten);
		strcat_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), writeInfo);

		// ���¹����ڴ��е���Ϣ
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(sendInfo));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}
	}

	return ret;
}

// ԭʼ����
static HANDLE(WINAPI* OldCreateRemoteThread)(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	) = CreateRemoteThread;

// Hook����
extern "C" __declspec(dllexport) HANDLE WINAPI NewCreateRemoteThread(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId)
{
	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = CREATEREMOTETHREAD;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 8;

	// ������
	const char* paramNames[] = {
		"hProcess", "lpThreadAttributes", "dwStackSize",
		"lpStartAddress", "lpParameter", "dwCreationFlags",
		"lpThreadId", "CallerInfo"
	};
	for (int i = 0; i < 8; i++) {
		strcpy(sendInfo.argName[i], paramNames[i]);
	}

	// ����ֵ����
	DWORD targetPid = GetProcessId(hProcess);
	sprintf(sendInfo.argValue[0], "%p (PID:%d)", hProcess, targetPid);
	sprintf(sendInfo.argValue[1], "%p", lpThreadAttributes);
	sprintf(sendInfo.argValue[2], "%zu", dwStackSize);
	sprintf(sendInfo.argValue[3], "%p", lpStartAddress);
	sprintf(sendInfo.argValue[4], "%p", lpParameter);

	// �����̱߳�־
	char flagsStr[50] = { 0 };
	if (dwCreationFlags & CREATE_SUSPENDED) strcat_s(flagsStr, "SUSPENDED|");
	if (strlen(flagsStr)) flagsStr[strlen(flagsStr) - 1] = '\0';
	sprintf(sendInfo.argValue[5], "0x%08X (%s)", dwCreationFlags, flagsStr);

	sprintf(sendInfo.argValue[6], "%p", lpThreadId);
	sprintf(sendInfo.argValue[7], "CallerPID:%d", GetCurrentProcessId());

	// д�빲���ڴ棨ע����Ϊ�������澯��
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	// ����ԭʼ����
	HANDLE hThread = OldCreateRemoteThread(
		hProcess, lpThreadAttributes, dwStackSize,
		lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	// ��¼ʵ���߳�ID
	if (hThread && lpThreadId) {
		char threadInfo[50] = { 0 };
		sprintf(threadInfo, "-> RemoteTID:%d", *lpThreadId);
		strcat(sendInfo.argValue[6], threadInfo);
		memcpy(lpBase, &sendInfo, sizeof(info)); // ������Ϣ
	}

	return hThread;
}

// ������Ҫhook�ĺ���
static int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxA;
// ������Ҫ�滻���µĺ���
extern "C" __declspec(dllexport) int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
	sendInfo.type = MESSAGEBOXA;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;
	//������
	sprintf(sendInfo.argName[0], "hWnd");//��������Ϊ����������������������������Ԫ�صĵ�ַ �������char*
	sprintf(sendInfo.argName[1], "lpText");
	sprintf(sendInfo.argName[2], "lpCaption");
	sprintf(sendInfo.argName[3], "uType");
	//����ֵ
	sprintf(sendInfo.argValue[0], "%08X", hWnd);
	sprintf(sendInfo.argValue[1], "%s", lpText);
	sprintf(sendInfo.argValue[2], "%s", lpCaption);
	sprintf(sendInfo.argValue[3], "%08X", uType);

	// ��sendinfo��ֵ�������ڴ�
	memcpy(lpBase, &sendInfo, sizeof(info));
	// ����V������ʹ���ź���+1
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	// ����ԭʼ�ӿ�
	return OldMessageBoxA(hWnd, lpText, lpCaption, uType);
}

static int (WINAPI* OldMessageBoxW)(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType) = MessageBoxW;
extern "C" __declspec(dllexport) int WINAPI NewMessageBoxW(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType)
{
	char temp[70];
	sendInfo.type = MESSAGEBOXW;
	GetLocalTime(&(sendInfo.st));

	sendInfo.argNum = 4;
	// ������
	sprintf(sendInfo.argName[0], "hWnd");
	sprintf(sendInfo.argName[1], "lpText");
	sprintf(sendInfo.argName[2], "lpCaption");
	sprintf(sendInfo.argName[3], "uType");
	// ����ֵ
	sprintf(sendInfo.argValue[0], "%08X", hWnd);

	// lpText: ���ֽ�ת ANSI���� NULL ���
	memset(temp, 0, sizeof(temp));
	if (lpText) {
		WideCharToMultiByte(CP_ACP, 0, lpText, sizeof(lpText), temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);
	}

	// lpCaption: ���ֽ�ת ANSI���� NULL ���
	memset(temp, 0, sizeof(temp));
	if (lpCaption) {
		WideCharToMultiByte(CP_ACP, 0, lpCaption, sizeof(lpCaption), temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "(null)", _TRUNCATE);
	}

	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", uType);


	sendInfo.argNum = 0;
	return OldMessageBoxW(hWnd, lpText, lpCaption, uType);
}

// ԭʼ����
static HWND(WINAPI* OldCreateWindowExW)(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCWSTR lpClassName,
	_In_opt_ LPCWSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam
	) = CreateWindowExW;

// Hook����
extern "C" __declspec(dllexport) HWND WINAPI NewCreateWindowExW(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCWSTR lpClassName,
	_In_opt_ LPCWSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam)
{
	char temp[256] = { 0 };
	char styleStr[256] = { 0 };

	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = CREATEWINDOWEXW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 13;

	// ������
	const char* paramNames[] = {
		"dwExStyle", "lpClassName", "lpWindowName", "dwStyle",
		"X", "Y", "nWidth", "nHeight", "hWndParent",
		"hMenu", "hInstance", "lpParam", "CallerInfo"
	};
	for (int i = 0; i < 13; i++) {
		strcpy(sendInfo.argName[i], paramNames[i]);
	}
	sprintf(sendInfo.argValue[0], "0x%08X", dwExStyle);
	if (lpClassName) {
		if (IS_INTRESOURCE(lpClassName)) {
			sprintf(sendInfo.argValue[1], "#%d", (UINT_PTR)lpClassName);
		}
		else {
			WideCharToMultiByte(CP_ACP, 0, lpClassName, -1, temp, sizeof(temp), NULL, NULL);
			sprintf(sendInfo.argValue[1], "%s", temp);
		}
	}
	else {
		strcpy(sendInfo.argValue[1], "NULL");
	}
	if (lpWindowName) {
		WideCharToMultiByte(CP_ACP, 0, lpWindowName, -1, temp, sizeof(temp), NULL, NULL);
		sprintf(sendInfo.argValue[2], "%s", temp);
	}
	else {
		strcpy(sendInfo.argValue[2], "NULL");
	}
	if (dwStyle & WS_OVERLAPPEDWINDOW) strcat(styleStr, "OVERLAPPEDWINDOW|");
	if (dwStyle & WS_CHILD) strcat(styleStr, "CHILD|");
	if (dwStyle & WS_VISIBLE) strcat(styleStr, "VISIBLE|");
	if (dwStyle & WS_DISABLED) strcat(styleStr, "DISABLED|");
	if (strlen(styleStr)) styleStr[strlen(styleStr) - 1] = '\0';
	sprintf(sendInfo.argValue[3], "0x%08X (%s)", dwStyle, strlen(styleStr) ? styleStr : "DEFAULT");
	sprintf(sendInfo.argValue[4], "%d", X);
	sprintf(sendInfo.argValue[5], "%d", Y);
	sprintf(sendInfo.argValue[6], "%d", nWidth);
	sprintf(sendInfo.argValue[7], "%d", nHeight);
	sprintf(sendInfo.argValue[8], "%p", hWndParent);
	if (IS_INTRESOURCE(hMenu)) {
		sprintf(sendInfo.argValue[9], "#%d", (UINT_PTR)hMenu);
	}
	else {
		sprintf(sendInfo.argValue[9], "%p", hMenu);
	}
	sprintf(sendInfo.argValue[10], "%p", hInstance);
	sprintf(sendInfo.argValue[11], "%p", lpParam);
	sprintf(sendInfo.argValue[12], "PID:%d/TID:%d",
		GetCurrentProcessId(), GetCurrentThreadId());
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	HWND hWnd = OldCreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle,
		X, Y, nWidth, nHeight, hWndParent,
		hMenu, hInstance, lpParam);
	if (hWnd) {
		char hwndInfo[50] = { 0 };
		sprintf(hwndInfo, "-> HWND:%p", hWnd);
		strcat(sendInfo.argValue[12], hwndInfo);
		memcpy(lpBase, &sendInfo, sizeof(info));
	}

	return hWnd;
}

// ԭʼ����
static ATOM(WINAPI* OldRegisterClassW)(_In_ CONST WNDCLASSW* lpWndClass) = RegisterClassW;

// Hook����
extern "C" __declspec(dllexport) ATOM WINAPI NewRegisterClassW(_In_ CONST WNDCLASSW * lpWndClass)
{
	char temp[256] = { 0 };

	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = REGISTERCLASSW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 8; // ��Ҫ�ֶ�+��������Ϣ

	// ������
	const char* paramNames[] = {
		"style", "lpfnWndProc", "cbClsExtra", "cbWndExtra",
		"hInstance", "hIcon", "hCursor", "CallerInfo"
	};
	for (int i = 0; i < 8; i++) {
		strcpy(sendInfo.argName[i], paramNames[i]);
	}
	if (lpWndClass) {
		sprintf(sendInfo.argValue[0], "0x%04X", lpWndClass->style);
		sprintf(sendInfo.argValue[1], "%p", lpWndClass->lpfnWndProc);
		sprintf(sendInfo.argValue[2], "%d", lpWndClass->cbClsExtra);
		sprintf(sendInfo.argValue[3], "%d", lpWndClass->cbWndExtra);
		sprintf(sendInfo.argValue[4], "%p", lpWndClass->hInstance);
		sprintf(sendInfo.argValue[5], "%p", lpWndClass->hIcon);
		sprintf(sendInfo.argValue[6], "%p", lpWndClass->hCursor);
		sprintf(sendInfo.argValue[7], "PID:%d/TID:%d",
			GetCurrentProcessId(), GetCurrentThreadId());
		// ������¼
		if (!IS_INTRESOURCE(lpWndClass->lpszClassName)) {
			WideCharToMultiByte(CP_ACP, 0, lpWndClass->lpszClassName, -1, temp, sizeof(temp), NULL, NULL);
			strcat(sendInfo.argValue[7], " ClassName:");
			strcat(sendInfo.argValue[7], temp);
		}
	}
	else {
		strcpy(sendInfo.argValue[0], "NULL");
	}

	// д�빲���ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// ����ԭʼ����
	ATOM ret = OldRegisterClassW(lpWndClass);

	// ��¼���ص�ԭ��ֵ
	if (ret) {
		char atomInfo[30] = { 0 };
		sprintf(atomInfo, "-> ATOM:0x%04X", ret);
		strcat(sendInfo.argValue[7], atomInfo);
		memcpy(lpBase, &sendInfo, sizeof(info));
	}

	return ret;
}

// ԭʼ����
static LONG(WINAPI* OldSetWindowLongW)(
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
	) = SetWindowLongW;

// Hook����
extern "C" __declspec(dllexport) LONG_PTR WINAPI NewSetWindowLongW(
    _In_ HWND hWnd,
    _In_ int nIndex,
    _In_ LONG_PTR dwNewLong)
{
    char indexStr[50] = { 0 };

    // ��ʼ����־�ṹ��
    ZeroMemory(&sendInfo, sizeof(sendInfo));
    sendInfo.type = SETWINDOWLONGW;
    GetLocalTime(&(sendInfo.st));
    sendInfo.argNum = 4;

    // ������
    strcpy_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "hWnd");
    strcpy_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "nIndex");
    strcpy_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwNewLong");
    strcpy_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "CallerInfo");

    sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", hWnd);
	#define GWLP_EXSTYLE (-20)
	#define GWLP_STYLE (-16)
    switch (nIndex) {
        case GWLP_EXSTYLE: strcpy_s(indexStr, sizeof(indexStr), "GWLP_EXSTYLE"); break;
        case GWLP_STYLE: strcpy_s(indexStr, sizeof(indexStr), "GWLP_STYLE"); break;
        case GWLP_WNDPROC: strcpy_s(indexStr, sizeof(indexStr), "GWLP_WNDPROC"); break;
        case GWLP_HINSTANCE: strcpy_s(indexStr, sizeof(indexStr), "GWLP_HINSTANCE"); break;
        case GWLP_ID: strcpy_s(indexStr, sizeof(indexStr), "GWLP_ID"); break;
        case GWLP_USERDATA: strcpy_s(indexStr, sizeof(indexStr), "GWLP_USERDATA"); break;
        default:
            sprintf_s(indexStr, sizeof(indexStr), "%d", nIndex);
    }

    sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%s", indexStr);

    if (nIndex == GWLP_WNDPROC) {
        sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p (WNDPROC)", (void*)dwNewLong);
    }
    else {
        sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "0x%016llX", (unsigned long long)dwNewLong);
    }

    sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "PID:%d/TID:%d",
        GetCurrentProcessId(), GetCurrentThreadId());

    // д�빲���ڴ�
    if (lpBase) {
        memcpy(lpBase, &sendInfo, sizeof(sendInfo));
        ReleaseSemaphore(hSemaphore, 1, NULL);
    }

    // ����ԭʼ����
    LONG_PTR ret = OldSetWindowLongW(hWnd, nIndex, dwNewLong);

    // ��ѡ����¼ԭʼֵ
    if (ret != 0) {
        char retInfo[100] = { 0 };
        sprintf_s(retInfo, sizeof(retInfo), "-> OldValue:0x%016llX", (unsigned long long)ret);
        strcat_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), retInfo);

        if (lpBase) {
            memcpy(lpBase, &sendInfo, sizeof(sendInfo));
            ReleaseSemaphore(hSemaphore, 1, NULL);
        }
    }

    return ret;
}

// ԭʼ����
static BOOL(WINAPI* OldShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow) = ShowWindow;

// Hook����
extern "C" __declspec(dllexport) BOOL WINAPI NewShowWindow(
	_In_ HWND hWnd,
	_In_ int nCmdShow)
{
	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = SHOWWINDOW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 3;

	// ������
	strcpy(sendInfo.argName[0], "hWnd");
	strcpy(sendInfo.argName[1], "nCmdShow");
	strcpy(sendInfo.argName[2], "CallerInfo");
	sprintf(sendInfo.argValue[0], "%p", hWnd);
	const char* cmdStr = NULL;
	switch (nCmdShow) {
	case SW_HIDE: cmdStr = "SW_HIDE(0)"; break;               // ���ش���
	case SW_SHOWNORMAL: cmdStr = "SW_SHOWNORMAL(1)"; break;   // ������ʾ������
	//case SW_NORMAL: cmdStr = "SW_NORMAL(1)"; break;           // ͬSW_SHOWNORMAL
	case SW_SHOWMINIMIZED: cmdStr = "SW_SHOWMINIMIZED(2)"; break; // ��С��������
	case SW_SHOWMAXIMIZED: cmdStr = "SW_SHOWMAXIMIZED(3)"; break; // ��󻯲�����
	//case SW_MAXIMIZE: cmdStr = "SW_MAXIMIZE(3)"; break;       // ͬSW_SHOWMAXIMIZED
	case SW_SHOWNOACTIVATE: cmdStr = "SW_SHOWNOACTIVATE(4)"; break; // ��ʾ��������
	case SW_SHOW: cmdStr = "SW_SHOW(5)"; break;               // ����ʾ
	case SW_MINIMIZE: cmdStr = "SW_MINIMIZE(6)"; break;       // ��С����ʧ��
	case SW_SHOWMINNOACTIVE: cmdStr = "SW_SHOWMINNOACTIVE(7)"; break; // ͬSW_MINIMIZE
	case SW_SHOWNA: cmdStr = "SW_SHOWNA(8)"; break;           // ��ʾ��ǰ״̬
	case SW_RESTORE: cmdStr = "SW_RESTORE(9)"; break;         // �ָ�����
	case SW_SHOWDEFAULT: cmdStr = "SW_SHOWDEFAULT(10)"; break; // ��STARTUPINFO������ʾ
	case SW_FORCEMINIMIZE: cmdStr = "SW_FORCEMINIMIZE(11)"; break; // ǿ����С��
	default: {
		char unknownCmd[20];
		sprintf(unknownCmd, "UNKNOWN(0x%X)", nCmdShow);
		cmdStr = unknownCmd;
	}
	}
	sprintf(sendInfo.argValue[1], "%s", cmdStr);
	sprintf(sendInfo.argValue[2], "PID:%d/TID:%d",
		GetCurrentProcessId(), GetCurrentThreadId());
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	BOOL ret = OldShowWindow(hWnd, nCmdShow);

	// ��¼������ǰ״̬
	char stateInfo[50] = { 0 };
	const char* prevState = "UNKNOWN";
	switch (ret) {
	case 0: prevState = "HIDDEN"; break;
	case 1: prevState = "NORMAL"; break;
	case 2: prevState = "MINIMIZED"; break;
	case 3: prevState = "MAXIMIZED"; break;
	case 4: prevState = "NOACTIVATE"; break;
	case 5: prevState = "SHOW"; break;
	}
	sprintf(stateInfo, "-> PreviousState:%s(%d)", prevState, ret);
	strcat(sendInfo.argValue[2], stateInfo);

	// ���¹����ڴ�
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
	}

	return ret;
}

// ԭʼ����
static BOOL(WINAPI* OldDestroyWindow)(_In_ HWND hWnd) = DestroyWindow;

// Hook����
extern "C" __declspec(dllexport) BOOL WINAPI NewDestroyWindow(_In_ HWND hWnd)
{
	// ��¼������Ϣ
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = DESTROYWINDOW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 2;

	// ������
	strcpy(sendInfo.argName[0], "hWnd");
	strcpy(sendInfo.argName[1], "CallerInfo");
	sprintf(sendInfo.argValue[0], "%p", hWnd);
	sprintf(sendInfo.argValue[1], "PID:%d/TID:%d",
		GetCurrentProcessId(), GetCurrentThreadId());
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	BOOL ret = OldDestroyWindow(hWnd);

	// ��¼���
	if (!ret) {
		DWORD err = GetLastError();
		char errInfo[50] = { 0 };
		sprintf(errInfo, "-> Failed(Error:%d)", err);
		strcat(sendInfo.argValue[1], errInfo);
		memcpy(lpBase, &sendInfo, sizeof(info));
	}

	return ret;
}


/*
* ------------------------------------------------------------------------------------------------------
  ----------------------------------------------- Ҧ�Ĵ� -------------------------------------------------
  ------------------------------------------------------------------------------------------------------
*/

// ���ĳ���������»����ͷ�
static SHORT (WINAPI* OldGetAsyncKeyState)(int vKey) = GetAsyncKeyState;
extern "C" __declspec(dllexport) SHORT WINAPI NewGetAsyncKeyState(int vKey) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = GETASYNCKEYSTATE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;
	//������
	sprintf(sendInfo.argName[0], "vKey");
	//����ֵ
	sprintf(sendInfo.argValue[0], "%d", vKey);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	//sendInfo.argNum = 0;
	return OldGetAsyncKeyState(vKey);
}

// ��ȡָ���������״̬
static SHORT(WINAPI* OldGetKeyState)(int nVirtKey) = GetKeyState;
extern "C" __declspec(dllexport) SHORT WINAPI NewGetKeyState(int nVirtKey) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = GETKEYSTATE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;
	//������
	sprintf(sendInfo.argName[0], "nVirtKey");
	//����ֵ
	sprintf(sendInfo.argValue[0], "%d", nVirtKey);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	return OldGetKeyState(nVirtKey);
}

// ע��һ��ϵͳ��Χ���ȼ���ȫ�ֿ�ݼ���
static BOOL(WINAPI* OldRegisterHotKey)(HWND hWnd, int  id, UINT fsModifiers, UINT vk) = RegisterHotKey;
extern "C" __declspec(dllexport) BOOL WINAPI NewRegisterHotKey(HWND hWnd, int  id, UINT fsModifiers, UINT vk) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = REGISTERHOTKEY;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;
	//������
	sprintf(sendInfo.argName[0], "hWnd");
	sprintf(sendInfo.argName[1], "id");
	sprintf(sendInfo.argName[2], "fsModifiers");
	sprintf(sendInfo.argName[3], "vk");
	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", hWnd); // HWND ��ָ��
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%d", id);   // id �� int
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%u", fsModifiers); // UINT
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "0x%X", vk); // ���������ʮ��������ʾ������

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	//sendInfo.argNum = 0;

	// ����ԭʼ����
	return OldRegisterHotKey(hWnd, id, fsModifiers, vk);

}

//�ú������ڰ�װһ�����ӣ����������ز�����������͵������¼���������Ϣ��
static HHOOK(WINAPI* OldSetWindowsHookExA) (int idHook, HOOKPROC  lpfn, HINSTANCE hmod, DWORD dwThreadId) = SetWindowsHookExA;
extern "C" __declspec(dllexport) HHOOK WINAPI NewSetWindowsHookExA(int idHook, HOOKPROC  lpfn, HINSTANCE hmod, DWORD dwThreadId) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = SETWINDOWSHOOKEXA;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;
	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "idHook");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpfn");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "hmod");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "dwThreadId");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%d", idHook);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", lpfn);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", hmod);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%lu", dwThreadId);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	// ����ԭʼ����
	return OldSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
}

// ��ȡ���������
static BOOL(WINAPI* OldGetCursorPos)(LPPOINT) = GetCursorPos;
extern "C" __declspec(dllexport) BOOL WINAPI NewGetCursorPos(LPPOINT lpPoint) {
	// ��¼������Ϣ
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = GETCURSORPOS;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpPoint");

	// ����ֵ���ȼ�¼ԭʼ��ַ�����ú��ټ�¼ʵ������
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", lpPoint);

	// ����ԭʼ������ȡ���λ��
	BOOL result = OldGetCursorPos(lpPoint);

	if (result && lpPoint != NULL) {
		// ����ɹ���ָ��ǿգ�������׷�ӵ�����ֵ��
		char temp[128];
		sprintf_s(temp, sizeof(temp), "(%ld, %ld)", lpPoint->x, lpPoint->y);
		strcat_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp);
	}

	// д�빲���ڴ沢֪ͨ
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//������ƶ�����Ļָ��λ��
static BOOL(WINAPI* OldSetCursorPos)(int, int) = SetCursorPos;
extern "C" __declspec(dllexport) BOOL WINAPI NewSetCursorPos(int X, int Y) {
	// ��ʼ����־�ṹ��
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = SETCURSORPOS;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 2;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "X");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Y");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%d", X);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%d", Y);

	// д�빲���ڴ沢֪ͨ
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldSetCursorPos(X, Y);
}

//�����ͷŻ�ȡ�����������������ڴ�
static BOOL(WINAPI* OldVirtualFree)(LPVOID, SIZE_T, DWORD) = VirtualFree;

extern "C" __declspec(dllexport) BOOL WINAPI NewVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
	// ��ʼ����־�ṹ��
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = VIRTUALFREE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 3;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpAddress");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "dwSize");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwFreeType");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", lpAddress);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%Iu", dwSize); // SIZE_T ��ʽ��Ϊ %Iu
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "0x%X", dwFreeType);

	// д�빲���ڴ沢֪ͨ
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldVirtualFree(lpAddress, dwSize, dwFreeType);;
}


// ��ȡϵͳ�������Ϣ��������б��߳��б������ȣ�
static  NTSTATUS(NTAPI* OldNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength) = NtQuerySystemInformation;

extern "C" __declspec(dllexport) NTSTATUS NTAPI NewNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength)
{
	// ��ʼ����־�ṹ��
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = NTQUERYSYSTEMINFORMATION;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "SystemInformationClass");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "SystemInformation");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "SystemInformationLength");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "ReturnLength");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%lu", SystemInformationClass);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", SystemInformation);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%lu", SystemInformationLength);
	if (ReturnLength != NULL) {
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%p(=%lu)", ReturnLength, *ReturnLength);
	}
	else {
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "NULL");
	}

	// д�빲���ڴ沢֪ͨ
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);;
}

//��ָ�����̵������ַ�ռ��ж�ȡ�ڴ�����

static NTSTATUS(NTAPI* OldNtReadVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID  BaseAddress,
	PVOID  Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead) = nullptr;

extern "C" __declspec(dllexport) NTSTATUS NTAPI NewNtReadVirtualMemory(
	HANDLE ProcessHandle,
	PVOID  BaseAddress,
	PVOID  Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead)
{
	// ��ʼ����־�ṹ��
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = NTREADVIRTUALMEMORY;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 5;

	// ������
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "ProcessHandle");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "BaseAddress");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "Buffer");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "BufferSize");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "NumberOfBytesRead");

	// ����ֵ
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", ProcessHandle);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", BaseAddress);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", Buffer);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%Iu", BufferSize);  // SIZE_T ʹ�� %Iu

	if (NumberOfBytesRead != NULL) {
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%p(=%Iu)", NumberOfBytesRead, *NumberOfBytesRead);
	}
	else {
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "NULL");
	}

	// д�빲���ڴ沢֪ͨ
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}


//---------------------------------------------- main���� ------------------------------------------------

BOOL WINAPI DllMain(HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)OldMessageBoxA, NewMessageBoxA);
		DetourAttach(&(PVOID&)OldMessageBoxW, NewMessageBoxW);
		DetourAttach(&(PVOID&)OldWriteFile, NewWriteFile);
		DetourAttach(&(PVOID&)OldReadFile, NewReadFile);
		DetourAttach(&(PVOID&)OldCreateFileA, NewCreateFileA);
		DetourAttach(&(PVOID&)OldCreateFileW, NewCreateFileW);
		DetourAttach(&(PVOID&)OldDeleteFileA, NewDeleteFileA);
		DetourAttach(&(PVOID&)OldDeleteFileW, NewDeleteFileW);
		DetourAttach(&(PVOID&)OldGetFileAttributesW, NewGetFileAttributesW);
		DetourAttach(&(PVOID&)OldGetFileSize, NewGetFileSize);
		DetourAttach(&(PVOID&)OldMoveFileW, NewMoveFileW);
		DetourAttach(&(PVOID&)OldMoveFileExW, NewMoveFileExW);
		DetourAttach(&(PVOID&)OldSend, NewSend);
		DetourAttach(&(PVOID&)OldSendTo, NewSendTo);
		DetourAttach(&(PVOID&)OldWSASend, NewWSASend);
		DetourAttach(&(PVOID&)OldRecv, NewRecv);
		DetourAttach(&(PVOID&)OldRecvFrom, NewRecvFrom);
		DetourAttach(&(PVOID&)OldWSARecv, NewWSARecv);
		DetourAttach(&(PVOID&)OldConnect, NewConnect);
		DetourAttach(&(PVOID&)OldWSAConnect, NewWSAConnect);
		DetourAttach(&(PVOID&)Old_gethostbyname, New_gethostbyname);
		DetourAttach(&(PVOID&)Old_getaddrinfo, New_getaddrinfo);
		DetourAttach(&(PVOID&)OldSocket, NewSocket);
		DetourAttach(&(PVOID&)OldCloseSocket, NewCloseSocket);
		DetourAttach(&(PVOID&)OldCreateProcessW, NewCreateProcessW);
		DetourAttach(&(PVOID&)OldCreateProcessA, NewCreateProcessA);
		DetourAttach(&(PVOID&)OldShellExecuteW, NewShellExecuteW);
		DetourAttach(&(PVOID&)OldCreateThread, NewCreateThread);
		DetourAttach(&(PVOID&)OldExitThread, NewExitThread);
		DetourAttach(&(PVOID&)OldLoadLibraryW, NewLoadLibraryW);
		DetourAttach(&(PVOID&)OldLoadLibraryExW, NewLoadLibraryExW);
		DetourAttach(&(PVOID&)OldGetProcAddress, NewGetProcAddress);
		DetourAttach(&(PVOID&)OldVirtualAllocEx, NewVirtualAllocEx);
		DetourAttach(&(PVOID&)OldWriteProcessMemory, NewWriteProcessMemory);
		DetourAttach(&(PVOID&)OldCreateRemoteThread, NewCreateRemoteThread);
		DetourAttach(&(PVOID&)OldCreateWindowExW, NewCreateWindowExW);
		DetourAttach(&(PVOID&)OldRegisterClassW, NewRegisterClassW);
		DetourAttach(&(PVOID&)OldSetWindowLongW, NewSetWindowLongW);
		DetourAttach(&(PVOID&)OldShowWindow, NewShowWindow);
		DetourAttach(&(PVOID&)OldDestroyWindow, NewDestroyWindow);
		DetourAttach(&(PVOID&)OldGetAsyncKeyState, NewGetAsyncKeyState);
		DetourAttach(&(PVOID&)OldGetKeyState, NewGetKeyState);
		DetourAttach(&(PVOID&)OldRegisterHotKey, NewRegisterHotKey);
		DetourAttach(&(PVOID&)OldSetWindowsHookExA, NewSetWindowsHookExA);
		DetourAttach(&(PVOID&)OldGetCursorPos, NewGetCursorPos);
		DetourAttach(&(PVOID&)OldSetCursorPos, NewSetCursorPos);
		DetourAttach(&(PVOID&)OldVirtualFree, NewVirtualFree);
		DetourAttach(&(PVOID&)OldNtQuerySystemInformation, NewNtQuerySystemInformation);
		DetourAttach(&(PVOID&)OldNtReadVirtualMemory, NewNtReadVirtualMemory);
		DetourTransactionCommit();
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)OldMessageBoxA, NewMessageBoxA);
		DetourDetach(&(PVOID&)OldMessageBoxW, NewMessageBoxW);
		DetourDetach(&(PVOID&)OldWriteFile, NewWriteFile);
		DetourDetach(&(PVOID&)OldReadFile, NewReadFile);
		DetourDetach(&(PVOID&)OldCreateFileA, NewCreateFileA);
		DetourDetach(&(PVOID&)OldCreateFileW, NewCreateFileW);
		DetourDetach(&(PVOID&)OldDeleteFileA, NewDeleteFileA);
		DetourDetach(&(PVOID&)OldDeleteFileW, NewDeleteFileW);
		DetourDetach(&(PVOID&)OldGetFileAttributesW, NewGetFileAttributesW);
		DetourDetach(&(PVOID&)OldGetFileSize, NewGetFileSize);
		DetourDetach(&(PVOID&)OldMoveFileW, NewMoveFileW);
		DetourDetach(&(PVOID&)OldMoveFileExW, NewMoveFileExW);
		DetourDetach(&(PVOID&)OldSend, NewSend);
		DetourDetach(&(PVOID&)OldSendTo, NewSendTo);
		DetourDetach(&(PVOID&)OldWSASend, NewWSASend);
		DetourDetach(&(PVOID&)OldRecv, NewRecv);
		DetourDetach(&(PVOID&)OldRecvFrom, NewRecvFrom);
		DetourDetach(&(PVOID&)OldWSARecv, NewWSARecv);
		DetourDetach(&(PVOID&)OldConnect, NewConnect);
		DetourDetach(&(PVOID&)OldWSAConnect, NewWSAConnect);
		DetourDetach(&(PVOID&)Old_gethostbyname, New_gethostbyname);
		DetourDetach(&(PVOID&)Old_getaddrinfo, New_getaddrinfo);
		DetourDetach(&(PVOID&)OldSocket, NewSocket);
		DetourDetach(&(PVOID&)OldCloseSocket, NewCloseSocket);
		DetourDetach(&(PVOID&)OldCreateProcessW, NewCreateProcessW);
		DetourDetach(&(PVOID&)OldCreateProcessA, NewCreateProcessA);
		DetourDetach(&(PVOID&)OldShellExecuteW, NewShellExecuteW);
		DetourDetach(&(PVOID&)OldCreateThread, NewCreateThread);
		DetourDetach(&(PVOID&)OldExitThread, NewExitThread);
		DetourDetach(&(PVOID&)OldLoadLibraryW, NewLoadLibraryW);
		DetourDetach(&(PVOID&)OldLoadLibraryExW, NewLoadLibraryExW);
		DetourDetach(&(PVOID&)OldGetProcAddress, NewGetProcAddress);
		DetourDetach(&(PVOID&)OldVirtualAllocEx, NewVirtualAllocEx);
		DetourDetach(&(PVOID&)OldWriteProcessMemory, NewWriteProcessMemory);
		DetourDetach(&(PVOID&)OldCreateRemoteThread, NewCreateRemoteThread);
		DetourDetach(&(PVOID&)OldCreateWindowExW, NewCreateWindowExW);
		DetourDetach(&(PVOID&)OldRegisterClassW, NewRegisterClassW);
		DetourDetach(&(PVOID&)OldSetWindowLongW, NewSetWindowLongW);
		DetourDetach(&(PVOID&)OldShowWindow, NewShowWindow);
		DetourDetach(&(PVOID&)OldDestroyWindow, NewDestroyWindow);
		DetourDetach(&(PVOID&)OldGetAsyncKeyState, NewGetAsyncKeyState);
		DetourDetach(&(PVOID&)OldGetKeyState, NewGetKeyState);
		DetourDetach(&(PVOID&)OldRegisterHotKey, NewRegisterHotKey);
		DetourDetach(&(PVOID&)OldSetWindowsHookExA, NewSetWindowsHookExA);
		DetourDetach(&(PVOID&)OldGetCursorPos, NewGetCursorPos);
		DetourDetach(&(PVOID&)OldSetCursorPos, NewSetCursorPos);
		DetourDetach(&(PVOID&)OldVirtualFree, NewVirtualFree);
		DetourDetach(&(PVOID&)OldNtQuerySystemInformation, NewNtQuerySystemInformation);
		DetourDetach(&(PVOID&)OldNtReadVirtualMemory, NewNtReadVirtualMemory);
		DetourTransactionCommit();
		break;
	}
	}
	return true;
}