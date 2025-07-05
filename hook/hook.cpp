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
#pragma comment (lib, "ws2_32.lib")  //加载 ws2_32.dll
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
#define MESSAGEBOXA              1  // 弹窗
#define MESSAGEBOXW              2  // 弹窗
#define WRITEFILE                3  // 写文件
#define READFILE                 4  // 读文件
#define CREATEFILEA              5  // 打开或创建文件
#define CREATEFILEW              6  // 打开或创建文件
#define DELETEFILEA              7  // 删除文件
#define DELETEFILEW              8  // 删除文件
#define GETFILEATTRIBUTESW       9  // 获取文件属性
#define GETFILESIZE             10  // 获取文件大小
#define MOVEFILEW               11  // 移动或重命名文件
#define MOVEFILEEXW             12  // 移动文件（支持更多选项）
#define SEND                    13  // 发送数据
#define SENDTO                  14  // 发送数据到指定地址
#define WSASEND                 15  // 发送数据
#define RECV                    16  // 接收数据
#define RECVFROM                17  // 接收远程数据
#define WSARECV                 18  // 接收数据
#define CONNECT                 19  // 建立连接
#define WSACONNECT              20  // 建立连接
#define GETHOSTBYNAME           21  // 域名解析
#define GETADDRINFO             22  // 域名/IP解析
#define SOCKET_CREATE           23  // 创建套接字
#define SOCKET_CLOSE            24  // 关闭套接字
#define CREATEPROCESSA          25  // 创建进程（ANSI版本）
#define CREATEPROCESSW          26  // 创建进程（Unicode版本）
#define SHELLEXECUTEW           27  // 执行shell命令（Unicode版本）
#define CREATETHREAD            28  // 创建线程
#define EXITTHREAD              29  // 终止线程
#define LOADLIBRARYA            30  // 加载动态库（ANSI版本）
#define LOADLIBRARYW            31  // 加载动态库（Unicode版本）
#define LOADLIBRARYEXW          32  // 加载动态库（扩展参数，Unicode版本）
#define GETPROCADDRESS          33  // 获取函数地址
#define VIRTUALALLOCEX          34  // 在远程进程中分配内存
#define WRITEPROCESSMEMORY      35  // 向远程进程写入内存
#define CREATEREMOTETHREAD      36  // 在远程进程中创建线程
#define CREATEWINDOWEXA         37  // 创建窗口（扩展样式，ANSI版本）
#define CREATEWINDOWEXW         38  // 创建窗口（扩展样式，Unicode版本）
#define REGISTERCLASSA          39  // 注册窗口类（ANSI版本）
#define REGISTERCLASSW          40  // 注册窗口类（Unicode版本）
#define SETWINDOWLONGA          41  // 设置窗口属性（ANSI版本）
#define SETWINDOWLONGW          42  // 设置窗口属性（Unicode版本）
#define SHOWWINDOW              43  // 显示窗口
#define DESTROYWINDOW           44  // 销毁窗口
#define GETASYNCKEYSTATE        45  // 检查某个键被按下还是释放
#define GETKEYSTATE             46  // 获取指定虚拟键的状态
#define REGISTERHOTKEY          47  // 注册一个系统范围的热键（全局快捷键）
#define SETWINDOWSHOOKEXA       48  // 该函数用于安装一个钩子，它可以拦截并处理各种类型的输入事件或其他消息。
#define GETCURSORPOS            49  // 获取鼠标光标坐标
#define SETCURSORPOS            50  // 将光标移动到指定位置
#define VIRTUALFREE             51  // 用于释放或取消保留调拨的虚拟内存
#define NTQUERYSYSTEMINFORMATION 52 // 获取系统级别的信息（如进程列表、线程列表、句柄表等）
#define NTREADVIRTUALMEMORY     53  // 从指定进程的虚拟地址空间中读取内存数据





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

// 打开一个名为mySemaphore的命名信号量，实质是连接到另一个进程已经创建好的信号量，之后可以使用这个信号量做PV操作
HANDLE hSemaphore = OpenSemaphore(EVENT_ALL_ACCESS, FALSE, L"mySemaphore");
// 打开一个名为ShareMemory的内存映射文件，实质是连接到一个已经由其他进程创建的共享内存区域，以实现数据交换
HANDLE hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, NULL, L"ShareMemory");
// 将 hMapFile 指向的共享内存文件映射到当前进程的虚拟地址空间中，并返回一个指向共享内存首地址的指针 lpBase，以便读写数据。
LPVOID lpBase = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(info));

/*
* ------------------------------------------------------------------------------------------------------
  ----------------------------------------------- 王博 -------------------------------------------------
  ------------------------------------------------------------------------------------------------------
*/

//打开文件
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

		// 参数名
		sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");
		sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "dwDesiredAccess");
		sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwShareMode");
		sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpSecurityAttributes");
		sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "dwCreationDisposition");
		sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "dwFlagsAndAttributes");
		sprintf_s(sendInfo.argName[6], sizeof(sendInfo.argName[6]), "hTemplateFile");

		// 参数值（ANSI字符串直接赋值）
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

		// 参数名
		sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");
		sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "dwDesiredAccess");
		sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwShareMode");
		sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpSecurityAttributes");
		sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "dwCreationDisposition");
		sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "dwFlagsAndAttributes");
		sprintf_s(sendInfo.argName[6], sizeof(sendInfo.argName[6]), "hTemplateFile");

		// 参数值（宽字符转ANSI）
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


//读文件

// 保存原始函数地址
static BOOL(WINAPI* OldReadFile)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
	) = ReadFile;

// 读文件
extern "C" __declspec(dllexport) BOOL WINAPI NewReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
) {
	// 设置信息类型
	sendInfo.type = READFILE;
	sendInfo.argNum = 5;
	GetLocalTime(&(sendInfo.st));

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "hFile");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpBuffer");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "nNumberOfBytesToRead");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpNumberOfBytesRead");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "lpOverlapped");

	// 参数值（转十六进制指针/数值）
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (DWORD_PTR)hFile);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", (DWORD_PTR)lpBuffer);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", nNumberOfBytesToRead);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", (DWORD_PTR)lpNumberOfBytesRead);
	sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%08X", (DWORD_PTR)lpOverlapped);

	// 写入共享内存并释放信号量
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	sendInfo.argNum = 0;

	// 调用原始 ReadFile
	return OldReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}


// 写文件
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
		// 参数名
		sprintf(sendInfo.argName[0], "hFile");
		sprintf(sendInfo.argName[1], "lpBuffer");
		sprintf(sendInfo.argName[2], "nNumberOfBytesToWrite");
		sprintf(sendInfo.argName[3], "lpNumberOfBytesWritten");
		sprintf(sendInfo.argName[4], "lpOverlapped");
		// 参数值
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

//删除文件{messageA)
static BOOL(WINAPI* OldDeleteFileA)(LPCSTR lpFileName) = DeleteFileA;

extern "C" __declspec(dllexport) BOOL WINAPI NewDeleteFileA(LPCSTR lpFileName)
{
	BOOL result = OldDeleteFileA(lpFileName);

	sendInfo.argNum = 1;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");

	// 参数值（ANSI字符串可直接复制）
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

//删除文件(messageW)
static BOOL(WINAPI* OldDeleteFileW)(LPCWSTR lpFileName) = DeleteFileW;

extern "C" __declspec(dllexport) BOOL WINAPI NewDeleteFileW(LPCWSTR lpFileName)
{
	BOOL result = OldDeleteFileW(lpFileName);

	sendInfo.argNum = 1;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");

	// 参数值（宽字符转换为 ANSI）
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

//文件属性
static DWORD(WINAPI* OldGetFileAttributesW)(LPCWSTR lpFileName) = GetFileAttributesW;

extern "C" __declspec(dllexport) DWORD WINAPI NewGetFileAttributesW(LPCWSTR lpFileName)
{
	DWORD result = OldGetFileAttributesW(lpFileName);

	sendInfo.type = GETFILEATTRIBUTESW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");

	// 参数值（宽字符转换为 ANSI）
	char temp[256] = { 0 };
	if (lpFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
	}

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//文件大小
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

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "hFile");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpFileSizeHigh");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (DWORD)hFile);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", (DWORD)lpFileSizeHigh);

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//简单移动/重命名文件
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

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpExistingFileName");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpNewFileName");

	// 参数值（宽字符转多字节）
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

	// 写入共享内存并释放信号量
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldMoveFileW(lpExistingFileName, lpNewFileName);
}

//支持替换、延迟、复制等高级移动操作
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

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpExistingFileName");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpNewFileName");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwFlags");

	// 参数值
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

	// 写入共享内存并释放信号量
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldMoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
}

//send(通过一个 已建立连接的套接字（SOCK_STREAM，即 TCP） 发送数据。)
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

//sendto(用于通过一个套接字（可以是 UDP 或未连接的 TCP）向指定地址发送数据，适用于无连接协议（如 UDP）。
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


//WSAsend(WSASend 是 send 的增强版本，支持异步/重叠 I/O 和多个缓冲区发送，通常用于更高性能或异步网络编程中。
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


//接收数据recv
static int (WINAPI* OldRecv)(SOCKET s, char* buf, int len, int flags) = recv;

extern "C" __declspec(dllexport) int WINAPI NewRecv(SOCKET s, char* buf, int len, int flags)
{
	sendInfo.type = RECV;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "Socket");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Buffer");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "Length");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "Flags");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (unsigned int)s);
	// 只记录buf前面部分数据做示例（防止过大）
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

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "Socket");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Buffer");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "Length");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "Flags");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "From");
	sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "FromLen");

	// 参数值
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

	// 打印 from 地址（IPv4 示例）
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

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "Socket");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Buffers");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "BufferCount");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "Flags");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "Overlapped");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (unsigned int)s);

	// 简单打印第一个缓冲区的数据
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

//connect(用于通过一个未连接的套接字（SOCK_STREAM，即 TCP）连接到指定地址，通常用于建立 TCP 连接。
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

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "s");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "name");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "namelen");

	// 参数值
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

//WSAConnect(用于通过一个未连接的套接字（SOCK_STREAM，即 TCP）连接到指定地址，通常用于建立 TCP 连接。
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

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "s");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "name");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "namelen");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpCallerData");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "lpCalleeData");
	sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "lpSQOS");
	sprintf_s(sendInfo.argName[6], sizeof(sendInfo.argName[6]), "lpGQOS");

	// 参数值
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

//IPv4 域名解析，旧 API
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

//IPv4/IPv6 统一解析接口
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


// 创建socket
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

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "af");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "type");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "protocol");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", af);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", type);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", protocol);

	sendInfo.type = SOCKETCREATE;
	GetLocalTime(&(sendInfo.st));

	memcpy(lpBase, &sendInfo, sizeof(info));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldSocket(af, type, protocol);
}

// 关闭socket
static int (WINAPI* OldCloseSocket)(SOCKET s) = closesocket;

// Hook 函数实现
extern "C" __declspec(dllexport) int WINAPI NewCloseSocket(SOCKET s) {
	sendInfo.argNum = 1;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "s");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", s);

	sendInfo.type = SOCKETCLOSE;
	GetLocalTime(&(sendInfo.st));

	memcpy(lpBase, &sendInfo, sizeof(info));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldCloseSocket(s);
}

/*
* ------------------------------------------------------------------------------------------------------
  ----------------------------------------------- 沈丽彤 -------------------------------------------------
  ------------------------------------------------------------------------------------------------------
*/

// 原始函数
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

// 定义Hook后函数
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

	// 参数名
	const char* paramNames[] = {
		"lpApplicationName", "lpCommandLine", "lpProcessAttributes",
		"lpThreadAttributes", "bInheritHandles", "dwCreationFlags",
		"lpEnvironment", "lpCurrentDirectory", "lpStartupInfo",
		"lpProcessInformation"
	};
	for (int i = 0; i < 10; i++) {
		strcpy(sendInfo.argName[i], paramNames[i]);
	}

	// 参数值处理
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

	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// 调用原始函数
	return OldCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
		lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment, lpCurrentDirectory, lpStartupInfo,
		lpProcessInformation);
}

// 原始函数
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

// Hook后函数
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
	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(sendInfo));
	sendInfo.type = CREATEPROCESSA;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 10;

	// 参数名
	const char* paramNames[] = {
		"lpApplicationName", "lpCommandLine", "lpProcessAttributes",
		"lpThreadAttributes", "bInheritHandles", "dwCreationFlags",
		"lpEnvironment", "lpCurrentDirectory", "lpStartupInfo",
		"lpProcessInformation"
	};

	for (int i = 0; i < 10; i++) {
		strcpy_s(sendInfo.argName[i], sizeof(sendInfo.argName[i]), paramNames[i]);
	}

	// 参数值处理
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

	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(sendInfo));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	sendInfo.argNum = 0;  // 清除参数数量

	return OldCreateProcessA(
		lpApplicationName, lpCommandLine, lpProcessAttributes,
		lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment, lpCurrentDirectory, lpStartupInfo,
		lpProcessInformation);
}


// 原始函数
static HINSTANCE(WINAPI* OldShellExecuteW)(
	_In_opt_ HWND hwnd,
	_In_opt_ LPCWSTR lpOperation,
	_In_ LPCWSTR lpFile,
	_In_opt_ LPCWSTR lpParameters,
	_In_opt_ LPCWSTR lpDirectory,
	_In_ INT nShowCmd
	) = ShellExecuteW;

// Hook后函数
extern "C" __declspec(dllexport) HINSTANCE WINAPI NewShellExecuteW(
	_In_opt_ HWND hwnd,
	_In_opt_ LPCWSTR lpOperation,
	_In_ LPCWSTR lpFile,
	_In_opt_ LPCWSTR lpParameters,
	_In_opt_ LPCWSTR lpDirectory,
	_In_ INT nShowCmd)
{
	char temp[256] = { 0 };

	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = SHELLEXECUTEW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;

	// 参数名
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

	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	return OldShellExecuteW(hwnd, lpOperation, lpFile,
		lpParameters, lpDirectory, nShowCmd);
}

// 原始函数
static HANDLE(WINAPI* OldCreateThread)(
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	) = CreateThread;

// Hook后函数
extern "C" __declspec(dllexport) HANDLE WINAPI NewCreateThread(
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId)
{
	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = CREATETHREAD;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;

	// 参数名
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
	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// 调用原始函数
	HANDLE hThread = OldCreateThread(
		lpThreadAttributes, dwStackSize, lpStartAddress,
		lpParameter, dwCreationFlags, lpThreadId);

	// 记录实际创建的线程ID
	if (hThread && lpThreadId) {
		char extraInfo[50] = { 0 };
		sprintf_s(extraInfo, "ActualTID:%d", *lpThreadId);
		strcat_s(sendInfo.argValue[6], extraInfo);
		memcpy(lpBase, &sendInfo, sizeof(info));
	}

	return hThread;
}

// 原始函数
static VOID(WINAPI* OldExitThread)(_In_ DWORD dwExitCode) = ExitThread;

// Hook后函数
extern "C" __declspec(dllexport) VOID WINAPI NewExitThread(_In_ DWORD dwExitCode)
{
	// 记录调用信息
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

	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	// 调用原始函数
	OldExitThread(dwExitCode);

}


// 原始函数
static HMODULE(WINAPI* OldLoadLibraryW)(_In_ LPCWSTR lpLibFileName) = LoadLibraryW;

// Hook后函数
extern "C" __declspec(dllexport) HMODULE WINAPI NewLoadLibraryW(_In_ LPCWSTR lpLibFileName)
{
	char temp[MAX_PATH] = { 0 };

	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = LOADLIBRARYW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 3;

	// 参数名
	strcpy(sendInfo.argName[0], "lpLibFileName");
	strcpy(sendInfo.argName[1], "CallerPID");
	strcpy(sendInfo.argName[2], "CallerTID");

	// 参数值处理
	if (lpLibFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpLibFileName, -1, temp, sizeof(temp), NULL, NULL);
		// 提取纯文件名（去掉路径）
		char* fileName = strrchr(temp, '\\');
		fileName = fileName ? fileName + 1 : temp;
		sprintf(sendInfo.argValue[0], "%s", fileName);
	}
	else {
		strcpy(sendInfo.argValue[0], "NULL");
	}

	// 调用者信息
	sprintf(sendInfo.argValue[1], "%d", GetCurrentProcessId());
	sprintf(sendInfo.argValue[2], "%d", GetCurrentThreadId());

	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// 调用原始函数
	HMODULE hModule = OldLoadLibraryW(lpLibFileName);

	// 记录加载结果
	if (hModule) {
		char modInfo[50] = { 0 };
		sprintf(modInfo, "BaseAddr:%p", hModule);
		strcat(sendInfo.argValue[0], modInfo);
		memcpy(lpBase, &sendInfo, sizeof(info)); // 更新信息
	}

	return hModule;
}

// 原始函数
static HMODULE(WINAPI* OldLoadLibraryExW)(
	_In_ LPCWSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags
	) = LoadLibraryExW;

// Hook函数后
extern "C" __declspec(dllexport) HMODULE WINAPI NewLoadLibraryExW(
	_In_ LPCWSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags)
{
	char temp[MAX_PATH] = { 0 };
	char flagsStr[100] = { 0 };

	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = LOADLIBRARYEXW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 5;  // 参数+调用者信息

	// 参数名
	strcpy(sendInfo.argName[0], "lpLibFileName");
	strcpy(sendInfo.argName[1], "dwFlags");
	strcpy(sendInfo.argName[2], "hFile");
	strcpy(sendInfo.argName[3], "CallerPID");
	strcpy(sendInfo.argName[4], "CallerTID");

	// 参数值处理
	if (lpLibFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpLibFileName, -1, temp, sizeof(temp), NULL, NULL);
		sprintf_s(sendInfo.argValue[0], "%s", temp);
	}
	else {
		strcpy(sendInfo.argValue[0], "NULL");
	}

	// 解析标志位
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

	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// 调用原始函数
	return OldLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

// 原始函数指针声明
static FARPROC(WINAPI* OldGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	) = GetProcAddress;

// Hook后函数
extern "C" __declspec(dllexport) FARPROC WINAPI NewGetProcAddress(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName)
{
	char modName[MAX_PATH] = { 0 };

	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = GETPROCADDRESS;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;

	// 参数名
	strcpy(sendInfo.argName[0], "hModule");
	strcpy(sendInfo.argName[1], "lpProcName");
	strcpy(sendInfo.argName[2], "CallerPID");
	strcpy(sendInfo.argName[3], "CallerTID");

	// 参数值处理
	sprintf(sendInfo.argValue[0], "%p", hModule);

	// 获取模块文件名
	if (hModule && GetModuleFileNameA(hModule, modName, MAX_PATH)) {
		char* fileName = strrchr(modName, '\\');
		fileName = fileName ? fileName + 1 : modName;
		sprintf(sendInfo.argValue[0], "%p (%s)", hModule, fileName);
	}

	// 处理函数名（可能是序号）
	if (IS_INTRESOURCE(lpProcName)) {
		sprintf(sendInfo.argValue[1], "#%d", (DWORD)lpProcName);
	}
	else {
		sprintf(sendInfo.argValue[1], "%s", lpProcName ? lpProcName : "NULL");
	}

	// 调用者信息
	sprintf(sendInfo.argValue[2], "%d", GetCurrentProcessId());
	sprintf(sendInfo.argValue[3], "%d", GetCurrentThreadId());

	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// 调用原始函数
	FARPROC proc = OldGetProcAddress(hModule, lpProcName);

	// 可选：记录获取结果
	if (proc) {
		char procInfo[50] = { 0 };
		sprintf(procInfo, "->%p", proc);
		strcat(sendInfo.argValue[1], procInfo);
		memcpy(lpBase, &sendInfo, sizeof(info)); // 更新信息
	}

	return proc;
}

// 原始函数
static LPVOID(WINAPI* OldVirtualAllocEx)(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	) = VirtualAllocEx;

// 保护属性解析函数
const char* GetMemoryProtectionString(DWORD protect) {
	static char buffer[128];
	ZeroMemory(buffer, sizeof(buffer));

	// 基础保护属性
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

	// 附加属性
	if (protect & PAGE_GUARD)
		strcat_s(buffer, " | GUARD");
	if (protect & PAGE_NOCACHE)
		strcat_s(buffer, " | NOCACHE");
	if (protect & PAGE_WRITECOMBINE)
		strcat_s(buffer, " | WRITECOMBINE");

	return buffer;
}

// Hook后函数
extern "C" __declspec(dllexport) LPVOID WINAPI NewVirtualAllocEx(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect)
{
	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = VIRTUALALLOCEX;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;  // 5参数+调用者信息

	// 参数名
	const char* paramNames[] = {
		"hProcess", "lpAddress", "dwSize",
		"flAllocationType", "flProtect", "CallerInfo"
	};
	for (int i = 0; i < 6; i++) {
		strcpy(sendInfo.argName[i], paramNames[i]);
	}

	// 参数值处理
	DWORD targetPid = GetProcessId(hProcess);
	sprintf(sendInfo.argValue[0], "%p (PID:%d)", hProcess, targetPid);
	sprintf(sendInfo.argValue[1], "%p", lpAddress);
	sprintf(sendInfo.argValue[2], "%zu bytes", dwSize);

	// 解析内存分配类型
	char allocType[128] = { 0 };
	if (flAllocationType & MEM_COMMIT) strcat(allocType, "COMMIT|");
	if (flAllocationType & MEM_RESERVE) strcat(allocType, "RESERVE|");
	if (flAllocationType & MEM_RESET) strcat(allocType, "RESET|");
	if (flAllocationType & MEM_RESET_UNDO) strcat(allocType, "RESET_UNDO|");
	if (flAllocationType & MEM_LARGE_PAGES) strcat(allocType, "LARGE_PAGES|");
	if (flAllocationType & MEM_PHYSICAL) strcat(allocType, "PHYSICAL|");
	if (flAllocationType & MEM_TOP_DOWN) strcat(allocType, "TOP_DOWN|");

	if (strlen(allocType) > 0) {
		allocType[strlen(allocType) - 1] = '\0'; // 移除末尾的|
	}
	else {
		strcpy(allocType, "DEFAULT");
	}
	sprintf(sendInfo.argValue[3], "0x%08X (%s)", flAllocationType, allocType);
	// 完整保护属性解析
	sprintf(sendInfo.argValue[4], "0x%08X (%s)", flProtect, GetMemoryProtectionString(flProtect));
	// 调用者信息
	sprintf(sendInfo.argValue[5], "CallerPID:%d", GetCurrentProcessId());
	// 检测可疑组合
	if ((flProtect & PAGE_EXECUTE_READWRITE) ||
		(flProtect & PAGE_EXECUTE_WRITECOPY)) {
		strcat(sendInfo.argValue[4], " [EXECUTABLE]");
	}
	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	// 调用原始函数
	LPVOID result = OldVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	// 记录分配结果
	if (result) {
		char resultInfo[128] = { 0 };
		sprintf_s(resultInfo, "-> Allocated at %p", result);
		strcat_s(sendInfo.argValue[2], resultInfo);

		// 更新共享内存
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(info));
		}
	}
	return result;
}

// 原始函数指针声明
static BOOL(WINAPI* OldWriteProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesWritten
	) = WriteProcessMemory;

// Hook后函数
extern "C" __declspec(dllexport) BOOL WINAPI NewWriteProcessMemory(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesWritten)
{
	// 初始化日志结构体
	ZeroMemory(&sendInfo, sizeof(sendInfo));
	sendInfo.type = WRITEPROCESSMEMORY;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;  // 5参数+调用者信息

	// 参数名
	const char* paramNames[] = {
		"hProcess", "lpBaseAddress", "nSize",
		"lpBuffer", "lpBytesWritten", "CallerInfo"
	};
	for (int i = 0; i < 6; i++) {
		strcpy_s(sendInfo.argName[i], sizeof(sendInfo.argName[i]), paramNames[i]);
	}

	// 参数值处理
	DWORD targetPid = 0;
	if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE) {
		targetPid = GetProcessId(hProcess);
	}
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p (PID:%d)", hProcess, targetPid);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", lpBaseAddress);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%zu bytes", nSize);

	// 敏感内容处理（限制记录长度）
	if (lpBuffer && nSize > 0) {
		char hexDump[512] = { 0 };
		size_t dumpLen = min(nSize, (SIZE_T)16);  // 只记录前16字节
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

	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(sendInfo));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// 调用原始函数
	BOOL ret = OldWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

	// 可选：记录实际写入字节数
	if (ret && lpNumberOfBytesWritten) {
		char writeInfo[100] = { 0 };
		sprintf_s(writeInfo, sizeof(writeInfo), "-> ActualWrite:%zu", *lpNumberOfBytesWritten);
		strcat_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), writeInfo);

		// 更新共享内存中的信息
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(sendInfo));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}
	}

	return ret;
}

// 原始函数
static HANDLE(WINAPI* OldCreateRemoteThread)(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId
	) = CreateRemoteThread;

// Hook后函数
extern "C" __declspec(dllexport) HANDLE WINAPI NewCreateRemoteThread(
	_In_ HANDLE hProcess,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ SIZE_T dwStackSize,
	_In_ LPTHREAD_START_ROUTINE lpStartAddress,
	_In_opt_ LPVOID lpParameter,
	_In_ DWORD dwCreationFlags,
	_Out_opt_ LPDWORD lpThreadId)
{
	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = CREATEREMOTETHREAD;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 8;

	// 参数名
	const char* paramNames[] = {
		"hProcess", "lpThreadAttributes", "dwStackSize",
		"lpStartAddress", "lpParameter", "dwCreationFlags",
		"lpThreadId", "CallerInfo"
	};
	for (int i = 0; i < 8; i++) {
		strcpy(sendInfo.argName[i], paramNames[i]);
	}

	// 参数值处理
	DWORD targetPid = GetProcessId(hProcess);
	sprintf(sendInfo.argValue[0], "%p (PID:%d)", hProcess, targetPid);
	sprintf(sendInfo.argValue[1], "%p", lpThreadAttributes);
	sprintf(sendInfo.argValue[2], "%zu", dwStackSize);
	sprintf(sendInfo.argValue[3], "%p", lpStartAddress);
	sprintf(sendInfo.argValue[4], "%p", lpParameter);

	// 解析线程标志
	char flagsStr[50] = { 0 };
	if (dwCreationFlags & CREATE_SUSPENDED) strcat_s(flagsStr, "SUSPENDED|");
	if (strlen(flagsStr)) flagsStr[strlen(flagsStr) - 1] = '\0';
	sprintf(sendInfo.argValue[5], "0x%08X (%s)", dwCreationFlags, flagsStr);

	sprintf(sendInfo.argValue[6], "%p", lpThreadId);
	sprintf(sendInfo.argValue[7], "CallerPID:%d", GetCurrentProcessId());

	// 写入共享内存（注入行为需立即告警）
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	// 调用原始函数
	HANDLE hThread = OldCreateRemoteThread(
		hProcess, lpThreadAttributes, dwStackSize,
		lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	// 记录实际线程ID
	if (hThread && lpThreadId) {
		char threadInfo[50] = { 0 };
		sprintf(threadInfo, "-> RemoteTID:%d", *lpThreadId);
		strcat(sendInfo.argValue[6], threadInfo);
		memcpy(lpBase, &sendInfo, sizeof(info)); // 更新信息
	}

	return hThread;
}

// 定义需要hook的函数
static int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxA;
// 定义需要替换的新的函数
extern "C" __declspec(dllexport) int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
	sendInfo.type = MESSAGEBOXA;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;
	//参数名
	sprintf(sendInfo.argName[0], "hWnd");//当数组作为函数参数，则数组名就是数组首元素的地址 即变成了char*
	sprintf(sendInfo.argName[1], "lpText");
	sprintf(sendInfo.argName[2], "lpCaption");
	sprintf(sendInfo.argName[3], "uType");
	//参数值
	sprintf(sendInfo.argValue[0], "%08X", hWnd);
	sprintf(sendInfo.argValue[1], "%s", lpText);
	sprintf(sendInfo.argValue[2], "%s", lpCaption);
	sprintf(sendInfo.argValue[3], "%08X", uType);

	// 将sendinfo赋值到共享内存
	memcpy(lpBase, &sendInfo, sizeof(info));
	// 进行V操作，使得信号量+1
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	// 返回原始接口
	return OldMessageBoxA(hWnd, lpText, lpCaption, uType);
}

static int (WINAPI* OldMessageBoxW)(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType) = MessageBoxW;
extern "C" __declspec(dllexport) int WINAPI NewMessageBoxW(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType)
{
	char temp[70];
	sendInfo.type = MESSAGEBOXW;
	GetLocalTime(&(sendInfo.st));

	sendInfo.argNum = 4;
	// 参数名
	sprintf(sendInfo.argName[0], "hWnd");
	sprintf(sendInfo.argName[1], "lpText");
	sprintf(sendInfo.argName[2], "lpCaption");
	sprintf(sendInfo.argName[3], "uType");
	// 参数值
	sprintf(sendInfo.argValue[0], "%08X", hWnd);

	// lpText: 宽字节转 ANSI，带 NULL 检查
	memset(temp, 0, sizeof(temp));
	if (lpText) {
		WideCharToMultiByte(CP_ACP, 0, lpText, sizeof(lpText), temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);
	}

	// lpCaption: 宽字节转 ANSI，带 NULL 检查
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

// 原始函数
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

// Hook后函数
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

	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = CREATEWINDOWEXW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 13;

	// 参数名
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

// 原始函数
static ATOM(WINAPI* OldRegisterClassW)(_In_ CONST WNDCLASSW* lpWndClass) = RegisterClassW;

// Hook后函数
extern "C" __declspec(dllexport) ATOM WINAPI NewRegisterClassW(_In_ CONST WNDCLASSW * lpWndClass)
{
	char temp[256] = { 0 };

	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = REGISTERCLASSW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 8; // 主要字段+调用者信息

	// 参数名
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
		// 类名记录
		if (!IS_INTRESOURCE(lpWndClass->lpszClassName)) {
			WideCharToMultiByte(CP_ACP, 0, lpWndClass->lpszClassName, -1, temp, sizeof(temp), NULL, NULL);
			strcat(sendInfo.argValue[7], " ClassName:");
			strcat(sendInfo.argValue[7], temp);
		}
	}
	else {
		strcpy(sendInfo.argValue[0], "NULL");
	}

	// 写入共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}

	// 调用原始函数
	ATOM ret = OldRegisterClassW(lpWndClass);

	// 记录返回的原子值
	if (ret) {
		char atomInfo[30] = { 0 };
		sprintf(atomInfo, "-> ATOM:0x%04X", ret);
		strcat(sendInfo.argValue[7], atomInfo);
		memcpy(lpBase, &sendInfo, sizeof(info));
	}

	return ret;
}

// 原始函数
static LONG(WINAPI* OldSetWindowLongW)(
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
	) = SetWindowLongW;

// Hook后函数
extern "C" __declspec(dllexport) LONG_PTR WINAPI NewSetWindowLongW(
    _In_ HWND hWnd,
    _In_ int nIndex,
    _In_ LONG_PTR dwNewLong)
{
    char indexStr[50] = { 0 };

    // 初始化日志结构体
    ZeroMemory(&sendInfo, sizeof(sendInfo));
    sendInfo.type = SETWINDOWLONGW;
    GetLocalTime(&(sendInfo.st));
    sendInfo.argNum = 4;

    // 参数名
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

    // 写入共享内存
    if (lpBase) {
        memcpy(lpBase, &sendInfo, sizeof(sendInfo));
        ReleaseSemaphore(hSemaphore, 1, NULL);
    }

    // 调用原始函数
    LONG_PTR ret = OldSetWindowLongW(hWnd, nIndex, dwNewLong);

    // 可选：记录原始值
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

// 原始函数
static BOOL(WINAPI* OldShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow) = ShowWindow;

// Hook后函数
extern "C" __declspec(dllexport) BOOL WINAPI NewShowWindow(
	_In_ HWND hWnd,
	_In_ int nCmdShow)
{
	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = SHOWWINDOW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 3;

	// 参数名
	strcpy(sendInfo.argName[0], "hWnd");
	strcpy(sendInfo.argName[1], "nCmdShow");
	strcpy(sendInfo.argName[2], "CallerInfo");
	sprintf(sendInfo.argValue[0], "%p", hWnd);
	const char* cmdStr = NULL;
	switch (nCmdShow) {
	case SW_HIDE: cmdStr = "SW_HIDE(0)"; break;               // 隐藏窗口
	case SW_SHOWNORMAL: cmdStr = "SW_SHOWNORMAL(1)"; break;   // 正常显示并激活
	//case SW_NORMAL: cmdStr = "SW_NORMAL(1)"; break;           // 同SW_SHOWNORMAL
	case SW_SHOWMINIMIZED: cmdStr = "SW_SHOWMINIMIZED(2)"; break; // 最小化并激活
	case SW_SHOWMAXIMIZED: cmdStr = "SW_SHOWMAXIMIZED(3)"; break; // 最大化并激活
	//case SW_MAXIMIZE: cmdStr = "SW_MAXIMIZE(3)"; break;       // 同SW_SHOWMAXIMIZED
	case SW_SHOWNOACTIVATE: cmdStr = "SW_SHOWNOACTIVATE(4)"; break; // 显示但不激活
	case SW_SHOW: cmdStr = "SW_SHOW(5)"; break;               // 简单显示
	case SW_MINIMIZE: cmdStr = "SW_MINIMIZE(6)"; break;       // 最小化并失活
	case SW_SHOWMINNOACTIVE: cmdStr = "SW_SHOWMINNOACTIVE(7)"; break; // 同SW_MINIMIZE
	case SW_SHOWNA: cmdStr = "SW_SHOWNA(8)"; break;           // 显示当前状态
	case SW_RESTORE: cmdStr = "SW_RESTORE(9)"; break;         // 恢复窗口
	case SW_SHOWDEFAULT: cmdStr = "SW_SHOWDEFAULT(10)"; break; // 按STARTUPINFO设置显示
	case SW_FORCEMINIMIZE: cmdStr = "SW_FORCEMINIMIZE(11)"; break; // 强制最小化
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

	// 记录窗口先前状态
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

	// 更新共享内存
	if (lpBase) {
		memcpy(lpBase, &sendInfo, sizeof(info));
	}

	return ret;
}

// 原始函数
static BOOL(WINAPI* OldDestroyWindow)(_In_ HWND hWnd) = DestroyWindow;

// Hook后函数
extern "C" __declspec(dllexport) BOOL WINAPI NewDestroyWindow(_In_ HWND hWnd)
{
	// 记录调用信息
	ZeroMemory(&sendInfo, sizeof(info));
	sendInfo.type = DESTROYWINDOW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 2;

	// 参数名
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

	// 记录结果
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
  ----------------------------------------------- 姚文达 -------------------------------------------------
  ------------------------------------------------------------------------------------------------------
*/

// 检查某个键被按下还是释放
static SHORT (WINAPI* OldGetAsyncKeyState)(int vKey) = GetAsyncKeyState;
extern "C" __declspec(dllexport) SHORT WINAPI NewGetAsyncKeyState(int vKey) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = GETASYNCKEYSTATE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;
	//参数名
	sprintf(sendInfo.argName[0], "vKey");
	//参数值
	sprintf(sendInfo.argValue[0], "%d", vKey);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	//sendInfo.argNum = 0;
	return OldGetAsyncKeyState(vKey);
}

// 获取指定虚拟键的状态
static SHORT(WINAPI* OldGetKeyState)(int nVirtKey) = GetKeyState;
extern "C" __declspec(dllexport) SHORT WINAPI NewGetKeyState(int nVirtKey) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = GETKEYSTATE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;
	//参数名
	sprintf(sendInfo.argName[0], "nVirtKey");
	//参数值
	sprintf(sendInfo.argValue[0], "%d", nVirtKey);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	return OldGetKeyState(nVirtKey);
}

// 注册一个系统范围的热键（全局快捷键）
static BOOL(WINAPI* OldRegisterHotKey)(HWND hWnd, int  id, UINT fsModifiers, UINT vk) = RegisterHotKey;
extern "C" __declspec(dllexport) BOOL WINAPI NewRegisterHotKey(HWND hWnd, int  id, UINT fsModifiers, UINT vk) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = REGISTERHOTKEY;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;
	//参数名
	sprintf(sendInfo.argName[0], "hWnd");
	sprintf(sendInfo.argName[1], "id");
	sprintf(sendInfo.argName[2], "fsModifiers");
	sprintf(sendInfo.argName[3], "vk");
	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", hWnd); // HWND 是指针
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%d", id);   // id 是 int
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%u", fsModifiers); // UINT
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "0x%X", vk); // 虚拟键码以十六进制显示更清晰

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	//sendInfo.argNum = 0;

	// 调用原始函数
	return OldRegisterHotKey(hWnd, id, fsModifiers, vk);

}

//该函数用于安装一个钩子，它可以拦截并处理各种类型的输入事件或其他消息。
static HHOOK(WINAPI* OldSetWindowsHookExA) (int idHook, HOOKPROC  lpfn, HINSTANCE hmod, DWORD dwThreadId) = SetWindowsHookExA;
extern "C" __declspec(dllexport) HHOOK WINAPI NewSetWindowsHookExA(int idHook, HOOKPROC  lpfn, HINSTANCE hmod, DWORD dwThreadId) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = SETWINDOWSHOOKEXA;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;
	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "idHook");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpfn");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "hmod");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "dwThreadId");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%d", idHook);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", lpfn);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", hmod);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%lu", dwThreadId);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	// 调用原始函数
	return OldSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
}

// 获取鼠标光标坐标
static BOOL(WINAPI* OldGetCursorPos)(LPPOINT) = GetCursorPos;
extern "C" __declspec(dllexport) BOOL WINAPI NewGetCursorPos(LPPOINT lpPoint) {
	// 记录调用信息
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = GETCURSORPOS;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpPoint");

	// 参数值：先记录原始地址，调用后再记录实际坐标
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", lpPoint);

	// 调用原始函数获取光标位置
	BOOL result = OldGetCursorPos(lpPoint);

	if (result && lpPoint != NULL) {
		// 如果成功且指针非空，把坐标追加到参数值中
		char temp[128];
		sprintf_s(temp, sizeof(temp), "(%ld, %ld)", lpPoint->x, lpPoint->y);
		strcat_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp);
	}

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//将光标移动到屏幕指定位置
static BOOL(WINAPI* OldSetCursorPos)(int, int) = SetCursorPos;
extern "C" __declspec(dllexport) BOOL WINAPI NewSetCursorPos(int X, int Y) {
	// 初始化日志结构体
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = SETCURSORPOS;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 2;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "X");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Y");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%d", X);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%d", Y);

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldSetCursorPos(X, Y);
}

//用于释放或取消保留调拨的虚拟内存
static BOOL(WINAPI* OldVirtualFree)(LPVOID, SIZE_T, DWORD) = VirtualFree;

extern "C" __declspec(dllexport) BOOL WINAPI NewVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
	// 初始化日志结构体
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = VIRTUALFREE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 3;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpAddress");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "dwSize");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwFreeType");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", lpAddress);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%Iu", dwSize); // SIZE_T 格式化为 %Iu
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "0x%X", dwFreeType);

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldVirtualFree(lpAddress, dwSize, dwFreeType);;
}


// 获取系统级别的信息（如进程列表、线程列表、句柄表等）
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
	// 初始化日志结构体
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = NTQUERYSYSTEMINFORMATION;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "SystemInformationClass");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "SystemInformation");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "SystemInformationLength");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "ReturnLength");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%lu", SystemInformationClass);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", SystemInformation);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%lu", SystemInformationLength);
	if (ReturnLength != NULL) {
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%p(=%lu)", ReturnLength, *ReturnLength);
	}
	else {
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "NULL");
	}

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);;
}

//从指定进程的虚拟地址空间中读取内存数据

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
	// 初始化日志结构体
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = NTREADVIRTUALMEMORY;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 5;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "ProcessHandle");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "BaseAddress");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "Buffer");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "BufferSize");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "NumberOfBytesRead");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", ProcessHandle);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", BaseAddress);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", Buffer);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%Iu", BufferSize);  // SIZE_T 使用 %Iu

	if (NumberOfBytesRead != NULL) {
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%p(=%Iu)", NumberOfBytesRead, *NumberOfBytesRead);
	}
	else {
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "NULL");
	}

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}


//---------------------------------------------- main函数 ------------------------------------------------

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