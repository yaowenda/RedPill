#include <windows.h>  
#include <detours.h>  
#include <stdio.h>
#include <string>
#define NAME_BUFFER_SIZE 30 // 根据实际定义修改
#define VALUE_BUFFER_SIZE 70 // 根据实际定义修改
#define  MESSAGEBOXW 1
#define CREATEFILEW 2


struct info {
    int type, argNum;
    SYSTEMTIME time; //记录调用时间
    char argName[10][30] = { 0 }; // 参数名（最多10个，每个最多30个字符）
    char argValue[10][70] = { 0 };

};

info sendInfo;

// 全局变量
LPVOID pBuf = NULL;
HANDLE hMapFile = NULL;
//HANDLE hSemaphore = NULL;

// 打开或创建命名信号量（建议在 DLL 初始化时执行一次）
HANDLE hSemaphore = OpenSemaphore(SEMAPHORE_ALL_ACCESS, FALSE, L"Global\\MySharedSemaphore");

//初始化共享内存
void InitSharedMemory()
{   //CreateFileMappingW 创建或打开一个命名内存映射文件对象
    hMapFile = CreateFileMappingW(
        INVALID_HANDLE_VALUE, //传入这个参数，表示不打算映射一个实际的文件，而是创建一个仅存在于系统内存中的共享内存区域
        NULL,
        PAGE_READWRITE,//这块内存可读写
        0,
        4096,// 字节 4KB
        L"MySharedMemory");

    // MapViewOfFile 将内存映射文件对象的全部或一部分映射到调用进程的地址空间中
    // 一旦映射成功，返回一个指向该映射区域的指针，进程可以像访问自己的内存一样，通过此指针直接读写该内存区域
    if (hMapFile != NULL)
    {
        pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        // hMapFile是CreateFileMappingW返回的 两个0：从起始位置开始映射 最后一个0：映射整个内存映射文件对象
    }

}


//  写入共享内存
void WriteToSharedMemory(const info& data)
{
    if (pBuf)//共享内存成功映射到当前进程的地址空间
    {
        memcpy(pBuf, &data, sizeof(info));
    }
    // 通知主程序已经写入完成
    if (hSemaphore) {
        ReleaseSemaphore(hSemaphore, 1, NULL);  // 增加信号量计数
    }
}

//定义函数指针指向原始MessageBoxW函数
static int (WINAPI* OldMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) = MessageBoxW;

//定义一个新的MessageBoxW函数
extern "C" int WINAPI NewMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    //sendInfo.type = MESSAGEBOXW;
    //GetLocalTime(&sendInfo.time);
    //sendInfo.argNum = 4;
    ////参数名
    //sprintf_s(sendInfo.argName[0], NAME_BUFFER_SIZE, "hWnd");
    //sprintf_s(sendInfo.argName[1], NAME_BUFFER_SIZE, "lpText");
    //sprintf_s(sendInfo.argName[2], NAME_BUFFER_SIZE, "lpCaption");
    //sprintf_s(sendInfo.argName[3], NAME_BUFFER_SIZE, "uType");
    //// 参数值
    //sprintf_s(sendInfo.argValue[0], VALUE_BUFFER_SIZE, "%08X", hWnd);
    //sprintf_s(sendInfo.argValue[1], VALUE_BUFFER_SIZE, "%s", lpText);
    //sprintf_s(sendInfo.argValue[2], VALUE_BUFFER_SIZE, "%s", lpCaption);
    //sprintf_s(sendInfo.argValue[3], VALUE_BUFFER_SIZE, "%08X", uType);

    printf("hook.dll输出：调用了MessageBoxW函数");

    /*WriteToSharedMemory(sendInfo);
    ReleaseSemaphore(hSemaphore, 1, NULL);*/

    //调用原始MessageBoxW函数
    return OldMessageBoxW(hWnd, lpText, lpCaption, uType);
}

//定义函数指针指向原始CreateFileW函数，该API用于打开文件
static HANDLE(WINAPI* OldCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;

//定义自己的新的CreateFileW函数
extern "C" HANDLE WINAPI NEWCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    sendInfo.type = 2;
    GetLocalTime(&sendInfo.time);
    sendInfo.argNum = 7;
    //参数名
    sprintf_s(sendInfo.argName[0], NAME_BUFFER_SIZE, "lpFileName");
    sprintf_s(sendInfo.argName[1], NAME_BUFFER_SIZE, "dwDesiredAccess");
    sprintf_s(sendInfo.argName[2], NAME_BUFFER_SIZE, "dwShareMode");
    sprintf_s(sendInfo.argName[3], NAME_BUFFER_SIZE, "lpSecurityAttributes");
    sprintf_s(sendInfo.argName[4], NAME_BUFFER_SIZE, "dwCreationDisposition");
    sprintf_s(sendInfo.argName[5], NAME_BUFFER_SIZE, "dwFlagsAndAttributes");
    sprintf_s(sendInfo.argName[6], NAME_BUFFER_SIZE, "hTemplateFile");
    //参数值
    sprintf_s(sendInfo.argValue[0], VALUE_BUFFER_SIZE, "%ls", lpFileName);
    sprintf_s(sendInfo.argValue[1], VALUE_BUFFER_SIZE, "%lu", dwDesiredAccess);
    sprintf_s(sendInfo.argValue[2], VALUE_BUFFER_SIZE, "%lu", dwShareMode);
    sprintf_s(sendInfo.argValue[3], VALUE_BUFFER_SIZE, "%p", lpSecurityAttributes);
    sprintf_s(sendInfo.argValue[4], VALUE_BUFFER_SIZE, "%lu", dwCreationDisposition);
    sprintf_s(sendInfo.argValue[5], VALUE_BUFFER_SIZE, "%lu", dwFlagsAndAttributes);
    sprintf_s(sendInfo.argValue[6], VALUE_BUFFER_SIZE, "%p", hTemplateFile);

    WriteToSharedMemory(sendInfo);

    return OldCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);


}

//DWORD WINAPI InitThread(LPVOID) {
//    OutputDebugStringA("[hook.dll] InitSharedMemory\n");
//    InitSharedMemory();
//
//    OutputDebugStringA("[hook.dll] 开始 Detour Hook\n");
//    DetourTransactionBegin();
//    DetourUpdateThread(GetCurrentThread());
//    DetourAttach(&(PVOID&)OldMessageBoxW, NewMessageBoxW);
//    LONG err = DetourTransactionCommit();
//    if (err != NO_ERROR) {
//        char buf[128];
//        sprintf_s(buf, "Hook 失败，错误码: %ld\n", err);
//        OutputDebugStringA(buf);
//    }
//    else {
//        OutputDebugStringA("[hook.dll] Hook 成功！\n");
//    }
//
//    return 0;
//}
/*
    在DllMain函数中不要调用LoadLibrary、CreateThread、WaitForSingleObject、EnterCriticalSection、DetourAttach
    等会导致加载器锁定的函数
*/
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OldMessageBoxW, NewMessageBoxW);
        DetourTransactionCommit();
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        // 一般可以直接执行卸载操作
        //与 Hook 安装逻辑完全对称，只是调用 DetourDetach 代替 DetourAttach。
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OldMessageBoxW, NewMessageBoxW);
        DetourTransactionCommit();
    }
    return TRUE;
}


