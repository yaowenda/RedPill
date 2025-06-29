#include <windows.h>  
#include <detours.h>  
#include <stdio.h>
#include <string>
#define NAME_BUFFER_SIZE 30 // ����ʵ�ʶ����޸�
#define VALUE_BUFFER_SIZE 70 // ����ʵ�ʶ����޸�
#define  MESSAGEBOXW 1
#define CREATEFILEW 2


struct info {
    int type, argNum;
    SYSTEMTIME time; //��¼����ʱ��
    char argName[10][30] = { 0 }; // �����������10����ÿ�����30���ַ���
    char argValue[10][70] = { 0 };

};

info sendInfo;

// ȫ�ֱ���
LPVOID pBuf = NULL;
HANDLE hMapFile = NULL;
//HANDLE hSemaphore = NULL;

// �򿪻򴴽������ź����������� DLL ��ʼ��ʱִ��һ�Σ�
HANDLE hSemaphore = OpenSemaphore(SEMAPHORE_ALL_ACCESS, FALSE, L"Global\\MySharedSemaphore");

//��ʼ�������ڴ�
void InitSharedMemory()
{   //CreateFileMappingW �������һ�������ڴ�ӳ���ļ�����
    hMapFile = CreateFileMappingW(
        INVALID_HANDLE_VALUE, //���������������ʾ������ӳ��һ��ʵ�ʵ��ļ������Ǵ���һ����������ϵͳ�ڴ��еĹ����ڴ�����
        NULL,
        PAGE_READWRITE,//����ڴ�ɶ�д
        0,
        4096,// �ֽ� 4KB
        L"MySharedMemory");

    // MapViewOfFile ���ڴ�ӳ���ļ������ȫ����һ����ӳ�䵽���ý��̵ĵ�ַ�ռ���
    // һ��ӳ��ɹ�������һ��ָ���ӳ�������ָ�룬���̿���������Լ����ڴ�һ����ͨ����ָ��ֱ�Ӷ�д���ڴ�����
    if (hMapFile != NULL)
    {
        pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        // hMapFile��CreateFileMappingW���ص� ����0������ʼλ�ÿ�ʼӳ�� ���һ��0��ӳ�������ڴ�ӳ���ļ�����
    }

}


//  д�빲���ڴ�
void WriteToSharedMemory(const info& data)
{
    if (pBuf)//�����ڴ�ɹ�ӳ�䵽��ǰ���̵ĵ�ַ�ռ�
    {
        memcpy(pBuf, &data, sizeof(info));
    }
    // ֪ͨ�������Ѿ�д�����
    if (hSemaphore) {
        ReleaseSemaphore(hSemaphore, 1, NULL);  // �����ź�������
    }
}

//���庯��ָ��ָ��ԭʼMessageBoxW����
static int (WINAPI* OldMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) = MessageBoxW;

//����һ���µ�MessageBoxW����
extern "C" int WINAPI NewMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    //sendInfo.type = MESSAGEBOXW;
    //GetLocalTime(&sendInfo.time);
    //sendInfo.argNum = 4;
    ////������
    //sprintf_s(sendInfo.argName[0], NAME_BUFFER_SIZE, "hWnd");
    //sprintf_s(sendInfo.argName[1], NAME_BUFFER_SIZE, "lpText");
    //sprintf_s(sendInfo.argName[2], NAME_BUFFER_SIZE, "lpCaption");
    //sprintf_s(sendInfo.argName[3], NAME_BUFFER_SIZE, "uType");
    //// ����ֵ
    //sprintf_s(sendInfo.argValue[0], VALUE_BUFFER_SIZE, "%08X", hWnd);
    //sprintf_s(sendInfo.argValue[1], VALUE_BUFFER_SIZE, "%s", lpText);
    //sprintf_s(sendInfo.argValue[2], VALUE_BUFFER_SIZE, "%s", lpCaption);
    //sprintf_s(sendInfo.argValue[3], VALUE_BUFFER_SIZE, "%08X", uType);

    printf("hook.dll�����������MessageBoxW����");

    /*WriteToSharedMemory(sendInfo);
    ReleaseSemaphore(hSemaphore, 1, NULL);*/

    //����ԭʼMessageBoxW����
    return OldMessageBoxW(hWnd, lpText, lpCaption, uType);
}

//���庯��ָ��ָ��ԭʼCreateFileW��������API���ڴ��ļ�
static HANDLE(WINAPI* OldCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;

//�����Լ����µ�CreateFileW����
extern "C" HANDLE WINAPI NEWCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    sendInfo.type = 2;
    GetLocalTime(&sendInfo.time);
    sendInfo.argNum = 7;
    //������
    sprintf_s(sendInfo.argName[0], NAME_BUFFER_SIZE, "lpFileName");
    sprintf_s(sendInfo.argName[1], NAME_BUFFER_SIZE, "dwDesiredAccess");
    sprintf_s(sendInfo.argName[2], NAME_BUFFER_SIZE, "dwShareMode");
    sprintf_s(sendInfo.argName[3], NAME_BUFFER_SIZE, "lpSecurityAttributes");
    sprintf_s(sendInfo.argName[4], NAME_BUFFER_SIZE, "dwCreationDisposition");
    sprintf_s(sendInfo.argName[5], NAME_BUFFER_SIZE, "dwFlagsAndAttributes");
    sprintf_s(sendInfo.argName[6], NAME_BUFFER_SIZE, "hTemplateFile");
    //����ֵ
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
//    OutputDebugStringA("[hook.dll] ��ʼ Detour Hook\n");
//    DetourTransactionBegin();
//    DetourUpdateThread(GetCurrentThread());
//    DetourAttach(&(PVOID&)OldMessageBoxW, NewMessageBoxW);
//    LONG err = DetourTransactionCommit();
//    if (err != NO_ERROR) {
//        char buf[128];
//        sprintf_s(buf, "Hook ʧ�ܣ�������: %ld\n", err);
//        OutputDebugStringA(buf);
//    }
//    else {
//        OutputDebugStringA("[hook.dll] Hook �ɹ���\n");
//    }
//
//    return 0;
//}
/*
    ��DllMain�����в�Ҫ����LoadLibrary��CreateThread��WaitForSingleObject��EnterCriticalSection��DetourAttach
    �Ȼᵼ�¼����������ĺ���
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
        // һ�����ֱ��ִ��ж�ز���
        //�� Hook ��װ�߼���ȫ�Գƣ�ֻ�ǵ��� DetourDetach ���� DetourAttach��
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OldMessageBoxW, NewMessageBoxW);
        DetourTransactionCommit();
    }
    return TRUE;
}


