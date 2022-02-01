#include "Global.h"

//tmp hook data
PVOID* xKdEnumerateDebuggingDevicesPtr;
PVOID xKdEnumerateDebuggingDevicesVal;

#define GameProc "TestEnvironment.exe"

namespace Win32K {
	ULONG64 gafAsyncKeyState;
	ULONG64 gafAsyncKeyStateRecentDown;
}

unsigned __int16 GetAsyncKeyState(unsigned int a1)
{
	__int16 result;

	if (a1 >= 0x100) { result = 0; }
	else
	{
		unsigned __int64 v1 = (unsigned __int8)a1;
		unsigned __int64 v2 = (unsigned __int64)(unsigned __int8)a1 >> 3;

		__int16 v4 = 0;
		unsigned int v3 = v1 & 7;

		int v5 = *(unsigned __int8*)(v2 + EPtr(Win32K::gafAsyncKeyStateRecentDown));

		if (_bittest((LONG*)&v5, v3)) {
			v4 = 1;
			*(UCHAR*)(v2 + EPtr(Win32K::gafAsyncKeyStateRecentDown)) = v5 & ~(1 << v3);
		}

		result = v4 | 0x8000;
		if (!(*((UCHAR*)EPtr(Win32K::gafAsyncKeyState) + (v1 >> 2)) & (unsigned __int8)(1 << (2 * (v1 & 3)))))
			result = v4;
	}

	return result;
}

PVOID Kbase2;
typedef NTSTATUS(__fastcall* ZwReleaseMutantFn)(HANDLE, PLONG);

class OSRender
{
private:
	PVOID OverlayBase;
	PVOID PaintBuffer;
	HANDLE InputMutex;
	HANDLE PaintCmdMutex;
	HANDLE InputAvailable;
	ZwReleaseMutantFn ZwReleaseMutant;

public:
	OSRender(PVOID OverlayBase1) {
		OverlayBase = OverlayBase1;
		ZwReleaseMutant = (ZwReleaseMutantFn)RVA(FindPatternSect(Kbase2, "PAGE", "48 83 F9 FF 74 07") + 8, 5);
		auto paintCmd = *(ULONG64*)(RVA(FindPatternSect(OverlayBase, ".text", "48 89 05 ? ? ? ? BA ? ? ? ? 48"), 7));
		auto inputCmd = *(ULONG64*)(RVA(FindPatternSect(OverlayBase, ".text", "48 8B 0D ? ? ? ? 41 B8 ? ? ? ? 48 8D"), 7));
		PaintCmdMutex = *(HANDLE*)(*(ULONG64*)(paintCmd + 0x108) + 0x10);
		PaintBuffer = *(PVOID*)(*(ULONG64*)(paintCmd + 0x110) + 0x10);
		InputMutex = *(HANDLE*)(*(ULONG64*)(inputCmd + 0x108) + 0x10);
		InputAvailable = *(HANDLE*)(*(ULONG64*)(inputCmd + 0x120) + 0x10);
	}

	void WaitLockFrame() {
		HANDLE handles[] = { PaintCmdMutex, InputMutex, InputAvailable };
		LARGE_INTEGER time; time.QuadPart = 0;
		ZwWaitForMultipleObjects(3, handles, WaitAll, 0, nullptr);
	}

	void PutCmd(const void* source, DWORD size)
	{
		struct StreamHeader
		{
			DWORD BufferStartIndex;
			DWORD BufferEndIndex;
			DWORD BufferCapacity;
			DWORD BufferSize;
		};
		auto Header = (StreamHeader*)PaintBuffer;
		auto Buffer = (char*)Header + sizeof(StreamHeader);

		//if (source == nullptr)
		//{
		//}	//throw std::invalid_argument("Source is null.");
		//
		//if (size > GetUnusedCapacity())
		//{
		//}	//throw std::out_of_range("Size exceeds the unused capacity of the buffer.");

		char* destination;

		//dp(Header->BufferSize);

		Header->BufferSize += size;

		// write is wrapped
		if (size > Header->BufferStartIndex)
		{
			DWORD postwrapSize = size - Header->BufferStartIndex;
			// update size
			size = Header->BufferStartIndex;
			// wrap buffer start index
			Header->BufferStartIndex = Header->BufferCapacity - postwrapSize;

			memcpy(Buffer + Header->BufferStartIndex, source, postwrapSize);
			// update source
			source = (char*)source + postwrapSize;
			// finish write at start
			destination = Buffer;
		}

		else
		{
			Header->BufferStartIndex -= size;
			destination = Buffer + Header->BufferStartIndex;
		}

		memcpy(destination, source, size);
	}

	void ReleaseFrame() {
		ZwReleaseMutant(InputMutex, 0);
		ZwReleaseMutant(PaintCmdMutex, 0);
	}
};

//meme thread
NTSTATUS MainThread()
{
	//unhook kernel hook
	_InterlockedExchangePointer(xKdEnumerateDebuggingDevicesPtr, xKdEnumerateDebuggingDevicesVal);
	xKdEnumerateDebuggingDevicesPtr = nullptr; xKdEnumerateDebuggingDevicesVal = nullptr;

	//create gui thread context
	auto hNtdll = GetUserModuleBase(ImpCall(IoGetCurrentProcess), E("user32"));
	auto CallBack = GetProcAdress(hNtdll, E("GetForegroundWindow"));
	CallUserMode(CallBack);

	//get target process
	PVOID OverlayBase;
	auto TargetProc = GetProcessWModule(E(GameProc), E("gameoverlayrenderer64"), &OverlayBase);
	
	//find steam overlay
	OSRender renderSteam(OverlayBase);

	int w = 400;
	int h = 400;

	DWORD size = w * h * 4;
	DWORD textureVersion = 0;
	auto pBuff111 = UAlloc(size);

	ByteRender BR;
	BR.Setup(w, h, pBuff111);
	DecompressFont();

	while (true)
	{
		renderSteam.WaitLockFrame();

		struct
		{
			DWORD renderCommand;
			int x0;
			int y0;
			int x1;
			int y1;
			float u0;
			float v0;
			float u1;
			float v1;
			float uk4;
			DWORD colorStart;
			DWORD colorEnd; // unused if gradient direction is set to none
			DWORD gradientDirection;
			DWORD textureId;
		} drawTexturedRect =
		{
		3, // render command
		0,
		0,
		w,
		h,
		0.0f,
		0.0f,
		1.0f,
		1.0f,
		1.0f,
		0xFFFFFFFF,
		0xFFFFFFFF,
		3, // none
		1337
		};
		renderSteam.PutCmd(&drawTexturedRect, sizeof(drawTexturedRect));
		
		BR.Clear();

		BR.FillRectangle({ 100,100 }, { 100,100 }, FColor(255, 0, 0));
		BR.String({ 100,100 }, L"Hi Im ~ @ FACE GGEZ ¸ ¨!", 1);


		//rctx.NewFrame(w, h, E(L"Calibri"), 48, 1);
		//rctx.String(100, 100, L"FACE", TA_CENTER, RGB(255, 0, 0));
		//rctx.EndFrame((PBYTE)pBuff111);


		renderSteam.PutCmd((PBYTE)pBuff111, size);
		struct
		{
			DWORD renderCommand;
			DWORD textureId;
			DWORD version;
			BOOL fullUpdate;
			DWORD size;
			DWORD width;
			DWORD height;
			DWORD x;
			DWORD y;
		} loadTexture =
		{
			1, // render command
			1337, // id
			++textureVersion,
			1, // full update
			size, // size
			w, // width
			h, // height
			0,
			0
		};

		// command
		renderSteam.PutCmd(&loadTexture, sizeof(loadTexture));
		renderSteam.ReleaseFrame();
	}

	//sp("end cheat!!!");
	DetachFromProcess(TargetProc);

	//lol return 1!!
	return STATUS_NOT_IMPLEMENTED;
}

#pragma code_seg(push)
#pragma code_seg("INIT")

//create thread meme
bool SetupKernelThread(PVOID KBase, PVOID ThreadStartAddr)
{
	//get thread fake start address
	PVOID hMsVCRT = nullptr;
	auto Process = GetProcessWModule(E("explorer.exe"), E("msvcrt"), &hMsVCRT);
	auto FakeStartAddr = (PUCHAR)GetProcAdress(hMsVCRT, E("_endthreadex")) + 0x30;

	auto win32k = GetKernelModuleBase(E("win32kbase.sys"));
	Win32K::gafAsyncKeyState = (ULONG64)EPtr(GetProcAdress(win32k, E("gafAsyncKeyState")));
	Win32K::gafAsyncKeyStateRecentDown = (ULONG64)EPtr(GetProcAdress(win32k, E("gafAsyncKeyStateRecentDown")));

	//get usermode func
	auto Var = UAlloc(0x1000); HANDLE Thread = nullptr;
	auto hNtdll = GetUserModuleBase(Process, E("ntdll"));
	auto CallBack = GetProcAdress(hNtdll, E("NtQueryAuxiliaryCounterFrequency"));

	//set kernel hook
	xKdEnumerateDebuggingDevicesPtr = (PVOID*)RVA((ULONG64)EPtr(KeQueryAuxiliaryCounterFrequencyFn) + 4, 7);
	xKdEnumerateDebuggingDevicesVal = _InterlockedExchangePointer(xKdEnumerateDebuggingDevicesPtr, ThreadStartAddr);

	//create new thread
	CLIENT_ID Cid;
	ImpCall(RtlCreateUserThread, ZwCurrentProcess(), nullptr, false, 0, 0, 0, CallBack, Var, &Thread, &Cid);

	if (Thread)
	{
		//close useless handle
		ImpCall(ZwClose, Thread);

		//spoof thread start address
		PETHREAD EThread;
		ImpCall(PsLookupThreadByThreadId, Cid.UniqueThread, &EThread);
		auto StartAddrOff = *(USHORT*)(FindPatternSect(KBase, E("PAGE"), E("48 89 86 ? ? ? ? 48 8B 8C")) + 3);
		*(PVOID*)((ULONG64)EThread + StartAddrOff/*Win32StartAddress*/) = FakeStartAddr;
		ImpCall(ObfDereferenceObject, EThread);

		//wait exec kernel callback
		while (xKdEnumerateDebuggingDevicesPtr && xKdEnumerateDebuggingDevicesVal) {
			Sleep(10);
		}
	}

	//cleanup
	UFree(Var);
	DetachFromProcess(Process);

	//ret create status
	return (bool)Thread;
}

//driver entry point
NTSTATUS DriverEntry(PVOID a1, PVOID KBase)
{
	//import set
	ImpSet(IoIs32bitProcess);
	ImpSet(PsGetProcessWow64Process);
	ImpSet(ExAllocatePoolWithTag);
	ImpSet(ExFreePoolWithTag);
	ImpSet(IoGetCurrentProcess);
	ImpSet(KeAttachProcess);
	ImpSet(KeDelayExecutionThread);
	ImpSet(KeDetachProcess);
	ImpSet(KeEnterGuardedRegion);
	ImpSet(KeLeaveGuardedRegion);
	ImpSet(KeQueryAuxiliaryCounterFrequency);
	ImpSet(KeUserModeCallback);
	ImpSet(MmIsAddressValid);
	ImpSet(ObfDereferenceObject);
	ImpSet(PsAcquireProcessExitSynchronization);
	ImpSet(PsGetProcessPeb);
	ImpSet(PsLookupProcessByProcessId);
	ImpSet(PsLookupThreadByThreadId);
	ImpSet(PsReleaseProcessExitSynchronization);
	ImpSet(RtlCreateUserThread);
	ImpSet(ZwAllocateVirtualMemory);
	ImpSet(ZwClose);
	ImpSet(ZwFreeVirtualMemory);
	ImpSet(ZwQuerySystemInformation);
	ImpSet(ZwQueryVirtualMemory); 
	ImpSet(MmSecureVirtualMemory);
	ImpSet(ZwProtectVirtualMemory);
	ImpSet(ZwQueryObject);

	Kbase2 = KBase;

	//create kernel usermode thread
	SetupKernelThread(KBase, MainThread);

	return STATUS_SUCCESS;
}

#pragma code_seg(pop)