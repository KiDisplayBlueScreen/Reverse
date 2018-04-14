#include <Windows.h>
#include <Ntsecapi.h>
#include <math.h>
typedef LONG KPRIORITY;
typedef WORD SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;
BOOLEAN ARGUMENT_PRESENT(CHAR *ArgumentPointer);
LONG StringToNumber(PCHAR pString);
ULONG StringToUlong(PCHAR pString, int Length);
LONG StringToLong(PCHAR pString, int Length);
#define RTL_MAX_DRIVE_LETTERS 32
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
BOOLEAN ARGUMENT_PRESENT(CHAR *ArgumentPointer)
{
	return (ArgumentPointer == NULL) ? 0 : 1;
}
typedef struct _NT_TIB
{
	struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
	union
	{
		PVOID FiberData;
		DWORD Version;
	};
	PVOID ArbitraryUserPointer;
	struct _NT_TIB *Self;
};
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
typedef struct _VM_COUNTERS
{
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;
typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
typedef enum _KWAIT_REASON
{
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	MaximumWaitReason
} KWAIT_REASON;
typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG    WaitTime;
	PVOID    StartAddress;
	CLIENT_ID   ClientID;
	KPRIORITY   Priority;
	KPRIORITY   BasePriority;
	ULONG    ContextSwitchCount;
	ULONG    ThreadState;
	KWAIT_REASON  WaitReason;
	ULONG    Reserved;
}SYSTEM_THREADS, *PSYSTEM_THREADS;
typedef struct _SYSTEM_PROCESSES
{
	ULONG          NextEntryDelta;
	ULONG          ThreadCount;
	ULONG          Reserved1[6];
	LARGE_INTEGER  CreateTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY      BasePriority;
	HANDLE         ProcessId;
	HANDLE         InheritedFromProcessId;
	ULONG          HandleCount;
	ULONG          Reserved2[2];
	VM_COUNTERS    VmCounters;
	IO_COUNTERS    IoCounters;
	SYSTEM_THREADS Threads[1];
}SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;
typedef struct _SYSTEM_THREAD_INFORMATION
{
	ULONGLONG KernelTime;
	ULONGLONG UserTime;
	ULONGLONG CreateTime;
	ULONG WaitTime;
	ULONG Reserved1;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG State;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _SECURITY_DESCRIPTOR
{
	BYTE Revision;
	BYTE Sbz1;
	SECURITY_DESCRIPTOR_CONTROL Control;
	PSID Owner;
	PSID Group;
	PACL Sacl;
	PACL Dacl;
};
typedef struct _ACE
{
	ACE_HEADER Header;
	ACCESS_MASK AccessMask;
};
typedef struct _PEB_LDR_DATA
{
	ULONG Length; // +0x00
	BOOLEAN Initialized; // +0x04
	PVOID SsHandle; // +0x08
	LIST_ENTRY InLoadOrderModuleList; // +0x0c
	LIST_ENTRY InMemoryOrderModuleList; // +0x14
	LIST_ENTRY InInitializationOrderModuleList;// +0x1c
} PEB_LDR_DATA, *PPEB_LDR_DATA; // +0x24
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct _CURDIR
{
		UNICODE_STRING DosPath;
	    HANDLE Handle;
} CURDIR, *PCURDIR;
typedef struct RTL_DRIVE_LETTER_CURDIR
{
	   USHORT                    Flags;
	   USHORT                    Length;
	   ULONG                      TimeStamp;
	   UNICODE_STRING     DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	HANDLE ConsoleHandle;
	ULONG  ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;
	CURDIR CurrentDirectory;        // ProcessParameters
	UNICODE_STRING DllPath;         // ProcessParameters
	UNICODE_STRING ImagePathName;   // ProcessParameters
	UNICODE_STRING CommandLine;     // ProcessParameters
	PVOID Environment;              // NtAllocateVirtualMemory
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;     // ProcessParameters
	UNICODE_STRING DesktopInfo;     // ProcessParameters
	UNICODE_STRING ShellInfo;       // ProcessParameters
	UNICODE_STRING RuntimeData;     // ProcessParameters
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[RTL_MAX_DRIVE_LETTERS];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,              // 0        Y        N
	SystemProcessorInformation,          // 1        Y        N
	SystemPerformanceInformation,        // 2        Y        N
	SystemTimeOfDayInformation,          // 3        Y        N
	SystemNotImplemented1,               // 4        Y        N
	SystemProcessesAndThreadsInformation, // 5       Y        N
	SystemCallCounts,                    // 6        Y        N
	SystemConfigurationInformation,      // 7        Y        N
	SystemProcessorTimes,                // 8        Y        N
	SystemGlobalFlag,                    // 9        Y        Y
	SystemNotImplemented2,               // 10       Y        N
	SystemModuleInformation,             // 11       Y        N
	SystemLockInformation,               // 12       Y        N
	SystemNotImplemented3,               // 13       Y        N
	SystemNotImplemented4,               // 14       Y        N
	SystemNotImplemented5,               // 15       Y        N
	SystemHandleInformation,             // 16       Y        N
	SystemObjectInformation,             // 17       Y        N
	SystemPagefileInformation,           // 18       Y        N
	SystemInstructionEmulationCounts,    // 19       Y        N
	SystemInvalidInfoClass1,             // 20
	SystemCacheInformation,              // 21       Y        Y
	SystemPoolTagInformation,            // 22       Y        N
	SystemProcessorStatistics,           // 23       Y        N
	SystemDpcInformation,                // 24       Y        Y
	SystemNotImplemented6,               // 25       Y        N
	SystemLoadImage,                     // 26       N        Y
	SystemUnloadImage,                   // 27       N        Y
	SystemTimeAdjustment,                // 28       Y        Y
	SystemNotImplemented7,               // 29       Y        N
	SystemNotImplemented8,               // 30       Y        N
	SystemNotImplemented9,               // 31       Y        N
	SystemCrashDumpInformation,          // 32       Y        N
	SystemExceptionInformation,          // 33       Y        N
	SystemCrashDumpStateInformation,     // 34       Y        Y/N
	SystemKernelDebuggerInformation,     // 35       Y        N
	SystemContextSwitchInformation,      // 36       Y        N
	SystemRegistryQuotaInformation,      // 37       Y        Y
	SystemLoadAndCallImage,              // 38       N        Y
	SystemPrioritySeparation,            // 39       N        Y
	SystemNotImplemented10,              // 40       Y        N
	SystemNotImplemented11,              // 41       Y        N
	SystemInvalidInfoClass2,             // 42
	SystemInvalidInfoClass3,             // 43
	SystemTimeZoneInformation,           // 44       Y        N
	SystemLookasideInformation,          // 45       Y        N
	SystemSetTimeSlipEvent,              // 46       N        Y
	SystemCreateSession,                 // 47       N        Y
	SystemDeleteSession,                 // 48       N        Y
	SystemInvalidInfoClass4,             // 49
	SystemRangeStartInformation,         // 50       Y        N
	SystemVerifierInformation,           // 51       Y        Y
	SystemAddVerifier,                   // 52       N        Y
	SystemSessionProcessesInformation    // 53       Y        N
} SYSTEM_INFORMATION_CLASS;
typedef struct _SYSTEM_HANDLE_INFORMATION1
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION1, *PSYSTEM_HANDLE_INFORMATION1;
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
typedef struct _OBJECT_HANDLE_INFORMATION
{
	ULONG HandleAttributes;
	ACCESS_MASK GrantedAccess;
} OBJECT_HANDLE_INFORMATION, *POBJECT_HANDLE_INFORMATION;
typedef enum _SECURITY_IMPERSONATION_LEVEL
{
	SecurityAnonymous,
	SecurityIdentification,
	SecurityImpersonation,
	SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;
typedef struct _SECURITY_SUBJECT_CONTEXT
{
	PACCESS_TOKEN                ClientToken;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	PACCESS_TOKEN                PrimaryToken;
	PVOID                                 ProcessAuditId;
} SECURITY_SUBJECT_CONTEXT, *PSECURITY_SUBJECT_CONTEXT;
typedef struct _INITIAL_PRIVILEGE_SET
{
	ULONG PrivilegeCount;
	ULONG Control;
	LUID_AND_ATTRIBUTES Privilege[3];
} INITIAL_PRIVILEGE_SET, *PINITIAL_PRIVILEGE_SET;
typedef struct _ACCESS_STATE
{
	LUID                          OperationID;
	BOOLEAN                  SecurityEvaluated;
	BOOLEAN                  GenerateAudit;
	BOOLEAN                  GenerateOnClose;
	BOOLEAN                  PrivilegesAllocated;
	ULONG                      Flags;
	ACCESS_MASK          RemainingDesiredAccess;
	ACCESS_MASK          PreviouslyGrantedAccess;
	ACCESS_MASK          OriginalDesiredAccess;
	SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
	PSECURITY_DESCRIPTOR         SecurityDescriptor;
	PVOID                       AuxData;
	union
	{
		INITIAL_PRIVILEGE_SET InitialPrivilegeSet;
		PRIVILEGE_SET         PrivilegeSet;
	} Privileges;
	BOOLEAN                  AuditPrivileges;
	UNICODE_STRING     ObjectName;
	UNICODE_STRING     ObjectTypeName;
} ACCESS_STATE, *PACCESS_STATE;
LONG StringToNumber(PCHAR pString)
{
	PBYTE p = (PBYTE)pString;
	int Flags = 0;
	int i = strlen(pString);
	for (; i > 0; i--)
	{
		if (*p == 0x2D)
		{
			p++;
			Flags = 1;
			continue;
		}
		if (*p < 0x30 || *p>0x39)
		{
			return 0;
		}
		p++;
	}
	i = strlen(pString);
	if (Flags == 0)
	{
		return StringToUlong(pString, i);
	}

	else return StringToLong(pString, i);

}

ULONG StringToUlong(PCHAR pString, int Length)
{
	PBYTE p = (PBYTE)pString;
	ULONG x = 0;
	for (; Length > 0; Length--)
	{
		x = x + (*p - 0x30)*pow(10, Length - 1);
		p++;
	}
	return x;
}

LONG StringToLong(PCHAR pString, int Length)
{
	PBYTE p = (PBYTE)pString + 1;
	LONG x = 0;
	for (; Length - 1>0; Length--)
	{
		x = x + (*p - 0x30)*pow(10, Length - 2);
		p++;
	}
	return (~x + 1);
}
PBYTE GetDWORDBit(DWORD Dest)
{
	BYTE Return[8] = { 0 };
	__asm
	{
		mov eax, Dest
		and eax, 0xF0000000
		shr eax, 0x1C
		mov Return[0], al

		mov eax, Dest
		and eax, 0xF000000
		sar eax, 0x18
		mov Return[1], al

		mov eax, Dest
		and eax, 0xF00000
		sar  eax, 0x14
		mov Return[2], al


		mov eax, Dest
		and eax, 0xF0000
		sar  eax, 0x10
		mov Return[3], al

		mov eax, Dest
		and eax, 0xF000
		sar  eax, 0xC
		mov Return[4], al

		mov eax, Dest
		and eax, 0xF00
		sar  eax, 0x8
		mov Return[5], al

		mov eax, Dest
		and eax, 0xF0
		sar  eax, 0x4
		mov Return[6], al


		mov eax, Dest
		and eax, 0xF
		mov Return[7], al
	}
	return Return;
}