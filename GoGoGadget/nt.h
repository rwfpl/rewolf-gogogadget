/**
*
* GoGoGadget - kernel exploitation helper class
*
* Copyright (c) 2016 ReWolf
* http://blog.rewolf.pl/
* http://blog.rewolf.pl/blog/?p=1739
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published
* by the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/
#pragma once

namespace nt
{
	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation,
		SystemProcessorInformation,             // obsolete...delete
		SystemPerformanceInformation,
		SystemTimeOfDayInformation,
		SystemPathInformation,
		SystemProcessInformation,
		SystemCallCountInformation,
		SystemDeviceInformation,
		SystemProcessorPerformanceInformation,
		SystemFlagsInformation,
		SystemCallTimeInformation,
		SystemModuleInformation,
		SystemLocksInformation,
		SystemStackTraceInformation,
		SystemPagedPoolInformation,
		SystemNonPagedPoolInformation,
		SystemHandleInformation,
		SystemObjectInformation,
		SystemPageFileInformation,
		SystemVdmInstemulInformation,
		SystemVdmBopInformation,
		SystemFileCacheInformation,
		SystemPoolTagInformation,
		SystemInterruptInformation,
		SystemDpcBehaviorInformation,
		SystemFullMemoryInformation,
		SystemLoadGdiDriverInformation,
		SystemUnloadGdiDriverInformation,
		SystemTimeAdjustmentInformation,
		SystemSummaryMemoryInformation,
		SystemMirrorMemoryInformation,
		SystemPerformanceTraceInformation,
		SystemObsolete0,
		SystemExceptionInformation,
		SystemCrashDumpStateInformation,
		SystemKernelDebuggerInformation,
		SystemContextSwitchInformation,
		SystemRegistryQuotaInformation,
		SystemExtendServiceTableInformation,
		SystemPrioritySeperation,
		SystemVerifierAddDriverInformation,
		SystemVerifierRemoveDriverInformation,
		SystemProcessorIdleInformation,
		SystemLegacyDriverInformation,
		SystemCurrentTimeZoneInformation,
		SystemLookasideInformation,
		SystemTimeSlipNotification,
		SystemSessionCreate,
		SystemSessionDetach,
		SystemSessionInformation,
		SystemRangeStartInformation,
		SystemVerifierInformation,
		SystemVerifierThunkExtend,
		SystemSessionProcessInformation,
		SystemLoadGdiDriverInSystemSpace,
		SystemNumaProcessorMap,
		SystemPrefetcherInformation,
		SystemExtendedProcessInformation,
		SystemRecommendedSharedDataAlignment,
		SystemComPlusPackage,
		SystemNumaAvailableMemory,
		SystemProcessorPowerInformation,
		SystemEmulationBasicInformation,
		SystemEmulationProcessorInformation,
		SystemExtendedHandleInformation,
		SystemLostDelayedWriteInformation,
		SystemBigPoolInformation,
		SystemSessionPoolTagInformation,
		SystemSessionMappedViewInformation,
		SystemHotpatchInformation,
		SystemObjectSecurityMode,
		SystemWatchdogTimerHandler,
		SystemWatchdogTimerInformation,
		SystemLogicalProcessorInformation,
		SystemWow64SharedInformation,
		SystemRegisterFirmwareTableInformationHandler,
		SystemFirmwareTableInformation,
		SystemModuleInformationEx,
		SystemVerifierTriageInformation,
		SystemSuperfetchInformation,
		SystemMemoryListInformation,
		SystemFileCacheInformationEx,
		MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
	} SYSTEM_INFORMATION_CLASS;

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

	typedef struct _SYSTEM_HANDLE_INFORMATION
	{
		ULONG NumberOfHandles;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
	} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

	typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
	{
		PVOID Object;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG  HandleAttributes;
		ULONG  Reserved;
	} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		ULONG_PTR NumberOfHandles;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;


	typedef NTSTATUS(WINAPI *__NtQuerySystemInformation)(nt::SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

#define DEFINE_NTAPI(name) extern __##name name
	DEFINE_NTAPI(NtQuerySystemInformation);
#undef DEFINE_NTAPI
}
