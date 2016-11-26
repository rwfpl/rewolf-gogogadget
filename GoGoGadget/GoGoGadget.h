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
#include <string>
#include <unordered_map>
#include <set>
#include <memory>
#include <Windows.h>
#include <winternl.h>
#include <functional>
#include "nt.h"

enum class GadgetType
{
	PopRcx,
	PopRdx,
	PopRax,
	PopRdi,
	PopR14,
	MovRaxPtrRax,
	AddRaxRcx,
	XchgRaxRdi,
	MovPtrRdiRax,
	MovRdiRax,
	MovR8Rax,
	MovRcxRbxCallR14,
	MovRcxRsiCallR14,
	MovRbxRax,
	MovPtrRaxRcx,
	Ret,
};

enum class SystemProcessType
{
	System, 
	Services, 
	Wininit, 
	Lsass
};

template <typename T>
using SmartPtr = std::unique_ptr<T, decltype(&free)>;
typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&CloseHandle)> SmartHANDLE;

class GoGoGadget
{
private:
	struct nameToPidCmp
	{
		bool operator()(const std::wstring& a, const std::wstring& b) const { return 0 == _wcsicmp(a.c_str(), b.c_str()); }
	};

	static const std::unordered_map<GadgetType, std::vector<std::vector<uint8_t>>> s_internalGadgets;

	std::string m_systemRoot;	
	std::set<std::string> m_drivers;
	std::set<uint32_t> m_pids;
	std::unordered_map<std::string, std::vector<std::vector<uint8_t>>> m_gadgets;
	std::unordered_map<std::string, std::vector<std::pair<std::string, std::string>>> m_apis;
	std::unordered_map<std::string, uint64_t> m_foundSymbols;
	std::unordered_map<SystemProcessType, uint64_t> m_specialSymbols;
	std::unordered_map<uint32_t, std::wstring> m_pidToName;
	std::unordered_multimap<std::wstring, uint32_t, std::hash<std::wstring>, nameToPidCmp> m_nameToPid;


	std::string convertNtPath(char* path) const;
	bool iterateExecutableNonDiscardableSections(uint8_t* module, uint64_t imageBase, std::function<bool(uint64_t base, uint8_t* ptr, size_t size)> f);
	void resolveExports(std::string& moduleName, uint8_t* module, uint64_t imageBase, const std::vector<std::pair<std::string, std::string>>& apiNames);
	std::string gadgetName(GadgetType type) const;
	uint32_t getProcessPid(const char* processName) const;
	void createPidNameMapping();
	void leakEprocessInfo();
	void applyPERelocations(uint8_t* module, uint64_t imageBase);
	bool resolveGadgets(uint8_t* hMod, uint64_t imageBase, size_t& foundGadgetsCnt);

public:
	GoGoGadget();
	void go();
	void stats();

	void addApi(const char* moduleName, const char* apiName, const char* symbolName = nullptr);
	
	void addGadget(GadgetType type);
	void addGadget(const char* gadgetName, const uint8_t* gadgetBody, size_t gadgetSize);
	void addGadget(const char* gadgetName, const std::vector<uint8_t>& gadgetBody);
	
	void addModule(const char* moduleName);
	
	void addProcess(const char* processName);
	void addProcess(uint32_t pid);
	
	uint64_t getSymbol(GadgetType type) const;
	uint64_t getSymbol(uint32_t pid) const;
	uint64_t getSymbol(const char* symbolName) const;
	uint64_t getSymbol(const std::string& symbolName) const;
	uint64_t getSymbol(const char* moduleName, const char* apiName) const;
	uint64_t getSymbol(SystemProcessType processType) const;
};
