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
#include "GoGoGadget.h"

int main()
{
	GoGoGadget gogo;
	
	gogo.addApi("ntoskrnl.exe", "PsGetCurrentProcess", "getCurProc");
	gogo.addApi("ntoskrnl.exe", "PsGetCurrentThreadId");
	
	gogo.addGadget(GadgetType::PopRax);
	gogo.addGadget(GadgetType::PopRcx);
	gogo.addGadget(GadgetType::PopRdx);
	gogo.addGadget(GadgetType::PopR14);
	gogo.addGadget(GadgetType::AddRaxRcx);
	gogo.addGadget(GadgetType::MovRaxPtrRax);
	gogo.addGadget("MovPtrRcx38Eax", { 0x89, 0x41, 0x38, 0xc3 });
	
	gogo.addModule("ntoskrnl.exe");
	gogo.addModule("ndis.sys");

	gogo.addProcess(GetCurrentProcessId());
	gogo.addProcess("explorer.exe");

	gogo.stats();

	gogo.go();

	printf("\nChecking results:\n");
	printf("%0I64X\n", gogo.getSymbol("getCurProc"));
	printf("%0I64X\n", gogo.getSymbol("ntoskrnl.exe", "PsGetCurrentThreadId"));
	printf("%0I64X\n", gogo.getSymbol(GadgetType::PopRax));
	printf("%0I64X\n", gogo.getSymbol(GadgetType::PopRcx));
	printf("%0I64X\n", gogo.getSymbol(GadgetType::PopRdx));
	printf("%0I64X\n", gogo.getSymbol("MovPtrRcx38Eax"));
	printf("%0I64X\n", gogo.getSymbol("ntoskrnl.exe"));
	printf("%0I64X\n", gogo.getSymbol("ndis.sys"));
	printf("%0I64X\n", gogo.getSymbol(GetCurrentProcessId()));
	printf("%0I64X\n", gogo.getSymbol("GoGoGadget.exe"));
	printf("%0I64X\n", gogo.getSymbol("explorer.exe"));
	printf("%0I64X\n", gogo.getSymbol(SystemProcessType::System));
	printf("%0I64X\n", gogo.getSymbol(SystemProcessType::Services));
	printf("%0I64X\n", gogo.getSymbol(SystemProcessType::Wininit));
	printf("%0I64X\n", gogo.getSymbol(SystemProcessType::Lsass));
	return 0;
}