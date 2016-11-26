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
#include <vector>
#include "GoGoGadget.h"

std::string GoGoGadget::gadgetName(GadgetType type) const
{
#define GGGSTR(a) case GadgetType::a: return #a
	switch (type)
	{
		GGGSTR(PopRcx);
		GGGSTR(PopRdx);
		GGGSTR(PopRax);
		GGGSTR(PopRdi);
		GGGSTR(PopR14);
		GGGSTR(MovRaxPtrRax);
		GGGSTR(AddRaxRcx);
		GGGSTR(XchgRaxRdi);
		GGGSTR(MovPtrRdiRax);
		GGGSTR(MovRdiRax);
		GGGSTR(MovR8Rax);
		GGGSTR(MovRcxRbxCallR14);
		GGGSTR(MovRcxRsiCallR14);
		GGGSTR(MovRbxRax);
		GGGSTR(MovPtrRaxRcx);
		GGGSTR(Ret);
	default: return "gadget_" + std::to_string((int)type);
	}
}

const std::unordered_map<GadgetType, std::vector<std::vector<uint8_t>>> GoGoGadget::s_internalGadgets =
{
	{ GadgetType::XchgRaxRdi,
	{
		{ 0x48, 0x97, 0xC3 },
		{ 0x4A, 0x97, 0xC3 },
		{ 0x4C, 0x97, 0xC3 },
		{ 0x4E, 0x97, 0xC3 },
		{ 0x48, 0x97, 0xC2, 0x00, 0x00 },
		{ 0x4A, 0x97, 0xC2, 0x00, 0x00 },
		{ 0x4C, 0x97, 0xC2, 0x00, 0x00 },
		{ 0x4E, 0x97, 0xC2, 0x00, 0x00 }
	}},
	{ GadgetType::AddRaxRcx,
	{
		{ 0x48, 0x03, 0xc1, 0xc3 }
	}},
	{ GadgetType::MovRaxPtrRax,
	{
		{ 0x48, 0x8b, 0x00, 0xc3 }
	}},
	{ GadgetType::PopRcx,
	{
		{ 0x59, 0xC3 }
	}},
	{ GadgetType::PopRax,
	{
		{ 0x58, 0xC3 }
	}},
	{ GadgetType::PopRdx,
	{
		{ 0x5A, 0xC3 },
		{ 0x5A, 0x40, 0xC3 },
		{ 0x5A, 0x41, 0xC3 },
		{ 0x5A, 0x42, 0xC3 },
		{ 0x5A, 0x43, 0xC3 },
		{ 0x5A, 0x44, 0xC3 },
		{ 0x5A, 0x45, 0xC3 },
		{ 0x5A, 0x46, 0xC3 },
		{ 0x5A, 0x47, 0xC3 },
		{ 0x5A, 0x48, 0xC3 },
		{ 0x5A, 0x49, 0xC3 },
		{ 0x5A, 0x4A, 0xC3 },
		{ 0x5A, 0x4B, 0xC3 },
		{ 0x5A, 0x4C, 0xC3 },
		{ 0x5A, 0x4D, 0xC3 },
		{ 0x5A, 0x4E, 0xC3 },
		{ 0x5A, 0x4F, 0xC3 },
	}},
	{ GadgetType::MovPtrRdiRax,
	{
		{ 0x48, 0x89, 0x07, 0xC3 }
	}},
	{ GadgetType::PopRdi,
	{
		{ 0x5F, 0xC3 }
	}},
	{ GadgetType::MovRdiRax,
	{
		{ 0x50, 0x5f, 0xc3 }
	}},
	{ GadgetType::MovR8Rax,
	{
		{ 0x4c, 0x8b, 0xc0, 0x49, 0x8b, 0xc0, 0xC3 }
	}},
	{ GadgetType::MovRcxRbxCallR14,
	{
		{ 0x48, 0x8b, 0xcb, 0x41, 0xff, 0xd6 }
	}},
	{ GadgetType::MovRcxRsiCallR14,
	{
		{ 0x48, 0x8b, 0xce, 0x41, 0xff, 0xd6 }
	}},
	{ GadgetType::PopR14,
	{
		{ 0x41, 0x5e, 0xc3 }
	}},
	{ GadgetType::MovRbxRax,
	{
		{ 0x50, 0x5b, 0xc3 }
	}},
	{ GadgetType::MovPtrRaxRcx,
	{
		{ 0x48, 0x89, 0x08, 0xc3 }
	}},
	{ GadgetType::Ret,
	{
		{ 0xc3 }
	}},
};
