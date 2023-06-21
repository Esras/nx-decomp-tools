# @category NX-Switch

# Purely for LSP support in editors
import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

import csv
from pprint import pprint
from itanium_demangler import parse as demangle

from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType

botw_decomp_tags = {
	'O': 'OK',
	'm': 'MINOR',
	'M': 'MAJOR',
	'W': "WIP",
	'U': 'UNDECOMPILED',
	'L': 'LIBRARY',
}

fmgr = currentProgram.getFunctionManager()
func_tag_mgr = fmgr.getFunctionTagManager()

def check_tags():
	current_tags = func_tag_mgr.getAllFunctionTags()
	for our_tag in botw_decomp_tags:
		if botw_decomp_tags[our_tag] not in current_tags:
			func_tag_mgr.createFunctionTag(our_tag, None)


def handle_special_characters(name: str):
	if len(name.split(' ')) == 1:
		return name
	else:
		return name.split(' ')[0]


def get_new_demangled_name(name: str):
	pass


# Copied from tools/common/rename_functions_in_ida.py
def can_overwrite_name(addr: int, new_name: str):
	if not new_name or new_name.startswith(("sub_", "nullsub_", "j_")):
		return False

	old_func = fmgr.getFunctionAt(addr)
	if not old_func:
		return True

	old_name = old_func.getName()
	# Auto-generated names can be overwritten.
	if old_name.startswith(("sub_", "nullsub_", "j_")):
		return True

	# If the existing name is mangled, then it probably came from the function list CSV
	# so it can be overwritten.
	if old_name.startswith("_Z"):
		return True

	# Prefer mangled names to temporary names.
	if new_name.startswith("_Z"):
		return True

	# Otherwise, we return false to avoid losing temporary names.
	return False

function_file = str(askFile("Choose uking_functions.csv", "Select"))
check_tags()

with open(function_file, 'r') as f:
	function_reader = csv.reader(f, delimiter=',')
	next(function_reader) # Skip the header row
	count = 0
	for func in function_reader:
		count += 1
		state = func[1]
		start_addr = toAddr(int(func[0], 16))
		size = int(func[2])
		end_addr = start_addr.addNoWrap(size - 1)
		addr_set = AddressSet(start_addr, end_addr)
		name = func[3]

		if can_overwrite_name(start_addr, name):
			try:
				new_func_ast = demangle(name)
			except NotImplementedError:
				continue
			if not new_func_ast:
				continue

			try:
				demangled_name = handle_special_characters(str(new_func_ast.name))
			except AttributeError:
				if demangled_name:
					print(f"Tried demangling '{name}'")
					print(f"  {new_func_ast}")
					print(f"  {new_func_ast.kind}")
					# print(f"  {dir(new_func_ast)}")
			setPlateComment(start_addr, str(new_func_ast))

			old_func = fmgr.getFunctionAt(start_addr)
			if old_func:
				if addr_set == old_func.getBody():
					old_name = old_func.getName()
					# print(f"Overwriting {old_func.getName()} with {demangled_name}")
					try:
						old_func.setName(demangled_name, SourceType.IMPORTED)
					except:
						pass
					old_func.addTag(botw_decomp_tags[state])
			else:
				print(f"Writing {name} to 0x{start_addr} - 0x{end_addr}")
				new_func = fmgr.createFunction(demangled_name, start_addr, addr_set, SourceType.IMPORTED)
				new_func.addTag(botw_decomp_tags[state])
		# if count >= 100:
		# 	break


