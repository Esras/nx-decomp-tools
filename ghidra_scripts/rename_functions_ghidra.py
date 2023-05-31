# @category NX-Switch

import csv
from pprint import pprint

from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType

fmgr = currentProgram.getFunctionManager()

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

with open(function_file, 'r') as f:
	function_reader = csv.reader(f, delimiter=',')
	next(function_reader) # Skip the header row
	for func in function_reader:
		start_addr = toAddr(int(func[0], 16))
		size = int(func[2])
		end_addr = start_addr.addNoWrap(size - 1)
		name = func[3]
		if can_overwrite_name(start_addr, name):
			print(f"Overwriting 0x{start_addr} with {name}")
			addr_set = AddressSet(start_addr, end_addr)
			fmgr.createFunction(name, start_addr, addr_set, SourceType.IMPORTED)
