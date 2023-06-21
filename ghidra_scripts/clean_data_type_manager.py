# @category NX-Switch

from ghidra.program.model.data import DataType
from ghidra.util.task import TaskMonitor
from collections import Counter, defaultdict
from pprint import pprint
from timeit import default_timer as timer

data_type_manager = currentProgram.getDataTypeManager()

processing_count = 1000
data_types = defaultdict(list)
to_delete_function_ref = []

for data_type in data_type_manager.getAllDataTypes():
	if data_type.getLength() == -1:
		to_delete_function_ref.append(data_type)

num_to_delete_fun_ref = len(to_delete_function_ref)
userChoice = askYesNo("Continue?", f"Will process {processing_count} out of {len(to_delete_function_ref)} entries to delete.\nContinue processing?\nThis may take a long time to complete.")

if userChoice:
	for _ in range(0, processing_count):
		data_type_manager.remove(to_delete_function_ref.pop(), monitor)
