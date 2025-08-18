#############################################################################################
##
## OALABS - Debugging Fundimentals For Reverse Engineers
##
## Lab 4 - Understanding DLL load event
##
## Usage: module_4_dlls.py <target.exe>
##
#############################################################################################

import sys
import os
import time
import ctypes
import msvcrt
import pefile

from dbglib import win32types
from dbglib import win32process
from dbglib import win32memory
from dbglib import win32debug

# Globals for easy access to target information
target_process_handle = None
target_dlls = {}

# Function to handle LOAD_DLL_DEBUG_EVENT
def handle_event_load_dll(pEvent):
    # Globals access
    global target_dlls
    print(f"\nLOAD_DLL_DEBUG_EVENT")
    # Extract process ID and thread ID from debug event
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    # The debug event also contains a LOAD_DLL_DEBUG_INFO struct
    dll_event_info = pEvent.u.LoadDll
    dll_file_handle = dll_event_info.hFile
    dll_based_address = dll_event_info.lpBaseOfDll

    # Because the LOAD_DLL_DEBUG_INFO.lpImageName member is not correctly
    # populated at the time the LOAD_DLL_DEBUG_EVENT event is raised 
    # we must use the dll_file_handle to locate the DLL file on disk and
    # parse the file directly for more information about the DLL

    # Create a buffer to hold the DLL file path
    file_path_buffer_size = win32types.MAX_PATH
    file_path_buffer = ctypes.create_unicode_buffer(u"", win32types.MAX_PATH + 1)

    # Use the file handle to get the DLL file path
    path_status = ctypes.windll.kernel32.GetFinalPathNameByHandleW( dll_file_handle, 
                                                                    file_path_buffer, 
                                                                    file_path_buffer_size, 
                                                                    win32types.FILE_NAME_NORMALIZED )
    # If the file path is not found print an error and return
    if not path_status:
        print(f"GetFinalPathNameByHandleW failed: {ctypes.WinError().strerror}")
        # Because we handled the event return a status of DBG_CONTINUE
        return win32types.DBG_CONTINUE
    # Get the DLL path from the buffer 
    dll_file_path = file_path_buffer.value

    # Load DLL file from disk and parse with pefile to get more info
    pe = pefile.PE(dll_file_path, fast_load=True)

    # Calculate DLL entry point by adding entrypoint RVA to DLL base address
    dll_entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint + dll_based_address
    # Calculate DLL end address by adding DLL base address and DLL virtual size calculated
    # by adding the size and virtual address of the DLL's last PE section
    dll_end_address = pe.sections[-1].Misc_VirtualSize + pe.sections[-1].VirtualAddress + dll_based_address
    # Calcuate the DLL virtual size by subtracting the DLL base address from the DLL end address
    dll_virtual_size = dll_end_address - dll_based_address
    # Extract the DLL name from the DLL file path
    dll_name = os.path.basename(dll_file_path)

    # Print some info about the DLL
    print(f"DLL Loaded: {dll_name}")
    print(f"Base: {hex(dll_based_address)}")
    print(f"End: {hex(dll_end_address)}")
    print(f"Size: {dll_virtual_size}")
    print(f"Entry Point: {hex(dll_entrypoint)}")
    
    if (dll_name) == "ntdll.dll":
        print("match")
        #rebase dll addresses based on lpBaseOfDll
        #print virtual address of NtWriteFile

    # We can also parse the exports from DLL and save these for later use
    # First we need to tell pefile to parse the export directory since we are using the fast_load option
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    # Now we can loop through each exported symbol and add the information to our exports list
    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name == b"NtWriteFile":
            dll_address = dll_based_address + exp.address
            print(f"NtWriteFile Address: {dll_address}")
        # The export address is the RVA so it must ba added to the DLL base address to
        # calculate the virtual address of the export
        export_address = dll_based_address + exp.address
        export_name = exp.name
        export_ord = exp.ordinal
        exports.append({'name':export_name, 'ord':export_ord, 'address':export_address})
      
    

    # Now that we have collected the exports we can add all of the DLL information
    # to the global target_dlls dictionary for use in other functions 
    target_dlls[dll_based_address] = { 'name':dll_name, 
                                        'path':dll_file_path, 
                                        'base':dll_based_address, 
                                        'end_address':dll_end_address,
                                        'size':dll_virtual_size,
                                        'entrypoint':dll_entrypoint, 
                                        'exports':exports }

    # Because we handled the event return a status of DBG_CONTINUE
    return win32types.DBG_CONTINUE


# Function to handle UNLOAD_DLL_DEBUG_EVENT
def handle_event_unload_dll(pEvent):
    print(f"\nUNLOAD_DLL_DEBUG_EVENT")
    # Because we handled the event return a status of DBG_CONTINUE
    return win32types.DBG_CONTINUE


def main():
    # Global access
    global target_process_handle
    # Get path to target exe
    target_path = sys.argv[1]
    print(f"Debugging target:{target_path}")

    # Create target process
    pStartupInfo = win32types.STARTUPINFO()
    pProcessInfo = win32types.PROCESS_INFORMATION()
    proc_status = ctypes.windll.kernel32.CreateProcessW(target_path,
                                                        None,
                                                        None,
                                                        None,
                                                        False,
                                                        # DEBUG_PROCESS flags tell the kernel 
                                                        # we will be debugging the created process
                                                        win32types.DEBUG_PROCESS,
                                                        None,
                                                        None,
                                                        ctypes.byref(pStartupInfo),
                                                        ctypes.byref(pProcessInfo))

    # If there is an error creating the process exit
    if not proc_status:
        print(f"Cannot create target process:{ctypes.WinError().strerror}")
        sys.exit(1)

    # The PROCESS_INFORMATION struct and STARTUPINFO struct returned from CreateProcessW()
    # contain important information about the target process including: 
    # - a handle to the process with full debug permissions
    # - the process ID
    # - a handle to the main thread
    target_process_handle = pProcessInfo.hProcess
    target_pid = pProcessInfo.dwProcessId
    target_main_thread_id = pProcessInfo.dwThreadId

    # Print the information we have received from CreateProcessW()
    print(f"Target process created (PID:{pProcessInfo.dwProcessId})")


    # This is our debug event loop
    # We keep processing debug events until the target has exited
    # The debug loop can also be terminated by pressing ENTER 
    print(f"Press ENTER to quit debug loop...")
    while True:
        # Create a DEBUG_EVENT struct to be populated with event information
        pEvent = win32types.DEBUG_EVENT()

        # Set the default debug status to DBG_EXCEPTION_NOT_HANDLED
        # This will be passed to ContinueDebugEvent() if the event is not handled 
        dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED

        # Wait for a debug event from the target
        # We timeout every 100 ms to allow the loop a chance to check if 
        # the user has pressed ENTER
        if ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(pEvent), 100):
            # If WaitForDebugEvent() returns TRUE we have a debug event to process
            if pEvent.dwDebugEventCode == win32types.LOAD_DLL_DEBUG_EVENT:
                dwStatus = handle_event_load_dll(pEvent)
            elif pEvent.dwDebugEventCode == win32types.UNLOAD_DLL_DEBUG_EVENT:
                dwStatus = handle_event_unload_dll(pEvent)

            # Continue target process
            ctypes.windll.kernel32.ContinueDebugEvent(pEvent.dwProcessId, pEvent.dwThreadId, dwStatus)

        # If WaitForDebugEvent() returns FALSE it timed out
        # Check for ENTER key on console 
        if msvcrt.kbhit():
            if msvcrt.getwche() == '\r':
                break





if __name__ == '__main__':
    main()
