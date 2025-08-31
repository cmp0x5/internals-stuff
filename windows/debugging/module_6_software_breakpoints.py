#############################################################################################
##
## OALABS - Debugging Fundimentals For Reverse Engineers
##
## Lab 6 - Understanding software breakpoints
##
## Usage: module_6_software_breakpoints.py <target.exe>
##
#############################################################################################

import sys
import os
import time
import ctypes
import msvcrt
import pefile
import struct

from dbglib import win32types
from dbglib import win32process
from dbglib import win32memory
from dbglib import win32debug

# Globals for easy access to target information
target_process_handle = None
target_path = None
# Use this to save the entry point info
entry_point_breakpoint_address = None
entry_point_breakpoint_byte = None

# Function to handle CREATE_PROCESS_DEBUG_EVENT
# We will take advantage of this event to set a
# breakpoint on the target entry point address
def handle_event_create_process(pEvent):
    global target_process_handle
    global target_path
    global entry_point_breakpoint_address 
    global entry_point_breakpoint_byte
    print(f"\nCREATE_PROCESS_DEBUG_EVENT")
    # Get debug event info 
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    # The event also contains a CREATE_PROCESS_DEBUG_INFO struct
    target_process_info = pEvent.u.CreateProcessInfo
    # Get target image base from debug event
    target_image_base = target_process_info.lpBaseOfImage
    # Get the entrypoint address from debug event
    target_start_address = target_process_info.lpStartAddress
    # Save the breakpoint address
    entry_point_breakpoint_address = target_start_address

    # Read the byte from the entry point that will be replaced 
    # with a breakpoint

    # Because we handled the event return a status of DBG_CONTINUE
    return win32types.DBG_CONTINUE

def handle_event_load_dll(pEvent):
    global target_process_handle
    global writefile_address
    global writefile_breakpoint_byte
    print(f"LOAD_DLL_DEBUG_EVENT\n")
    # Extract process ID and thread ID from debug event
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    # The debug event also contains a LOAD_DLL_DEBUG_INFO struct
    dll_event_info = pEvent.u.LoadDll
    dll_file_handle = dll_event_info.hFile
    dll_based_address = dll_event_info.lpBaseOfDll
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
        print('found')
        #rebase dll addresses based on lpBaseOfDll
        #print virtual address of NtWriteFile

        # We can also parse the exports from DLL and save these for later use
        # First we need to tell pefile to parse the export directory since we are using the fast_load option
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        # Now we can loop through each exported symbol and add the information to our exports list
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name == b"NtWriteFile":
            function_address = dll_based_address + exp.address
            print(f"NtWriteFile Address: {function_address}")
            writefile_address = function_address
            # The export address is the RVA so it must ba added to the DLL base address to
            # calculate the virtual address of the export
            
            #write bp
            print(f"Setting breakpoint at {hex(function_address)}")
            # Read the byte from the entry point that will be replaced 
            # with a breakpoint
        
            writefile_breakpoint_byte = win32memory.read(target_process_handle, function_address, 1)

            # Write the INT3 opcode 0xcc to the entry point
            bytes_written = win32memory.write(target_process_handle, function_address, b'\xcc')
            # Print some status to the user
            print(f"Wrote {bytes_written} bytes to NtWriteFile address at {hex(function_address)}")
            break
    # Because we handled the event return a status of DBG_CONTINUE
    return win32types.DBG_CONTINUE

def handle_software_breakpoint(pEvent):
    global target_process_handle
    global target_path
    global entry_point_breakpoint_address 
    global entry_point_breakpoint_byte
    global writefile_breakpoint_byte
    print(f"\nEXCEPTION_BREAKPOINT")
    # Get debug event info 
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    # The event also contains an EXCEPTION_RECORD struct
    exception_info  = pEvent.u.Exception.ExceptionRecord
    # Get address of breakpoint from exception
    exception_address = exception_info.ExceptionAddress
    # Set default status breakpoint not handled
    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
    # Check if the breakpoint address matches the breakpoint
    # we set on the entry point
    if exception_address == writefile_address:
        # Notify the user that the breakpoint was hit
        # and clear the breakpoint so execution can continue
        print(f"Breakpoint on NtWriteFile hit at {hex(exception_address)}")
        # Restore original byte at entry point
        bytes_written = win32memory.write(target_process_handle, exception_address, writefile_breakpoint_byte)
        print(f"Restored {bytes_written} byte at {hex(exception_address)}")

        # Get a thread handle with full access
        target_thread_handle = win32process.OpenThread(win32types.THREAD_ALL_ACCESS, False, target_thread_id)
        # Get the thread context
        context = win32process.GetThreadContext(target_thread_handle)
        stack_pointer = context.Esp
        print(f"Stack pointer at {stack_pointer}")
        # Move instruction pointer EIP back one byte
        # this will ensure that the restored byte is executed
        context.Eip = context.Eip - 1
        set_context_status = win32process.SetThreadContext(target_thread_handle, context)
        
        buffer_ptr_bytes = win32memory.read(target_process_handle, stack_pointer+0x18, 4)
        length_ptr_bytes = win32memory.read(target_process_handle, stack_pointer+0x1C, 4)
        
        buffer_ptr_dec = struct.unpack("<I", buffer_ptr_bytes)[0]
        length_ptr_dec = struct.unpack("<I", length_ptr_bytes)[0]
        
        buffer_arg = win32memory.read(target_process_handle, buffer_ptr_dec, length_ptr_dec)
        print(f"Buffer of NtWriteFile at address {stack_pointer+24} is {buffer_arg}, of len {length_ptr_dec}")
        # Clear breakpoint info and continue execution
        entry_point_breakpoint_address = None
        entry_point_breakpoint_byte = None
        dwStatus = win32types.DBG_CONTINUE
    else:
        # Alert the user that a breakpoint was hit that we didn't set
        # This is likely the "System Breakpoint"
        print(f"Breakpoint hit at {hex(exception_address)} - not set by us!")
        dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
    return dwStatus


def main():
    # Global access
    global target_process_handle
    global target_path
    global writefile_address
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
            # Check if the event is CREATE_PROCESS_DEBUG_EVENT
            
            if pEvent.dwDebugEventCode == win32types.CREATE_PROCESS_DEBUG_EVENT:
                dwStatus = handle_event_create_process(pEvent)
            elif pEvent.dwDebugEventCode == win32types.EXCEPTION_DEBUG_EVENT: 
                # Obtain the exception code
                exception_code = pEvent.u.Exception.ExceptionRecord.ExceptionCode
                exception_address = pEvent.u.Exception.ExceptionRecord.ExceptionAddress

                # Handle software breakpoint exception event
                if exception_code == win32types.EXCEPTION_BREAKPOINT: 
                    dwStatus = handle_software_breakpoint(pEvent)
            elif pEvent.dwDebugEventCode == win32types.LOAD_DLL_DEBUG_EVENT:
                dwStatus = handle_event_load_dll(pEvent)

            # Continue target process
            ctypes.windll.kernel32.ContinueDebugEvent(pEvent.dwProcessId, pEvent.dwThreadId, dwStatus)

        # If WaitForDebugEvent() returns FALSE it timed out
        # Check for ENTER key on console 
        if msvcrt.kbhit():
            if msvcrt.getwche() == '\r':
                break





if __name__ == '__main__':
    main()
