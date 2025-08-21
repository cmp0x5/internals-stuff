#############################################################################################
##
## OALABS - Debugging Fundimentals For Reverse Engineers
##
## Lab 1 - Understanding debug events 
##
## Usage: module_1_debug_events.py <target.exe>
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
target_path = None

# Function to handle CREATE_PROCESS_DEBUG_EVENT
# We will take advantage of this event to test our memory read/write
# and replace the "hello world" string in the target PE with 
# the string "string hack"
# **NOTE: This will only work with the provided hello world target exe
def handle_event_create_process(pEvent):
    global target_process_handle
    global target_path
    print(f"\nCREATE_PROCESS_DEBUG_EVENT")
    # Get debug event info 
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    # The event also contains a CREATE_PROCESS_DEBUG_INFO struct
    target_process_info = pEvent.u.CreateProcessInfo
    # Get target image base from debug event
    target_image_base = target_process_info.lpBaseOfImage
    print(f"Target loaded at {hex(target_image_base)}")
    print(f"Replacing 'Hello Word' string with 'String Hack'")
    # Read in the target PE file and parse to locate "hello world"
    # Load target file from disk and parse with pefile 
    target_pe = pefile.PE(target_path, fast_load=True)

    # Locate the rdata section which will contain the strings
    rdata_address = None
    rdata_size = None
    for s in target_pe.sections:
        if b'rdata' in s.Name:
            rdata_address = s.VirtualAddress + target_image_base
            rdata_size = s.Misc_VirtualSize
    # If the rdata section cannot be located return
    if rdata_address is None:
        print(f"Cannot find rdata section in PE: {target_path}")
        # Because we handled the event return a status of DBG_CONTINUE
        return win32types.DBG_CONTINUE
    # Read the rdata section from the process memory 
    radata_data = win32memory.read(target_process_handle, rdata_address, rdata_size)
    # Search for the "Hello World" string
    string_offset = radata_data.find(b'Hello World')
    # If the string is not found return
    if string_offset == -1:
        print(f"Cannot find 'Hello World' string")
        # Because we handled the event return a status of DBG_CONTINUE
        return win32types.DBG_CONTINUE
    # Convert the string offset into an address
    string_address = string_offset + rdata_address
    string_address = target_image_base + 0x104B
    # Overwrite the string with "String Hack"
    bytes_written = win32memory.write(target_process_handle, string_address, b'\x90\x90\x90\x90\x90\x90')
    #bytes_written = win32memory.write(target_process_handle, string_address, b'String Hack')
    # Print some status to the user
    print(f"Wrote {bytes_written} bytes to {hex(string_address)}")

    # Because we handled the event return a status of DBG_CONTINUE
    return win32types.DBG_CONTINUE


def main():
    # Global access
    global target_process_handle
    global target_path
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
                # Pass event to handler and return status
                dwStatus = handle_event_create_process(pEvent)

            # Continue target process
            ctypes.windll.kernel32.ContinueDebugEvent(pEvent.dwProcessId, pEvent.dwThreadId, dwStatus)

        # If WaitForDebugEvent() returns FALSE it timed out
        # Check for ENTER key on console 
        if msvcrt.kbhit():
            if msvcrt.getwche() == '\r':
                break





if __name__ == '__main__':
    main()
