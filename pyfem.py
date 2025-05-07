"""
PyFem - Advanced Python Memory Forensic Module for Roblox
"""
import pymem
import psutil
import ctypes
import re
import time
import struct
from typing import Union, List, Dict, Optional

class PyFem:
    def __init__(self, target: Union[str, int] = None):
        """
        Initialize PyFem with target process (name or PID)
        """
        self.pymem = pymem.Pymem()
        self._process_info = {
            'handle': None,
            'base_address': 0,
            'is_64bit': True,
            'pid': None,
            'modules': [],
            'main_module': None
        }
        
        if target:
            self.attach_process(target)

    # ----------------------
    # Process Management
    # ----------------------
    def attach_process(self, target: Union[str, int]) -> bool:
        """Attach to process by name or PID"""
        try:
            if isinstance(target, str):
                self.pymem = pymem.Pymem(target)
                self._update_process_info()
                return True
            elif isinstance(target, int):
                self.pymem.open_process_from_id(target)
                self._update_process_info()
                return True
            return False
        except pymem.exception.ProcessNotFound:
            print(f"Process {target} not found")
            return False

    def _update_process_info(self):
        """Get/update proc info"""
        try:
            modules = self.pymem.list_modules()
            roblox_module = next(
                (m for m in modules 
                if m.name.lower() in ["robloxplayerbeta.exe", "windowsrobloxplayer.exe"]),
                None
            )

            if roblox_module:
                self._process_info.update({
                    'main_module': roblox_module,
                    'base_address': roblox_module.lpBaseOfDll
                })
                print(f"Found base: {self.dec_to_hex(roblox_module.lpBaseOfDll)}")
            else:
                print("Roblox module not found in process!")
                
        except Exception as e:
            print(f"Base address error: {str(e)}")

    @property
    def base_address(self) -> int:
        """Get main module base address"""
        return self._process_info['base_address']

    @property
    def process_handle(self) -> int:
        """Get process handle"""
        return self._process_info['handle']

    # ----------------------
    # Memory Operations
    # ----------------------
    def read_ptr_chain(self, base: int, offsets: List[int], is_64bit: Optional[bool] = None) -> int:
        """
        Read pointer chain (base + offset1 + offset2 + ...)
        """
        ptr = self.read_memory(base, 'qword' if (is_64bit or self._process_info['is_64bit']) else 'dword')
        for offset in offsets:
            ptr = self.read_memory(ptr + offset, 'qword' if (is_64bit or self._process_info['is_64bit']) else 'dword')
        return ptr

    def read_memory(self, address: int, data_type: str, length: int = None) -> Union[int, float, bytes]:
        """
        Read memory with type support
        Supported types: byte, short, word, dword, qword, float, double, bytes
        For 'bytes' type, specify length parameter
        """
        type_map = {
            'byte': ('b', 1),
            'short': ('h', 2),
            'word': ('H', 2),
            'dword': ('I', 4),
            'qword': ('Q', 8),
            'float': ('f', 4),
            'double': ('d', 8)
        }

        if data_type.lower() == 'bytes':
            if not length:
                raise ValueError("Length parameter required for 'bytes' type")
            return self.pymem.read_bytes(address, length)

        fmt, size = type_map[data_type.lower()]
        buffer = self.pymem.read_bytes(address, size)
        return struct.unpack(fmt, buffer)[0]

    def write_memory(self, address: int, value: Union[int, float, bytes], data_type: str) -> None:
        """Write to memory with type support"""
        if data_type == 'bytes':
            self.pymem.write_bytes(address, value, len(value))
            return
        
        type_map = {
            'byte': ('b', 1),
            'short': ('h', 2),
            'word': ('H', 2),
            'dword': ('I', 4),
            'qword': ('Q', 8),
            'float': ('f', 4),
            'double': ('d', 8)
        }
        
        fmt, size = type_map[data_type.lower()]
        packed = struct.pack(fmt, value)
        self.pymem.write_bytes(address, packed, size)

    # ----------------------
    # Pattern Scanning
    # ----------------------
    def pattern_scan(self, pattern: str, return_multiple: bool = False) -> Union[List[int], int]:
        """Scan for byte pattern in process memory"""
        compiled_pattern = self._compile_pattern(pattern)
        return pymem.pattern.pattern_scan_all(
            self.process_handle,
            compiled_pattern,
            return_multiple=return_multiple
        )

    def _compile_pattern(self, pattern: str) -> bytes:
        """Compile AoB pattern to bytes"""
        clean_pattern = re.sub(r'[^0-9a-fA-F?]', '', pattern)
        byte_pattern = bytearray()
        
        for i in range(0, len(clean_pattern), 2):
            byte = clean_pattern[i:i+2]
            if '?' in byte:
                byte_pattern.extend(b'.')
            else:
                byte_pattern.extend(re.escape(bytes.fromhex(byte)))
        
        return bytes(byte_pattern)

    # ----------------------
    # Process Control
    # ----------------------
    def suspend(self) -> None:
        """Suspend process execution"""
        kernel32 = ctypes.WinDLL('kernel32.dll')
        kernel32.DebugActiveProcess(self._process_info['pid'])

    def resume(self) -> None:
        """Resume process execution"""
        kernel32 = ctypes.WinDLL('kernel32.dll')
        kernel32.DebugActiveProcessStop(self._process_info['pid'])

    def wait_for_process(self, name: str, timeout: int = 30) -> bool:
        """Wait for process to become available"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.attach_process(name):
                return True
            time.sleep(1)
        return False

    # ----------------------
    # Memory Protection
    # ----------------------
    def set_memory_protection(self, address: int, protection: int, size: int = 4) -> int:
        """Change memory protection flags"""
        old_protect = ctypes.c_ulong(0)
        kernel32 = ctypes.WinDLL('kernel32.dll')
        kernel32.VirtualProtectEx(
            self.process_handle,
            address,
            size,
            protection,
            ctypes.byref(old_protect)
        )
        return old_protect.value

    def get_memory_protection(self, address: int) -> Dict[str, Union[int, str]]:
        """Get memory protection information"""
        mem_info = pymem.memory.virtual_query(self.process_handle, address)
        return {
            'protection': mem_info.Protect,
            'type': mem_info.Type,
            'state': mem_info.State,
            'readable': mem_info.Protect in [0x02, 0x04, 0x08, 0x20, 0x40, 0x80],
            'writable': mem_info.Protect in [0x04, 0x08, 0x40, 0x80]
        }

    # ----------------------
    # Utility Functions
    # ----------------------
    @staticmethod
    def hex_to_dec(value: Union[str, int], bit: int = 16) -> int:
        """Convert hexadecimal string to decimal integer"""
        return int(value, bit) if isinstance(value, str) else value

    @staticmethod
    def dec_to_hex(value: Union[int, str], bits: int = 64) -> str:
        """Convert decimal integer to hexadecimal string"""
        if isinstance(value, str):
            return value
        mask = (1 << bits) - 1
        return f"{value & mask:0{bits//4}X}"

    def calculate_jmp(self, source: int, destination: int) -> str:
        """Calculate JMP instruction offset"""
        offset = destination - source - 5
        return self.dec_to_hex(offset, 32)

    def is_valid(self, address: int) -> bool:
        """Check if address is valid"""
        try:
            self.pymem.read_bytes(address, 1)
            return True
        except pymem.exception.MemoryReadError:
            return False

    # ----------------------
    # Roblox-Specific Helpers
    # ----------------------
    def get_roblox_instance(self, address: int) -> Dict[str, Union[int, str]]:
        """Get Roblox instance information from memory"""
        try:
            class_name_ptr = self.read_ptr_chain(address, [0x18, 0x8])
            class_name = self.pymem.read_string(class_name_ptr)
            return {
                'address': address,
                'class_name': class_name,
                'parent': self.read_memory(address + 0x28, 'qword'),
                'children': self.read_memory(address + 0x30, 'qword')
            }
        except:
            return {'error': 'Invalid Roblox instance'}
