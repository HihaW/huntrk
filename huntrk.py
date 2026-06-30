#!/usr/bin/env python3

import os
import sys
import re
import logging
from typing import List, Tuple, Dict

logging.basicConfig(level=logging.INFO, format='[SECURITY_HUNTER] %(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MemoryHunter")

def decode_signature(encoded_bytes: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in encoded_bytes])

SUSPICIOUS_SIGNATURES = {
    "Reverse_Shell_Pattern_A": decode_signature(b"\x9b\x6a\xfa\xc2\x85\x85\xd9\xc2", 0xAA),
    "Memory_Patch_Hook": decode_signature(b"\x3a\x3a\x3a\x41\x54", 0xAA)
}

class ProcessMemoryScanner:
    def __init__(self, pid: int):
        self.pid = pid
        self.maps_path = f"/proc/{pid}/maps"
        self.mem_path = f"/proc/{pid}/mem"

    def get_executable_regions(self) -> List[Tuple[int, int, str]]:
        regions = []
        map_regex = re.compile(r'([0-9a-f]+)-([0-9a-f]+)\s+([rwxp-]+)\s+.*')
        
        try:
            with open(self.maps_path, 'r', errors='ignore') as f:
                for line in f:
                    match = map_regex.match(line)
                    if match:
                        start_hex, end_hex, permissions = match.groups()
                        if 'x' in permissions or 'w' in permissions:
                            start_addr = int(start_hex, 16)
                            end_addr = int(end_hex, 16)
                            regions.append((start_addr, end_addr, permissions))
        except PermissionError:
            logger.error(f"Akses ditolak untuk PID {self.pid}. Jalankan script menggunakan sudo/root.")
        except FileNotFoundError:
            logger.warning(f"Proses dengan PID {self.pid} sudah mati atau tidak ditemukan.")
        
        return regions

    def scan_process(self) -> Dict[str, List[int]]:
        detections = {sig_name: [] for sig_name in SUSPICIOUS_SIGNATURES}
        regions = self.get_executable_regions()
        
        if not regions:
            return detections

        try:
            with open(self.mem_path, 'rb') as mem_file:
                for start_addr, end_addr, perms in regions:
                    size = end_addr - start_addr
                    
                    if size <= 0 or size > 100 * 1024 * 1024: 
                        continue
                    
                    try:
                        mem_file.seek(start_addr)
                        chunk = mem_file.read(size)
                        
                        if not chunk:
                            continue

                        for sig_name, sig_bytes in SUSPICIOUS_SIGNATURES.items():
                            offset = chunk.find(sig_bytes)
                            if offset != -1:
                                actual_memory_address = start_addr + offset
                                detections[sig_name].append(actual_memory_address)
                                
                    except (OSError, OverflowError, ValueError):
                        continue
        except PermissionError:
            pass
        except OSError:
            pass
            
        return detections
    def scan_process(self) -> Dict[str, List[int]]:
        detections = {sig_name: [] for sig_name in SUSPICIOUS_SIGNATURES}
        regions = self.get_executable_regions()
        
        if not regions:
            return detections

        try:
            with open(self.mem_path, 'rb') as mem_file:
                for start_addr, end_addr, perms in regions:
                    size = end_addr - start_addr
                    
                    if size <= 0 or size > 100 * 1024 * 1024: 
                        continue
                    
                    try:
                        mem_file.seek(start_addr)
                        chunk = mem_file.read(size)
                        
                        if not chunk:
                            continue

                        for sig_name, sig_bytes in SUSPICIOUS_SIGNATURES.items():
                            offset = chunk.find(sig_bytes)
                            if offset != -1:
                                actual_memory_address = start_addr + offset
                                detections[sig_name].append(actual_memory_address)
                                
                    except (OSError, OverflowError, ValueError):
                        continue
        except PermissionError:
            pass
        except OSError:
            pass
            
        return detections


def hunt_system():
    logger.info("Memulai pemindaian memori global pada seluruh proses sistem...")
    
    all_pids = [int(p) for p in os.listdir('/proc') if p.isdigit()]
    total_scanned = 0
    total_threats = 0
    
    for pid in all_pids:
        if pid == os.getpid():
            continue
            
        scanner = ProcessMemoryScanner(pid)
        results = scanner.scan_process()
        total_scanned += 1
        
        for threat_name, addresses in results.items():
            if addresses:
                for addr in addresses:
                    total_threats += 1
                    logger.critical(
                        f"[ALERT] ANCAMAN DIDETEKSI! Jenis: {threat_name} | "
                        f"Ditemukan pada PID: {pid} | Alamat Memori RAM: {hex(addr)}"
                    )
                    
    logger.info(f"Pemindaian selesai. Total proses diperiksa: {total_scanned}. Total ancaman: {total_threats}.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Error: Proyek ini membutuhkan hak akses Root Linux.")
        print("[*] Silakan jalankan ulang menggunakan perintah: sudo python3 pro_hunter.py")
        sys.exit(1)
        
    hunt_system()
