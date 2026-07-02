# Huntrk
Tools for scanning global memory of your linux OS system using python

## 🛡️ huntrk.py - Global Memory System Detector
huntrk.py adalah alat (script) otomatisasi keamanan berbasis Python yang dirancang untuk menganalisis dan mendeteksi anomali pada memori global (global memory) di sistem operasi Linux. Dengan memonitor memori secara mendalam, alat ini membantu administrator mendeteksi potensi rootkit tingkat kernel, injeksi kode (code injection), dan aktivitas fileless malware.

## 📌 Fitur Utama
- Live Memory Scanning: Memindai memori global secara real-time untuk mendeteksi anomali.
- Kernel-Level Anomaly Detection: Mengidentifikasi proses mencurigakan yang mencoba menyembunyikan diri dari userspace.
- Cross-View Analysis: Membandingkan struktur memori dengan filesystem untuk menemukan ketidaksesuaian.
- Laporan Otomatis: Menghasilkan log terstruktur untuk mempermudah audit keamanan (security hardening).

## 📋 Prasyarat Sistem
Pastikan sistem Linux Anda memenuhi persyaratan berikut sebelum menjalankan script:
1. Python 3.x terinstal.
2. Hak akses Root / Sudo (diperlukan untuk membaca memori sistem secara langsung).

## 🚀 Cara Penggunaan
Clone repositori ini ke dalam direktori lokal Anda:
```bash
git clone https://github.com/HihaW/huntrk.git
cd huntrk
sudo python3 huntrk.py
```
