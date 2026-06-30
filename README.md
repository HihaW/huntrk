# huntrk
Tools for scanning global memory of your linux OS system using python
Linux Memory ScannerAlat berbasis Python untuk memindai, menganalisis, dan mendeteksi anomali atau string sensitif pada memori sistem (RAM) Linux. Proyek ini dirancang untuk kebutuhan forensik digital, analisis malware, dan audit keamanan.🚀 Fitur UtamaPemindaian Proses: Memindai memori dari PID spesifik atau seluruh proses yang berjalan.Pencarian Regex: Mencari string sensitif seperti kunci API, token, IP, atau data sensitif lain.Analisis RAM Fisik: Mendukung pembacaan /dev/mem atau /dev/kmem (memerlukan akses root).Dump Memori: Mengekstrak segmentasi memori tertentu ke dalam file untuk analisis lanjutan.Ringan & Cepat: Optimalisasi pembacaan buffer untuk meminimalkan dampak beban sistem.📦 PrasyaratPastikan sistem Linux Anda memiliki dependensi berikut:Python 3.8+Akses Root / Sudo (diperlukan untuk membaca memori proses lain atau file sistem /proc)🛠️ InstalasiKloning repositori ini dan instal dependensi yang diperlukan:bashgit clone https://github.com
cd linux-memory-scanner
pip install -r requirements.txt
Gunakan kode dengan hati-hati.💻 Cara Penggunaan1. Pindai PID Spesifik berdasarkan Stringbashsudo python3 scanner.py --pid 1234 --search "KUNCI_RAHASIA"
Gunakan kode dengan hati-hati.2. Pindai Seluruh Proses untuk Pola Regex (misal: Alamat IP)bashsudo python3 scanner.py --all --regex "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
Gunakan kode dengan hati-hati.3. Dump Memori Proses ke Filebashsudo python3 scanner.py --pid 1234 --dump -o /tmp/process_memory.dmp
Gunakan kode dengan hati-hati.⚠️ DisclaimerAlat ini dibuat hanya untuk tujuan pendidikan, riset keamanan, dan forensik. Penggunaan alat ini untuk memantau sistem tanpa izin tertulis dari pemilik sah adalah tindakan ilegal.
