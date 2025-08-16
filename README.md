# 🔎 Multi-depth Security Scanner

A Python-based **multi-depth network and web scanner** that integrates with `nmap` and enriches the results with:
- Port scanning (quick / medium / deep modes)
- Service detection & OS fingerprinting
- Traceroute results
- Vulnerability script outputs
- HTTP/HTTPS probing (status, headers, title, body preview)
- Directory brute-forcing
- Rich HTML report generation

---

## ⚙️ Installation

```bash
git clone https://github.com/YourUsername/your-scanner.git
cd your-scanner
pip install -r requirements.txt
```

Requirements:
- Python 3.8+
- `nmap` installed and available in PATH
- Python libraries in `requirements.txt`

---

## 📖 Usage

```bash
python scanner.py <target> -q   # Quick scan
python scanner.py <target> -m   # Medium scan
python scanner.py <target> -d   # Deep scan
```

Options:
- `--dirs-file FILE` → custom wordlist  
- `--http-timeout SECS` → HTTP timeout (default 5s)  
- `--preview-bytes N` → max preview size (default 2000)  
- `--save-json` → also save raw nmap JSON results  

---

## 📂 Example

```bash
python scanner.py 192.168.1.10 -m --save-json
```

Produces:
- `scan_report_192_168_1_10_m.html` → full HTML report  
- `scan_raw_192_168_1_10_m.json` → raw nmap results  

---

## ⚠️ Disclaimer

This tool is developed **for educational purposes and authorized penetration testing only**.  
You must **only use it on systems you own or have explicit written permission to test**.  
Unauthorized use is **illegal** and may result in **criminal charges**.  

The author assumes **no responsibility** for misuse or damage caused by this tool.  

---

## 📜 License

Released under the MIT License. See [LICENSE](LICENSE) for details.