# LogLancer 🔍

Advanced real-time web log analysis tool for security professionals.

## Features

- 🚨 Real-time threat detection (SQLi, XSS, RCE, LFI, etc.)
- 📊 Live monitoring with color-coded output  
- 📈 Comprehensive security statistics
- 💾 HTML/JSON report generation
- 🔍 Automatic log file detection
- ⚡ Minimal dependencies (pure Bash)

## Usage 

# Analyze specific log file
./loglancer.sh -f /var/log/nginx/access.log

# Real-time monitoring  
tail -f /var/log/nginx/access.log | ./loglancer.sh -i --live-mode 5

# Auto-detect and analyze Nginx logs
./loglancer.sh --nginx --output report.html

# Generate JSON report
./loglancer.sh -f access.log --output results.json

## Installation

```bash
git clone https://github.com/niko13teen/loglancer.git
cd loglancer
chmod +x loglancer.sh
