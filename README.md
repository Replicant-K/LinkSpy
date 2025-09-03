# LinkSpy&#128269;
Flask app designed to grab device info and store to a .txt file before redirecting to a new link.
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## Legal Notice

LinkSpy is a tool for fingerprinting and network analysis. Use it ethically and legally. Unauthorized data collection or network scanning (e.g., via Nmap) without explicit consent may violate privacy laws or terms of service. Always obtain permission from users or network owners before deploying. (like any of you give a fuck anyway)

## Description

LinkSpy is a Flask-based web application designed to capture detailed device and browser information from anyone who clicks on your devious little link. it then gets stored in a directory on your device, and seamlessly redirects them to a specified URL. Built for the nosy fuckers, LinkSpy collects a wide range of fingerprinting data, including IP addresses, geolocation, HTTP headers, CSS media queries, WebGL, and more, all while maintaining a lightweight and customizable setup. 
 
 
   
## Setup

### Prerequisites
- Ubuntu (tested on 20.04+)
- Python 3.8+
- Ngrok (free tier)
- MaxMind GeoLite2 databases (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`)

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Replicant-K/LinkSpy.git
   cd LinkSpy
   ```

2. **Install Dependencies**:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip nmap
   pip3 install flask geoip2 user-agents requests pyshark
   ```

3. **Download GeoIP Databases**:
   - Sign up at [MaxMind](https://www.maxmind.com) and download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
   - Place both files in the `LinkSpy` directory.

4. **Install Ngrok**:
   ```bash
   snap install ngrok
   ngrok authtoken YOUR_AUTH_TOKEN  # Get token from ngrok.com
   ```

5. **(Optional) Install Tshark for TLS Fingerprinting**:
   ```bash
   sudo apt install tshark
   ```
## Usage

1. **Configure the App**:
   - Edit `fingerprint_server.py` to set your desired `REDIRECT_URL` (e.g., `https://example.com`).
   - Optionally, change `PAGE_TITLE` to customize the webpage title (default: “LinkSpy”).

2. **Run the Server**:
   ```bash
   python3 fingerprint_server.py
   ```

3. **Expose with Ngrok**:
   ```bash
   ngrok http 5000
   ```
   - Copy the Ngrok URL (e.g., `https://abc123.ngrok.io`) for public access.

4. **Test the App**:
   - Visit the Ngrok URL in a browser.
   - LinkSpy collects device info, saves it to `fingerprints/fingerprint_YYYYMMDD_HHMMSS.txt`, and redirects to the specified URL.

## Output
Each visitor’s data is saved in a timestamped `.txt` file in the `fingerprints/` directory. Example output:
```json
{
    "ip_address": "192.168.1.1",
    "hostname": "example.com",
    "user_agent": {
        "raw": "Mozilla/5.0 ...",
        "browser": "Chrome",
        "version": "120.0",
        "os": "Windows",
        "os_version": "10"
    },
    "geo_info": {
        "country": "United States",
        "city": "San Francisco",
        ...
    },
    "fingerprint": {
        "canvas": "...",
        "webgl": "...",
        "media_queries": ["min-width-0", "min-width-320"],
        ...
    },
    "timestamp": "2025-09-03T03:15:00"
}
```

## Contributing
Pull requests are welcome! Fork the repo, make your changes, and submit a PR. For major changes, open an issue first to discuss.

## Acknowledgments
- Built with [Flask](https://flask.palletsprojects.com), [FingerprintJS2](https://github.com/fingerprintjs/fingerprintjs), and [Nmap](https://nmap.org).
- Inspired by tools like BrowserLeaks and CreepJS.

## License

MIT License

Copyright (c) 2025 [Replicant-K]

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
