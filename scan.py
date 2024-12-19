# scan.py

import sys
import json
import time
import subprocess
import requests
import socket
import maxminddb
from urllib.parse import urlparse

def scan_time(url):
    return int(time.time() * 100) / 100

def ipv4_addresses(url):
    domain = urlparse(url).netloc or url
    public_dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9",
        "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1",
        "198.101.242.72", "176.103.130.130"]
    address_set = set()
    for resolver in public_dns_resolvers:
        try:
            result = subprocess.check_output(["nslookup", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            sublist = []
            for line in result.splitlines():
                if "Address:" in line and "." in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        sublist.append(parts[1].strip())
                for address in sublist[1:]:  # ignore the DNS server address
                    address_set.add(address)
        except subprocess.TimeoutExpired:
            continue
        except FileNotFoundError as e:
            raise e
        except Exception:
            continue
    return list(address_set)

def ipv6_addresses(url):
    domain = urlparse(url).netloc or url
    public_dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9",
        "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1",
        "198.101.242.72", "176.103.130.130"]
    address_set = set()
    for resolver in public_dns_resolvers:
        try:
            result = subprocess.check_output(["nslookup", "-type=AAAA", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            sublist = []
            for line in result.splitlines():
                if "Address:" in line and ":" in line:  # check for ":" indicating IPv6
                    parts = line.split(": ")
                    if len(parts) > 1:
                        sublist.append(parts[1].strip())
                for address in sublist[1:]:  # ignore the DNS server address
                    address_set.add(address)
        except subprocess.TimeoutExpired:
            continue
        except FileNotFoundError as e:
            raise e
        except Exception:
            continue
    return list(address_set)



def http_server(url):
    try:
        res = requests.get(f"http://{url}" if not url.startswith("http") else url, timeout=2)
        return res.headers.get("Server")
    except Exception:
        return None

def insecure_http(url):
    try:
        response = requests.get(f"http://{url}" if not url.startswith("http") else url, timeout=2)
        return response.status_code == 200
    except Exception:
        return False

def redirect_to_https(url):
    try:
        if not url.startswith("http://"):
            if url.startswith("https://"):
                url = url.replace("https://", "http://")
            else:
                url = f"http://{url}"
        for _ in range(10):  # allow up to 10 redirects
            res = requests.get(url, timeout=2, allow_redirects=False)
            if 300 <= res.status_code < 310:
                new_url = res.headers.get('Location')
                if new_url and new_url.startswith('https'):
                    return True
                url = new_url or url
            else:
                break
        return False
    except Exception:
        return False

def hsts(url):
    try:
        response = requests.get(url if url.startswith("https") else f"https://{url}", timeout=2, allow_redirects=True)
        return 'Strict-Transport-Security' in response.headers
    except Exception:
        return False

def tls_versions(url):
    domain = urlparse(url).netloc or url
    if not domain:
        raise ValueError("Invalid URL provided")
    
    domain = domain.split(':')[0]
    
    supported_tls = []
    tls_versions = ['-ssl2', '-ssl3', '-tls1', '-tls1_1', '-tls1_2', '-tls1_3']
    tls_map = {'-ssl2': 'SSLv2',
               '-ssl3': 'SSLv3',
               '-tls1': 'TLSv1.0',
               '-tls1_1': 'TLSv1.1',
               '-tls1_2': 'TLSv1.2',
               '-tls1_3': 'TLSv1.3'}

    for version in tls_versions:
        try:
            # Run OpenSSL s_client with the given TLS/SSL version
            result = subprocess.run(
                ["openssl", "s_client", "-connect", f"{domain}:443", version],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            # Check if connection was successful
            if "CONNECTED" in result.stdout.decode():
                supported_tls.append(tls_map[version])
        except subprocess.TimeoutExpired:
            continue
        except FileNotFoundError:
            raise FileNotFoundError("OpenSSL is not installed or not in the PATH")
        except subprocess.CalledProcessError:
            pass
        except Exception as e:
            continue
    return supported_tls


def root_ca(url):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname or parsed_url.netloc or parsed_url.path or url
    try:
        output = subprocess.check_output(
            ["openssl", "s_client", "-showcerts", "-connect", f"{domain}:443"],
            input=b"", stderr=subprocess.DEVNULL, timeout=2
        ).decode()
        root_ca = None
        in_certificate = False
        for line in output.split("\n"):
            if "Certificate chain" in line:
                in_certificate = True
            if in_certificate and "O =" in line:
                root_ca = line.split("O =")[1].split(",")[0].strip()
        return root_ca
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError as e:
        raise e
    except Exception:
        return None

def rdns_names(url, ipv4s=None):
    if ipv4s is None:
        ipv4s = ipv4_addresses(url)
    rdns_results = []
    for address in ipv4s:
        try:
            names = socket.gethostbyaddr(address)
            rdns_results.append(names[0])  # append the primary name
        except Exception:
            continue
    return rdns_results

def rtt_range(url, addresses=None):
    if addresses is None:
        addresses = ipv4_addresses(url)
    rtt_times = []
    ports = [80, 22, 443]  # ports to check

    for address in addresses:
        for port in ports:
            try:
                start = time.time()
                with socket.create_connection((address, port), timeout=2):
                    end = time.time()
                rtt_times.append((end - start) * 1000)  # convert to milliseconds
            except Exception:
                continue  # skip if connection fails

    return [round(min(rtt_times), 2), round(max(rtt_times), 2)] if rtt_times else None

def geo_locations(url, addresses=None):
    if addresses is None:
        addresses = ipv4_addresses(url)
    try:
        with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
            locations = []
            for ip in addresses:
                location = reader.get(ip)
                if location:
                    city = location.get('city', {}).get('names', {}).get('en', '')
                    country = location.get('country', {}).get('names', {}).get('en', '')
                    if city or country:
                        locations.append(f"{city}, {country}".strip(", "))
            return list(set(locations))  # remove duplicates
    except FileNotFoundError as e:
        raise e
    except Exception:
        return []

def scan(url):
    result = {}

    # Compute scan_time
    try:
        value = scan_time(url)
        if value is not None:
            result['scan_time'] = value
    except Exception:
        pass

    # Compute ipv4_addresses
    try:
        value = ipv4_addresses(url)
        if value:
            result['ipv4_addresses'] = value
            ipv4s = value
        else:
            ipv4s = []
    except FileNotFoundError as e:
        print(f"Error: Required command-line tool is missing: {str(e)}", file=sys.stderr)
        ipv4s = []
    except Exception:
        ipv4s = []

    # Compute ipv6_addresses
    try:
        value = ipv6_addresses(url)
        if value:
            result['ipv6_addresses'] = value
    except FileNotFoundError as e:
        print(f"Error: Required command-line tool is missing: {str(e)}", file=sys.stderr)
    except Exception:
        result['ipv6_addresses'] = []

    # Compute http_server
    try:
        value = http_server(url)
        if value:
            result['http_server'] = value
        else:
            result['http_server'] = None
    except Exception:
        pass

    # Compute insecure_http
    try:
        value = insecure_http(url)
        result['insecure_http'] = value
    except Exception:
        pass

    # Compute redirect_to_https
    try:
        value = redirect_to_https(url)
        result['redirect_to_https'] = value
    except Exception:
        pass

    # Compute hsts
    try:
        value = hsts(url)
        result['hsts'] = value
    except Exception:
        pass

    # Compute tls_versions
    try:
        value = tls_versions(url)
        if value:
            result['tls_versions'] = value
        else:
            result['tls_versions'] = None
    except FileNotFoundError as e:
        print(f"Error: Required command-line tool is missing: {str(e)}", file=sys.stderr)
    except Exception:
        pass

    # Compute root_ca
    try:
        value = root_ca(url)
        if value:
            result['root_ca'] = value
    except FileNotFoundError as e:
        print(f"Error: Required command-line tool is missing: {str(e)}", file=sys.stderr)
    except Exception:
        pass

    # Now, functions that need ipv4s
    # rdns_names(url, ipv4s)
    try:
        value = rdns_names(url, ipv4s)
        if value:
            result['rdns_names'] = value
        else:
            result['rdns_names'] = []
    except Exception:
        pass

    # rtt_range(url, ipv4s)
    try:
        value = rtt_range(url, ipv4s)
        if value:
            result['rtt_range'] = value
    except Exception:
        result['rtt_range'] = None

    # geo_locations(url, ipv4s)
    try:
        value = geo_locations(url, ipv4s)
        if value:
            result['geo_locations'] = value
    except FileNotFoundError as e:
        print(f"Error: Required file is missing: {str(e)}", file=sys.stderr)
    except Exception:
        pass

    return result

def main(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f.readlines() if line.strip()]
        
        results = {}
        for domain in domains:
            print(f"Scanning {domain}...")
            results[domain] = scan(domain)
            
        with open(output_file, 'w') as f:
            json.dump(results, f, sort_keys=False, indent=4)
            print(f"Scan results written to {output_file}")
    except FileNotFoundError:
        print(f"Error: file {input_file} not found")
    except Exception as e:
        print(f"An exception occurred: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])