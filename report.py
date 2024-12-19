# report.py

import sys
import json
from texttable import Texttable

def main(input_file, output_file):
    if len(sys.argv) != 3:
        sys.exit(1)

    with open(input_file, 'r') as f:
        data = json.load(f)

    total_domains = len(data)

    with open(output_file, 'w') as f:
        ################################
        # Section 1: Domain Information
        ################################
        for domain in data:
            f.write(f"Domain: {domain}\n")
            domain_data = data[domain]
            table = Texttable()
            table.set_cols_align(["l", "l"])
            table.set_cols_valign(["t", "t"])
            rows = [["Metric", "Value"]]
            for key, value in domain_data.items():
                # Format lists and dictionaries as strings
                if isinstance(value, list) or isinstance(value, dict):
                    value = json.dumps(value, indent=2)
                rows.append([key, str(value)])
            table.add_rows(rows)
            f.write(table.draw())
            f.write("\n\n")
        
        ########################
        # Section 2: RTT Ranges
        ########################
        rtt_data = []
        for domain in data:
            rtt_range = data[domain].get('rtt_range')
            if rtt_range and isinstance(rtt_range, list) and len(rtt_range) == 2:
                min_rtt, max_rtt = rtt_range
                rtt_data.append((domain, min_rtt, max_rtt))
        rtt_data.sort(key=lambda x: x[1])

        f.write("RTT Ranges for All Domains (Fastest to Slowest):\n")
        table = Texttable()
        table.set_cols_align(["l", "r", "r"])
        table.set_cols_valign(["t", "t", "t"])
        rows = [["Domain", "Min RTT (ms)", "Max RTT (ms)"]]
        for domain, min_rtt, max_rtt in rtt_data:
            rows.append([domain, f"{min_rtt}", f"{max_rtt}"])
        table.add_rows(rows)
        f.write(table.draw())
        f.write("\n\n")
        
        #################################
        # Section 3: Root CA Occurrences
        #################################
        root_ca_counts = {}
        for domain in data:
            root_ca = data[domain].get('root_ca')
            if root_ca:
                root_ca_counts[root_ca] = root_ca_counts.get(root_ca, 0) + 1
        sorted_root_ca = sorted(root_ca_counts.items(), key=lambda x: x[1], reverse=True)

        f.write("Root Certificate Authority Occurrences:\n")
        table = Texttable()
        table.set_cols_align(["l", "r"])
        table.set_cols_valign(["t", "t"])
        rows = [["Root CA", "Occurrences"]]
        for root_ca, count in sorted_root_ca:
            rows.append([root_ca, f"{count}"])
        table.add_rows(rows)
        f.write(table.draw())
        f.write("\n\n")

        #####################################
        # Section 4: HTTP Server Occurrences
        #####################################
        http_server_counts = {}
        for domain in data:
            http_server = data[domain].get('http_server')
            if http_server:
                http_server_counts[http_server] = http_server_counts.get(http_server, 0) + 1
        sorted_http_server = sorted(http_server_counts.items(), key=lambda x: x[1], reverse=True)

        f.write("HTTP Server Occurrences:\n")
        table = Texttable()
        table.set_cols_align(["l", "r"])
        table.set_cols_valign(["t", "t"])
        rows = [["HTTP Server", "Occurrences"]]
        for server, count in sorted_http_server:
            rows.append([server, f"{count}"])
        table.add_rows(rows)
        f.write(table.draw())
        f.write("\n\n")
        
        ###################################
        # Section 5: Percentage Statistics
        ###################################
        tls_versions_list = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        tls_version_counts = {version: 0 for version in tls_versions_list}
        insecure_http_count = 0
        redirect_to_https_count = 0
        hsts_count = 0
        ipv6_count = 0

        for domain in data:
            # TLS versions
            tls_versions_supported = data[domain].get('tls_versions')
            if tls_versions_supported:
                for version in tls_versions_supported:
                    if version in tls_version_counts:
                        tls_version_counts[version] += 1
            # insecure_http
            if data[domain].get('insecure_http') is True:
                insecure_http_count += 1
            # redirect_to_https
            if data[domain].get('redirect_to_https') is True:
                redirect_to_https_count += 1
            # hsts
            if data[domain].get('hsts') is True:
                hsts_count += 1
            # ipv6_addresses
            ipv6_addresses = data[domain].get('ipv6_addresses')
            if ipv6_addresses and isinstance(ipv6_addresses, list) and len(ipv6_addresses) > 0:
                ipv6_count += 1

        def percentage(part, whole):
            return 100 * float(part) / float(whole) if whole else 0

        f.write("Percentage of Domains Supporting Each TLS Version:\n")
        table = Texttable()
        table.set_cols_align(["l", "r"])
        table.set_cols_valign(["t", "t"])
        rows = [["TLS Version", "Percentage"]]
        for version in tls_versions_list:
            percent = percentage(tls_version_counts[version], total_domains)
            rows.append([version, f"{percent:.2f}%"])
        table.add_rows(rows)
        f.write(table.draw())
        f.write("\n\n")

        f.write("Percentage of Domains Supporting Various Features:\n")
        table = Texttable()
        table.set_cols_align(["l", "r"])
        table.set_cols_valign(["t", "t"])
        rows = [
            ["Feature", "Percentage"],
            ["Plain HTTP", f"{percentage(insecure_http_count, total_domains):.2f}%"],
            ["HTTPS Redirect", f"{percentage(redirect_to_https_count, total_domains):.2f}%"],
            ["HSTS", f"{percentage(hsts_count, total_domains):.2f}%"],
            ["IPv6", f"{percentage(ipv6_count, total_domains):.2f}%"]
        ]
        table.add_rows(rows)
        f.write(table.draw())
        f.write("\n\n")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])