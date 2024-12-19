# Net-Probe

**Net-Probe** is a lightweight and flexible network monitoring tool designed to help you analyze network traffic, measure latency, and monitor packet loss in real time. It can be used for network performance diagnostics, ensuring that your network operates at peak efficiency.

## Files
scan.py is a comprehensive Python script designed to perform in-depth analyses of a list of domains. It systematically gathers a wide range of network and security-related information for each domain, including IPv4 and IPv6 addresses through DNS lookups, detection of the HTTP server software, and assessment of security features like HTTP Strict Transport Security (HSTS) and support for various TLS/SSL versions. Additionally, it measures network performance metrics such as Round-Trip Time (RTT) to common ports and retrieves geographical locations of the domain's IP addresses using the MaxMind GeoLite2 database.

report.py complements scan.py by taking the structured JSON data generated from the scans and transforming it into a comprehensive, human-readable report. Utilizing the Texttable library, it organizes the information into well-formatted tables that display individual domain metrics, aggregated statistics, and insightful analyses. The report includes sections such as Domain Information, RTT Ranges, Root Certificate Authority occurrences, HTTP Server occurrences, and Percentage Statistics for various security and performance features. This structured presentation allows users to easily interpret the results, identify trends, and make informed decisions based on the scanned data.

Together, scan.py and report.py provide a powerful toolkit for network administrators and security professionals to assess and document the state of multiple domains efficiently.


## Features

- **Real-Time Network Monitoring**: Track live network statistics including latency and packet loss.
- **Packet Loss Detection**: Measure the percentage of lost packets to identify possible network issues.
- **Latency Measurement**: Continuously track network round-trip times (RTT) to detect performance degradation.
- **Customizable Configuration**: Easily adjust monitoring parameters to fit your network environment.
- **Lightweight & Efficient**: Minimal impact on system resources.