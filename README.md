## RedWarden Lite - A lightweight HTTP/HTTPS reverse proxy for efficient, policy-based traffic filtering and redirection.

This project is a modified version of the original project [RedWarden](https://github.com/mgeeky/RedWarden)

Unlike the original RedWarden project, which is designed to work with specific apps and policies, RedWarden Lite is a universal HTTP/HTTPS proxy filter and redirector. This means you can deploy it to inspect, proxy, drop, or redirect traffic based on policies specified in the YAML config file. 

Several tests were made against traffic originating from different web browsers and both desktop and web applications.


![Process](resources/redwarden-lite.jpg?raw=true "Process")

## Core Features
- Listening on multiple ports: HTTP, HTTPS, or custom ports
- SSL inspection
- Support for proxying multiple URLs (final-allowed destinations)
- Flexible options to take action when a request does not comply with proxy policies: Reset, Redirect, Proxy
- Redirecting traffic that does not comply with rules to one or multiple URLs (random selection)
- Protection against replay attacks
- Whitelisting specific IP addresses to pass without policy checks
- Auto-whitelisting peers after X number of successful policy checks
- Banning IPs based on specific keywords in headers, such as `curl` in the user-agent
- Verifying peer IP using third-party IP information providers such as `ipgeolocation.io` and `ip-api.com`



### Policies
```YAML
policy:
  # [IP: ALLOW, reason:0] Request conforms ProxyPass entry (url="..." host="..."). Passing request to specified host
  allow_proxy_pass: True
  # [IP: ALLOW, reason:2] Peer's IP was added dynamically to a whitelist based on a number of allowed requests
  allow_dynamic_peer_whitelisting: True
  # [IP: DROP, reason:2] HTTP header name contained banned word
  drop_http_banned_header_names: True
  # [IP: DROP, reason:3] HTTP header value contained banned word:
  drop_http_banned_header_value: True
  # [IP: DROP, reason:4b] peer's reverse-IP lookup contained banned word
  drop_dangerous_ip_reverse_lookup: True
  # [IP: DROP, reason:4e] Peer's IP geolocation metadata contained banned keyword! Peer banned in generic fashion.
  drop_ipgeo_metadata_containing_banned_keywords: True
  # [IP: DROP, reason:5] HTTP request did not contain expected header
  drop_request_without_expected_header: False
  # [IP: DROP, reason:6] HTTP request did not contain expected header value:
  drop_request_without_expected_header_value: False
  # [IP: DROP, reason:7] Unexpected HTTP method:
  drop_request_without_expected_http_method: True
  # [IP: DROP, reason:8] Unexpected URIs:
  drop_request_without_expected_uri: False
```

### Usage
1. Grab a copy of RedWardenLite: `wget https://github.com/iomoath/RedWardenLite/archive/refs/heads/master.zip` or `git clone https://github.com/iomoath/RedWardenLite`
2. Extract the archive and adjust your settings in `example-config.yaml`
3. Run the command: `python RedWardenLite.py -c example-config.yaml`

* The application will keep running in the background; you may use screen or tmux to manage this.
* Tested on Ubuntu 18.04 (LTS) x64 with Python 3.8.3







## Credits
Special thanks to Mariusz Banach / mgeeky for the significant effort they put into [RedWarden](https://github.com/mgeeky/RedWarden)
```
   Mariusz Banach / mgeeky, '19-'21
   <mb [at] binary-offensive.com>
   (https://github.com/mgeeky) 
```