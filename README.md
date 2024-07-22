# Helios: Automated XSS Auditing

![image](https://github.com/user-attachments/assets/9f6f608d-9c00-49c2-9bad-455df258f74e)


## Features

- **Comprehensive Scanning**: Tests URL parameters, POST parameters, headers, and DOM content for XSS vulnerabilities.
- **Multiple Browser Support**: Compatible with both Firefox and Chrome for testing.
- **Headless Mode**: Option to run scans in headless browser mode for faster & traditional execution.
- **Paralellised Scanning**: Utilises multi-threading for efficient scanning of multiple targets.
- **Customizable**: Supports custom headers, cookies, and payload files.
- **Crawling Capability**: Can crawl websites to discover and test additional pages.
- **Detailed Reporting**: Provides comprehensive output with color-coded console logs and optional file output.
- **DOM XSS Detection**: Advanced detection of DOM-based XSS vulnerabilities.
- **Payload Customization**: Automatically customises payloads with unique identifiers for accurate detection.
- **Tamper Techniques**: WAF evasion techniques
- **Detection of SQLi**: Validates whether SQLi is also indicative within responses


## Key Capabilities

- URL parameter analysis & testing
- POST parameter analysis & testing
- DOM content analysis & testing
- Header testing
- External script analysis
- Crawling targets and depth control
- Custom payload support
- Accurate detection
- Parallelised tasks


## Usage

```
pip install -r requirements.txt
```

```
python3 helios.py [target_url] [options] 
```

## Example

```
python3 helios.py target.com -o output.txt --crawl
```

```
python3 helios.py -l targetlist.txt --payload-file xsspayloads.txt -o output.txt --crawl --headless --cookies "Name=abcdefg" --headers "X-Forwarded For: 127.0.0.1"
```

Use `python helios.py --help` for a full list of options and usage instructions.


## POST Method XSS

![image](https://github.com/user-attachments/assets/29b60c24-f832-43b6-b023-18981b462f38)

## DOM-Based XSS

![image](https://github.com/user-attachments/assets/f49efbf6-3a3c-483e-b7b5-dce426a63b41)

## Accurate Payload Detection

![image](https://github.com/user-attachments/assets/96f7d2bf-cdf9-46cd-8b72-c0fa6fcebcc6)

## SQLI Detection

![image](https://github.com/user-attachments/assets/cca33815-5e24-45bc-aea4-9a1cf6eae9d3)

## Scan Summaries

![image](https://github.com/user-attachments/assets/19ff0dde-08a9-4662-a487-9b0cfca7be4f)


## Future Development

- Getting gud
- Enhance payload generation dependant on context of target

## Note

Helios is currently in early stages of development. While it offers powerful scanning capabilities, users should be aware that it may contain bugs or limitations. Contributions and feedback are welcome to improve its functionality and reliability.

## Disclaimer

This tool is for educational and ethical testing purposes only. Always obtain proper authorization before scanning any web applications or networks you do not own or have explicit permission to test.

## Author

Created by @stuub

