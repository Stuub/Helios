# Helios: Automated XSS Auditing

![image](https://github.com/user-attachments/assets/9f6f608d-9c00-49c2-9bad-455df258f74e)


## Features

- **Comprehensive Scanning**: Tests URL parameters, POST parameters, headers, and DOM content for XSS vulnerabilities.
- **Multiple Browser Support**: Compatible with both Firefox and Chrome for testing.
- **Headless Mode**: Option to run scans in headless browser mode for faster & traditional execution.
- **Concurrent Scanning**: Utilises multi-threading for efficient scanning of multiple targets.
- **Customizable**: Supports custom headers, cookies, and payload files.
- **Crawling Capability**: Can crawl websites to discover and test additional pages.
- **Detailed Reporting**: Provides comprehensive output with color-coded console logs and optional file output.
- **DOM XSS Detection**: Advanced detection of DOM-based XSS vulnerabilities.
- **Payload Customization**: Automatically customises payloads with unique identifiers for accurate detection.

## Key Capabilities

- URL parameter testing
- POST parameter analysis
- Header scanning
- DOM content examination
- External script analysis
- Crawling targets and depth control
- Custom payload support

## Usage

```
pip install -r requirements.txt
```

```
python3 helios.py [target_url] [options] 
```

## POST Method XSS

![image](https://github.com/user-attachments/assets/29b60c24-f832-43b6-b023-18981b462f38)

## DOM-Based XSS

![image](https://github.com/user-attachments/assets/f49efbf6-3a3c-483e-b7b5-dce426a63b41)


Use `python helios.py --help` for a full list of options and usage instructions.

## Future Development

- Getting gud
- Enhance payload generation dependant on context of target
- Optimize performance for large-scale scans, current still kinda sucks at speed - but any faster seems to produce false negatives :( 

## Note

Helios is currently in early stages of development. While it offers powerful scanning capabilities, users should be aware that it may contain bugs or limitations. Contributions and feedback are welcome to improve its functionality and reliability.

## Disclaimer

This tool is for educational and ethical testing purposes only. Always obtain proper authorization before scanning any web applications or networks you do not own or have explicit permission to test.

## Author

Created by @stuub

