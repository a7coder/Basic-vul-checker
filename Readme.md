# Website Basic Checker

A Python script to scan a website and check for basic vulnerabilities.

## Description

The goal of this project is to create a Python script that scans a given website and checks for broken or invalid links, Check if security headers aren't present, Scan the open ports, check the SSL/TLS version.

## Note -> Please allow approximately 10 minutes for the scanning of available ports on the website. Your patience is appreciated.

## Features

- Takes a website URL as input from the user. 
- Crawls the web pages of the given website and extracts all the links to find the broken links (Checks the status of each link to determine if it is valid or broken).
- Check the website for security headers and report if not present
- Scan the website IP for all active open ports along with the service name running on that port using multi-threading to speed up.
- Check the SSL/TLS version & expiry date to report basic overview
- Handles exceptions and errors gracefully.

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/thinkgroupy/API-CHECKER


2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt

3. Run the script:

   ```bash
    python script.py

## TEST WEBSITES

1. USE these websites to test:

- For Security Headers: http://www.deadlinkcity.com/
- For Port scanning: http://scanme.nmap.org/
- For Broken Links: http://www.deadlinkcity.com/
