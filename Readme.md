# 🌐 API Checker

A Python script to scan a website and check for broken or invalid links.

## Description

The goal of this project is to create a Python script that scans a given website and checks for broken or invalid links. The script will crawl through the web pages of the website, extract all the links, and then check the status of each link to determine if it is valid or broken.

## Note -> Please allow approximately 10 minutes for the scanning of available ports on the website. Your patience is appreciated.

## Features

- Takes a website URL as input from the user.
- Crawls the web pages of the given website and extracts all the links.
- Checks the status of each link to determine if it is valid or broken.
- Displays the total number of links checked, the number of valid links, and the number of broken links.
- Displays the URL of the page where a broken link was found and the broken link itself.
- Handles common HTTP status codes (e.g., 404 for not found, 200 for OK, etc.) to determine the status of the link.
- Handles exceptions and errors gracefully.
- Supports multi-threading or asynchronous requests to speed up the scanning process.
- Provides an option to save the results to a file.
- Allows limiting the depth of crawling (e.g., only scan links within a certain number of levels from the starting URL).

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/a7coder/API-CHECKER


2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt

3. Run the script:

   ```bash
    python link_checker.py

