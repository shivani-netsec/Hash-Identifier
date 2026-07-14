# Hash Identifier

## Project Overview

Hash Identifier is a Python-based cybersecurity project developed to identify common hash algorithms and check whether a hash has been reported as malicious using the VirusTotal API.

The project allows users to analyze either a single hash entered manually or multiple hashes stored in a text file. After analysis, the program generates both a text report and a CSV report containing the results.

This project was developed as part of my Python learning journey to gain practical experience with file handling, APIs, functions, dictionaries, exception handling, and modular programming.

---

## Features

- Analyze a single hash
- Analyze multiple hashes from a file
- Validate hexadecimal hashes
- Identify common hash algorithms
  - MD5
  - SHA-1
  - SHA-224
  - SHA-256
  - SHA-384
  - SHA-512
- Retrieve malware detection statistics using the VirusTotal API
- Generate a text report (`report.txt`)
- Generate a CSV report (`report.csv`)
- Display a summary of the scan results

---

## Technologies Used

- Python 3
- Requests Library
- VirusTotal API
- Git & GitHub

---

## Project Structure

```
Hash-Identifier/
│
├── main.py
├── analyzer.py
├── virustotal.py
├── config.py
├── hashes.txt
├── report.txt
├── report.csv
├── requirements.txt
└── README.md
```

---

## Installation

1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/Hash-Identifier.git
```

2. Move into the project directory

```bash
cd Hash-Identifier
```

3. Install the required package

```bash
pip install -r requirements.txt
```

---

## VirusTotal API Key

This project requires a VirusTotal API key.

Create a file named .env in the project root:

VT_API_KEY=your_api_key_here

A free API key can be obtained by creating an account on the VirusTotal website.

---

## Running the Program

Run the following command:

```bash
python main.py
```

The program provides two options:

```
1. Analyze Single Hash
2. Analyze Hashes From File
```

For batch analysis, place one hash per line inside `hashes.txt`.

---

## Sample Output

```
========================================
HASH ANALYSIS REPORT
========================================
Hash        : 5d41402abc4b2a76b9719d911017c592
Length      : 32
Hexadecimal : Yes
Hash Type   : MD5

VirusTotal Analysis
-------------------------
Malicious : 0
Harmless  : 0
Suspicious: 0
Undetected: 58

Verdict: CLEAN
```

---

## Learning Outcomes

Through this project, I gained practical experience with:

- Python functions
- Dictionaries
- File handling
- Exception handling
- API integration
- JSON data processing
- Report generation
- Modular programming
- Version control using Git and GitHub

