# SBOM Generator & Security Analysis Platform

A Flask-based application that generates Software Bills of Materials (SBOMs) from Python project dependency files and performs comprehensive vulnerability and package health analysis.

## Overview

This platform transforms Python dependency files into standardized SPDX SBOMs while providing advanced vulnerability and package health analysis. The system includes vulnerability scanning, risk assessment, GitHub enrichment, and detection of abandoned or problematic packages.

## Features

### Core Functionality

- **SBOM Generation**: Creates SPDX 2.3 format SBOMs from Python dependency files
- **Vulnerability Scanning**: Real-time scanning via OSV (Open Source Vulnerabilities) database
- **Risk Assessment**: Calculates risk scores (0-100) with severity classifications
- **Dependency Analysis**: Maps complete dependency trees including subdependencies
- **GitHub Enrichment**: Fetches repository metadata (stars, forks, issues, last commit) for dependencies
- **Package Health Checking**: Detects abandoned, deprecated, or problematic packages using dynamic and static analysis

### Performance & Storage

- **Local Caching**: SQLite database for vulnerability data caching (24-hour TTL)
- **Session Management**: Persistent scan result storage and retrieval
- **Rate Limiting**: Controlled API request handling with parallel processing
- **Export Capabilities**: Excel reports, SPDX (JSON) format exports, and export interactive dependency graph as PNG image

## Architecture

The platform implements a layered architecture with the following components:

```
Vulnerability Scanner (Detection & Scoring)
    ↓
GitHub Enrichment & Health Checker (Metadata & Health)
    ↓
Caching Database (Performance Layer)
    ↓
SBOM Generator (Dependency Parsing)
```

## Module Documentation

### Core Modules

| Module                    | Responsibility                                                   |
|---------------------------|------------------------------------------------------------------|
| `sbom_analyzer.py`        | Dependency parsing, subdependency resolution, SPDX generation, orchestrates analysis |
| `vulnerability_scanner.py`| OSV API integration, risk scoring, vulnerability detection       |
| `vulnerability_database.py`| SQLite caching, scan result persistence, data management         |
| `github_fetcher.py`       | Fetches GitHub repository metadata for dependencies              |
| `package_health_checker.py`| Detects abandoned, deprecated, or problematic packages           |
| `routes.py`               | Flask routing, API endpoints, request handling                   |

## Installation

### Requirements

- Python 3.8+
- pip package manager

#### Python dependencies (from `requirements.txt`):
```
Flask>=2.0.0
Werkzeug>=2.0.0
requests>=2.25.0
packaging>=21.0
openpyxl>=3.0.0
python-dotenv>=0.19.0
toml>=0.10.0
```

### Quick Setup

```bash
# Clone repository
git clone <repository-url>
cd sbom

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### GitHub Token Setup (Optional, but recommended)

To enable advanced GitHub repository analysis, **click the 'Enter GitHub API Token' button in the web interface** and paste your token. You no longer need to create a `.env` file manually.

**How to get your GitHub token:**
1. Go to [GitHub Settings → Developer settings → Personal access tokens](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Select `public_repo` scope
4. Copy the token and enter it in the web UI

**Note:** Without a token, GitHub API calls are limited to 60 requests/hour. With a token, you get 5,000+ requests/hour.

### Running the Application

```bash
python run.py
```

The application will be available at `http://localhost:5001`

## Usage

### Basic Operation

1. Upload a Python dependency file (`requirements.txt`, `pyproject.toml`, or `Pipfile`).
2. Submit for analysis via the web interface.
3. Review generated SBOM and vulnerability analysis.
4. Access GitHub enrichment and package health insights.
5. Export results in desired format (Excel, SPDX, or export the dependency graph as a PNG image from the results page).
   - SPDX export is provided in JSON format (not tag-value text)

### Supported File Types

- **Python**: `requirements.txt`, `pyproject.toml`, `Pipfile`

## API Endpoints

- `POST /upload` — Upload and analyze dependency files
- `GET /results` — View analysis results
- `GET /api/scan_data` — Retrieve scan data via API
- `GET /api/vulnerabilities/<package_name>` — Get vulnerability data for a specific package
- `GET /api/package_health` — Get package health data for the current scan
- `GET /api/recent_scans` — List recent scans
- `GET /api/scan_result/<scan_id>` — Get full scan result by scan_id
- `POST /export_excel` — Generate Excel reports
- `POST /export_spdx` — Generate SPDX SBOM file (JSON format)
- `POST /api/github_token` — Set GitHub token (used by UI)
- `GET /api/github_token/status` — Get GitHub token status
- `POST /api/github_token/clear` — Clear GitHub token

## Technical Implementation

### Vulnerability Detection Process

1. Parse dependency files to extract package names and versions
2. Query PyPI API for package metadata and subdependencies
3. Query OSV database for known vulnerabilities
4. Calculate risk scores based on CVSS data and severity levels
5. Enrich dependencies with GitHub repository metadata
6. Check for abandoned or problematic packages
7. Cache results in local SQLite database
8. Generate comprehensive analysis reports

### Data Sources

- OSV (Open Source Vulnerabilities) Database
- PyPI API for Python package metadata and subdependency resolution
- GitHub Security Advisories

## Configuration

### Environment Variables

- `SECRET_KEY`: Flask session security key
- Default port: 5001 (configurable in run.py)

### Database

- SQLite database automatically created on first run
- Location: `vulnerability_cache.db` in project root
- Schema includes vulnerability cache and scan results tables

## License

This project is developed for educational and research purposes.

## Contributing

This codebase implements a modular architecture designed for extensibility. New analysis modules can be added to the `app/utils/` directory following the established patterns.
