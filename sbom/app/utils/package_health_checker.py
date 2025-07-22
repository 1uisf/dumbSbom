"""
Package Health Checker
Dynamically detects abandoned, deprecated, or problematic packages
"""

from typing import Dict, List, Optional
import requests
from datetime import datetime, timedelta
import json
import re

class PackageHealthChecker:
    """Dynamically detects abandoned, deprecated, or problematic packages"""
    
    def __init__(self):
        # Known critical packages that should always be flagged
        self.critical_packages = {
            'pycrypto': {
                'status': 'abandoned',
                'last_release': '2014-01-20',
                'warning': 'CRITICAL: PyCrypto is abandoned and has multiple security vulnerabilities. Use pycryptodome instead.',
                'recommendation': 'Replace with pycryptodome or pycryptodomex',
                'severity': 'critical',
                'cve_count': 5,
                'replacement': 'pycryptodome'
            },
            'django-rest-framework': {
                'status': 'alias_package',
                'last_release': '2011-01-01',
                'warning': 'CRITICAL: This is an old alias package for Django REST Framework. Use the correct package name.',
                'recommendation': 'Replace with djangorestframework (without hyphens)',
                'severity': 'critical',
                'replacement': 'djangorestframework'
            }
        }
        
        # Built-in Python modules (should be excluded from health checks)
        self.builtin_modules = {
            'hashlib', 'os', 'sys', 'json', 're', 'datetime', 'time', 'random',
            'collections', 'itertools', 'functools', 'pathlib', 'shutil',
            'subprocess', 'threading', 'multiprocessing', 'asyncio', 'logging',
            'urllib', 'http', 'socket', 'ssl', 'email', 'base64', 'zlib',
            'gzip', 'bz2', 'lzma', 'pickle', 'shelve', 'sqlite3', 'xml',
            'html', 'cgi', 'cgitb', 'wsgiref', 'urllib3', 'certifi',
            'charset_normalizer', 'idna', 'requests', 'pip', 'setuptools',
            'wheel', 'build', 'hatchling', 'flit', 'packaging', 'pyparsing',
            'six', 'python_dateutil', 'flask', 'werkzeug', 'jinja2',
            'markupsafe', 'itsdangerous', 'click', 'blinker', 'openpyxl',
            'et_xmlfile', 'numpy', 'pandas', 'matplotlib', 'scipy', 'sklearn',
            'tensorflow', 'torch', 'jupyter', 'ipython', 'notebook'
        }
        
        # Trust criteria - packages meeting these criteria are considered trusted
        self.trust_criteria = {
            'min_stars': 1000,  # GitHub stars (increased back to 1000)
            'min_forks': 100,    # GitHub forks (increased back to 100)
            'max_days_since_commit': 60,  # Last commit within 60 days (reduced from 90)
            'min_downloads_per_day': 1000,  # PyPI downloads (if available)
            'core_packages': {  # Only truly core packages that should always be trusted
                'setuptools', 'pip', 'wheel', 'build', 'hatchling', 'flit',
                'packaging', 'pyparsing', 'six', 'python-dateutil',
                'bcrypt', 'colorama', 'pyyaml', 'readme-renderer',
                'djangorestframework'  # Django REST Framework (correct package name)
            }
        }
        
        # Thresholds for dynamic detection - focused on abandoned packages
        self.thresholds = {
            'max_days_since_release': 365 * 2,  # 2 years - abandoned threshold
            'max_days_since_commit': 365 * 2,  # 2 years - abandoned threshold
            'min_stars_for_active': 100,  # Increased - low activity = abandoned
            'min_forks_for_active': 20,  # Increased - low activity = abandoned
            'max_issues_ratio': 0.05  # 5% of stars - high issues = problematic (more sensitive)
        }
    
    def check_package_health(self, package_name: str, version: Optional[str] = None) -> Optional[Dict]:
        """Dynamically check if a package has health issues"""
        package_name_lower = package_name.lower()
        
        # Skip built-in modules - they are part of Python's standard library
        if package_name_lower in self.builtin_modules:
            print(f"DEBUG: Skipping {package_name} - built-in module")
            return None
        
        # Skip trusted packages - they should never trigger warnings
        if self._is_trusted_package(package_name):
            print(f"DEBUG: Skipping {package_name} - trusted package")
            return None
        
        # Check if it's a known critical package
        if package_name_lower in self.critical_packages:
            print(f"DEBUG: Found {package_name} in critical packages list")
            return {
                'package_name': package_name,
                'version': version,
                'issue_type': 'critical_known',
                'details': self.critical_packages[package_name_lower],
                'severity': 'critical'
            }
        
        # Dynamic health check
        try:
            print(f"DEBUG: Running dynamic health check for {package_name}")
            health_issues = self._check_pypi_health(package_name, version)
            if health_issues:
                print(f"DEBUG: PyPI health check found issues for {package_name}")
                return health_issues
            
            # Check GitHub if available
            github_issues = self._check_github_health(package_name)
            if github_issues:
                print(f"DEBUG: GitHub health check found issues for {package_name}")
                return github_issues
            else:
                print(f"DEBUG: No health issues found for {package_name}")
                
        except Exception as e:
            print(f"Error checking health for {package_name}: {e}")
        
        return None
    
    def _check_pypi_health(self, package_name: str, version: Optional[str] = None) -> Optional[Dict]:
        """Check package health using PyPI metadata"""
        try:
            pypi_url = f"https://pypi.org/pypi/{package_name}/json"
            response = requests.get(pypi_url, timeout=10)
            
            if response.status_code != 200:
                return None
            
            pypi_data = response.json()
            
            # Check last release date
            releases = pypi_data.get('releases', {})
            if releases:
                # Get the latest release date
                latest_release = None
                for release_version, release_info in releases.items():
                    if release_info and len(release_info) > 0:
                        release_date = release_info[0].get('upload_time')
                        if release_date:
                            release_date = datetime.fromisoformat(release_date.replace('Z', '+00:00'))
                            if not latest_release or release_date > latest_release:
                                latest_release = release_date
                
                if latest_release:
                    days_since_release = (datetime.now().replace(tzinfo=latest_release.tzinfo) - latest_release).days
                    
                    if days_since_release > self.thresholds['max_days_since_release']:
                        # Determine severity based on how long abandoned
                        if days_since_release > 365 * 5:  # 5+ years
                            severity = 'critical'
                            status = 'severely_abandoned'
                        elif days_since_release > 365 * 3:  # 3+ years
                            severity = 'high'
                            status = 'very_abandoned'
                        else:  # 2+ years
                            severity = 'medium'
                            status = 'abandoned'
                        
                        return {
                            'package_name': package_name,
                            'version': version,
                            'issue_type': 'abandoned',
                            'details': {
                                'status': status,
                                'warning': f'This package has not been updated in {days_since_release} days ({days_since_release//365} years). It appears to be abandoned.',
                                'recommendation': 'Consider finding an alternative or checking if the project is still maintained.',
                                'severity': severity,
                                'days_since_release': days_since_release,
                                'years_abandoned': days_since_release // 365
                            },
                            'severity': severity
                        }
            
            # Check for deprecated classifiers
            info = pypi_data.get('info', {})
            classifiers = info.get('classifiers', [])
            
            for classifier in classifiers:
                if 'deprecated' in classifier.lower() or 'discontinued' in classifier.lower():
                    return {
                        'package_name': package_name,
                        'version': version,
                        'issue_type': 'deprecated',
                        'details': {
                            'status': 'deprecated',
                            'warning': f'This package is marked as deprecated: {classifier}',
                            'recommendation': 'Find an alternative package.',
                            'severity': 'high'
                        },
                        'severity': 'high'
                    }
            
            # Check for very low download counts (indicating abandonment)
            # Note: PyPI doesn't provide download stats in the JSON API anymore
            # We could use other metrics like GitHub stars/activity
            
        except Exception as e:
            print(f"Error checking PyPI health for {package_name}: {e}")
        
        return None
    
    def _check_github_health(self, package_name: str) -> Optional[Dict]:
        """Check package health using GitHub repository data"""
        try:
            # First get PyPI data to find the repository URL
            pypi_url = f"https://pypi.org/pypi/{package_name}/json"
            response = requests.get(pypi_url, timeout=10)
            
            if response.status_code != 200:
                return None
            
            pypi_data = response.json()
            info = pypi_data.get('info', {})
            
            # Extract repository URL
            repo_url = None
            for key in ['home_page', 'project_urls']:
                if key in info:
                    if key == 'project_urls' and info[key]:
                        for url_type, url in info[key].items():
                            if 'github.com' in url or 'gitlab.com' in url:
                                repo_url = url
                                break
                    elif key == 'home_page' and info[key]:
                        if 'github.com' in info[key] or 'gitlab.com' in info[key]:
                            repo_url = info[key]
            
            if not repo_url:
                return None
            
            # Extract GitHub repo info
            if 'github.com' in repo_url:
                match = re.search(r'github\.com/([^/]+/[^/]+)', repo_url)
                if match:
                    repo_path = match.group(1)
                    return self._check_github_repo_health(repo_path)
            
        except Exception as e:
            print(f"Error checking GitHub health for {package_name}: {e}")
        
        return None
    
    def _check_github_repo_health(self, repo_path: str) -> Optional[Dict]:
        """Check GitHub repository health"""
        try:
            # Use GitHub API to check repository status
            api_url = f"https://api.github.com/repos/{repo_path}"
            response = requests.get(api_url, timeout=10)
            
            if response.status_code != 200:
                return None
            
            repo_data = response.json()
            
            # Check if repository is archived
            if repo_data.get('archived', False):
                return {
                    'package_name': repo_path.split('/')[-1],
                    'issue_type': 'archived',
                    'details': {
                        'status': 'archived',
                        'warning': 'This package repository is archived and no longer maintained.',
                        'recommendation': 'Find an alternative package.',
                        'severity': 'high'
                    },
                    'severity': 'high'
                }
            
            # Check last commit date
            commits_url = f"https://api.github.com/repos/{repo_path}/commits"
            commits_response = requests.get(commits_url, timeout=10)
            
            if commits_response.status_code == 200:
                commits_data = commits_response.json()
                if commits_data:
                    last_commit_date = datetime.fromisoformat(
                        commits_data[0]['commit']['author']['date'].replace('Z', '+00:00')
                    )
                    days_since_commit = (datetime.now().replace(tzinfo=last_commit_date.tzinfo) - last_commit_date).days
                    
                    if days_since_commit > self.thresholds['max_days_since_commit']:
                        return {
                            'package_name': repo_path.split('/')[-1],
                            'issue_type': 'inactive',
                            'details': {
                                'status': 'inactive',
                                'warning': f'This package has not been updated in {days_since_commit} days.',
                                'recommendation': 'Consider finding an alternative or checking if the project is still maintained.',
                                'severity': 'medium',
                                'days_since_commit': days_since_commit
                            },
                            'severity': 'medium'
                        }
            
            # Check for low activity indicators - abandoned repositories
            stars = repo_data.get('stargazers_count', 0)
            forks = repo_data.get('forks_count', 0)
            open_issues = repo_data.get('open_issues_count', 0)
            
            # Check for very low activity (abandoned)
            if stars < self.thresholds['min_stars_for_active'] and forks < self.thresholds['min_forks_for_active']:
                severity = 'high' if stars < 50 and forks < 10 else 'medium'
                return {
                    'package_name': repo_path.split('/')[-1],
                    'issue_type': 'low_activity',
                    'details': {
                        'status': 'low_activity',
                        'warning': f'This package has very low community activity ({stars} stars, {forks} forks). It may be abandoned.',
                        'recommendation': 'Consider more popular alternatives with active maintenance.',
                        'severity': severity,
                        'stars': stars,
                        'forks': forks
                    },
                    'severity': severity
                }
            
            # Check for high issue ratio (indicates problems)
            if stars > 0:
                issue_ratio = open_issues / stars
                if issue_ratio > self.thresholds['max_issues_ratio']:
                    # Determine severity based on issue ratio
                    if issue_ratio > 0.2:  # Very high ratio (>20% of stars)
                        severity = 'high'
                    elif issue_ratio > 0.1:  # High ratio (>10% of stars)
                        severity = 'medium'
                    else:
                        severity = 'low'
                    
                    return {
                        'package_name': repo_path.split('/')[-1],
                        'issue_type': 'high_issues',
                        'details': {
                            'status': 'high_issues',
                            'warning': f'This package has a high ratio of open issues ({open_issues} issues, {stars} stars). It may be poorly maintained.',
                            'recommendation': 'Consider the project\'s maintenance status before using.',
                            'severity': severity,
                            'issue_ratio': round(issue_ratio, 2)
                        },
                        'severity': severity
                    }
            
        except Exception as e:
            print(f"Error checking GitHub repo health for {repo_path}: {e}")
        
        return None
    
    def _is_trusted_package(self, package_name: str) -> bool:
        """Check if a package meets trust criteria"""
        package_name_lower = package_name.lower()
        
        # Core packages are always trusted
        if package_name_lower in self.trust_criteria['core_packages']:
            return True
        
        # Check GitHub metrics for dynamic trust
        try:
            github_data = self._get_github_data(package_name)
            if github_data:
                stars = github_data.get('stargazers_count', 0)
                forks = github_data.get('forks_count', 0)
                last_commit = github_data.get('pushed_at')
                
                # Check if meets trust criteria
                if (stars >= self.trust_criteria['min_stars'] and 
                    forks >= self.trust_criteria['min_forks']):
                    
                    # Check recent activity
                    if last_commit:
                        commit_date = datetime.fromisoformat(last_commit.replace('Z', '+00:00'))
                        days_since_commit = (datetime.now().replace(tzinfo=commit_date.tzinfo) - commit_date).days
                        
                        if days_since_commit <= self.trust_criteria['max_days_since_commit']:
                            return True
                            
        except Exception as e:
            print(f"Error checking trust status for {package_name}: {e}")
        
        return False
    
    def _get_github_data(self, package_name: str) -> Optional[Dict]:
        """Get GitHub data for a package"""
        try:
            # Get PyPI data to find repository URL
            pypi_url = f"https://pypi.org/pypi/{package_name}/json"
            response = requests.get(pypi_url, timeout=10)
            
            if response.status_code != 200:
                return None
            
            pypi_data = response.json()
            info = pypi_data.get('info', {})
            
            # Extract repository URL
            repo_url = None
            for key in ['home_page', 'project_urls']:
                if key in info:
                    if key == 'project_urls' and info[key]:
                        for url_type, url in info[key].items():
                            if 'github.com' in url:
                                repo_url = url
                                break
                    elif key == 'home_page' and info[key]:
                        if 'github.com' in info[key]:
                            repo_url = info[key]
            
            if not repo_url:
                return None
            
            # Extract GitHub repo info
            match = re.search(r'github\.com/([^/]+/[^/]+)', repo_url)
            if match:
                repo_path = match.group(1)
                api_url = f"https://api.github.com/repos/{repo_path}"
                api_response = requests.get(api_url, timeout=10)
                
                if api_response.status_code == 200:
                    return api_response.json()
                    
        except Exception as e:
            print(f"Error getting GitHub data for {package_name}: {e}")
        
        return None 