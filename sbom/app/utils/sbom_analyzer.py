"""
SBOM Generation and Analysis Module
"""

import json
import re
from datetime import datetime
from pathlib import Path
import requests
from .vulnerability_scanner import VulnerabilityScanner, PackageRisk
from .github_fetcher import GitHubFetcher
from .package_health_checker import PackageHealthChecker
import concurrent.futures
from .vulnerability_database import VulnerabilityDatabase
from config import check_github_token
from flask import session


def is_runtime_dependency(req_str):
    """Return True if the requirement string is a runtime dependency (not test/dev/extra)."""
    # Exclude dependencies with extras or environment markers for test/dev
    # Example: 'pytest; extra == "test"', 'pytest; extra == "dev"', etc.
    if ';' in req_str:
        marker = req_str.split(';', 1)[1].strip().lower()
        if 'extra == "test"' in marker or 'extra == "dev"' in marker or 'extra == "docs"' in marker:
            return False
        # Also filter out any requirement with "; extra" (even without specific extra name)
        if 'extra' in marker:
            return False
    # Exclude common test/dev packages by name (optional, can expand)
    test_dev_pkgs = {'pytest', 'pytest-xdist', 'pytest-cov', 'coverage', 'tox', 'black', 'flake8', 'mypy', 'reno', 'sphinx'}
    pkg_name = extract_package_name(req_str)
    if pkg_name.lower() in test_dev_pkgs:
        return False
    return True


def clean_package_name(pkg_name):
    """Clean package name by removing platform-specific markers and long conditional expressions."""
    if not pkg_name:
        return pkg_name
    
    # Remove platform-specific markers and long conditional expressions
    # These often appear as: package-"platform" or package-(long_condition)
    cleaned = pkg_name
    
    # Remove quoted platform markers like "aarch64", "x86_64", etc.
    # Pattern: package-"platform" -> package
    import re
    cleaned = re.sub(r'-["\']([^"\']+)["\']', '', cleaned)
    
    # Remove long conditional expressions in parentheses
    # Pattern: package-(long_condition) -> package
    # This handles cases like: greenlet-(platform_machine == "x86_64" or ...)
    cleaned = re.sub(r'-[\(][^)]{20,}[\)]', '', cleaned)
    
    # Remove any remaining platform markers that might be left
    # Common platform identifiers
    platform_patterns = [
        r'-aarch64', r'-x86_64', r'-amd64', r'-ppc64le', r'-win32', r'-WIN32',
        r'-linux', r'-macos', r'-windows', r'-darwin',
        r'-cp\d+', r'-py\d+', r'-abi\d+',  # Python version markers
    ]
    
    for pattern in platform_patterns:
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)
    
    # Clean up any double dashes or trailing dashes
    cleaned = re.sub(r'-+', '-', cleaned)  # Replace multiple dashes with single
    cleaned = cleaned.rstrip('-')  # Remove trailing dash
    
    return cleaned.strip()


def extract_package_name(req_str):
    """Extract clean package name from requirement string."""
    # Remove version specifiers and extras
    pkg_name = req_str.split('[')[0]  # Remove extras like [dev]
    pkg_name = pkg_name.split('==')[0]  # Remove == version
    pkg_name = pkg_name.split('>=')[0]  # Remove >= version
    pkg_name = pkg_name.split('<=')[0]  # Remove <= version
    pkg_name = pkg_name.split('!=')[0]  # Remove != version
    pkg_name = pkg_name.split('<')[0]   # Remove < version
    pkg_name = pkg_name.split('>')[0]   # Remove > version
    pkg_name = pkg_name.split('~=')[0]  # Remove ~= version
    pkg_name = pkg_name.split('===')[0] # Remove === version
    pkg_name = pkg_name.strip()
    
    # Clean the package name to remove platform-specific markers
    return clean_package_name(pkg_name)


def fetch_pypi_subdependencies(package_name, seen=None, depth=0, max_depth=1, max_packages_per_level=20, direct_deps=None):
    """Recursively fetch unique, runtime sub-dependencies from PyPI JSON API, up to max_depth."""
    if seen is None:
        seen = set()
    if direct_deps is None:
        direct_deps = set()
    if package_name in seen or depth >= max_depth:
        return []  # Prevent cycles and limit depth
    seen.add(package_name)
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
        requires_dist = data.get('info', {}).get('requires_dist', [])
        if requires_dist is None:
            requires_dist = []
        subdeps = []
        seen_in_branch = set()  # Track duplicates within this branch
        
        # Limit the number of packages fetched per level to prevent explosion
        packages_fetched = 0
        
        for req in requires_dist:
            # Stop if we've reached the limit for this level
            if packages_fetched >= max_packages_per_level:
                break
                
            # Filter out non-runtime dependencies
            if not is_runtime_dependency(req):
                continue
                
            # Extract package name (before any version specifiers)
            pkg_name = extract_package_name(req)
            
            # Skip if already seen in this branch (duplicate)
            if pkg_name in seen_in_branch:
                continue
            seen_in_branch.add(pkg_name)
            
            # Skip if this package is already a direct dependency (case-insensitive)
            if pkg_name.lower() in direct_deps:
                print(f"⚠️ Skipping {pkg_name} - already a direct dependency")
                continue
            
            # Also skip if this package name (case-insensitive) is already a direct dependency
            # This handles cases like "werkzeug" vs "Werkzeug"
            direct_dep_names_lower = {name.lower() for name in direct_deps}
            if pkg_name.lower() in direct_dep_names_lower:
                print(f"⚠️ Skipping {pkg_name} - already a direct dependency (case-insensitive)")
                continue
            
            # Try to extract version information from the requirement string
            version = 'unknown'
            if '==' in req:
                # Exact version: requests==2.31.0
                version = req.split('==', 1)[1].split(';')[0].strip()
            elif '>=' in req and '<' not in req:
                # Minimum version: requests>=2.25.0
                version = req.split('>=', 1)[1].split(';')[0].strip()
            elif '~=' in req:
                # Compatible release: requests~=2.31.0
                version = req.split('~=', 1)[1].split(';')[0].strip()
            elif '===' in req:
                # Arbitrary equality: requests===2.31.0
                version = req.split('===', 1)[1].split(';')[0].strip()
            else:
                # No version specified or complex version spec
                version = 'flexible'
            
            # Create subdependency dict
            subdep = {
                'name': pkg_name,
                'version': version,
                'type': 'python',
                'subdependencies': []
            }
            
            # Only add sub-dependencies if we haven't reached max_depth
            if depth + 1 < max_depth:
                # Recursively fetch sub-dependencies with a copy of seen to prevent cycles
                subdep['subdependencies'] = fetch_pypi_subdependencies(
                    pkg_name, seen.copy(), depth + 1, max_depth, max_packages_per_level, direct_deps
                )
            
            subdeps.append(subdep)
            packages_fetched += 1
        
        return subdeps
    except Exception as e:
        print(f"Error fetching subdependencies for {package_name}: {e}")
        return []


def parse_requirements_txt(filepath, max_depth=1, max_packages_per_level=20):
    """Parse Python requirements.txt file and fetch sub-dependencies from PyPI."""
    dependencies = []
    
    # First pass: collect all direct dependencies
    direct_deps = set()
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            # Remove inline comments
            line = line.split('#', 1)[0].strip()
            if not line or line.startswith('#'):
                continue
            # Skip lines that are not installable packages
            if (line.startswith('-') or line.startswith('--') or
                line.startswith('git+') or '://' in line or
                line.startswith('http') or line.startswith('https')):
                print(f"[WARN] Skipping non-package line: {line}")
                continue
            if line.startswith('-e') or line.startswith('-r') or line.startswith('-c'):
                print(f"[WARN] Skipping editable/include/constraint line: {line}")
                continue
            # Remove environment markers (anything after ';')
            if ';' in line:
                line = line.split(';', 1)[0].strip()
            if not line:
                continue
            try:
                # Handle extras (package[extra]==1.2.3)
                pkg_part = line
                version = 'latest'
                if '==' in line:
                    pkg_part, version = line.split('==', 1)
                elif '>=' in line:
                    pkg_part, version = line.split('>=', 1)
                    # Use the minimum version for >= requirements
                    version = version.strip()
                elif '<=' in line:
                    pkg_part, version = line.split('<=', 1)
                    version = 'flexible'
                elif '>' in line:
                    pkg_part, version = line.split('>', 1)
                    version = 'flexible'
                elif '<' in line:
                    pkg_part, version = line.split('<', 1)
                    version = 'flexible'
                elif '~=' in line:
                    pkg_part, version = line.split('~=', 1)
                    version = 'flexible'
                elif '===' in line:
                    pkg_part, version = line.split('===', 1)
                # Remove extras
                pkg_name = pkg_part.split('[')[0].strip()
                if not re.match(r'^[a-zA-Z0-9_.-]+$', pkg_name):
                    print(f"[WARN] Skipping unrecognized package name: {pkg_name}")
                    continue
                
                # Add to direct dependencies set
                direct_deps.add(pkg_name.lower())
            except Exception as e:
                print(f"[ERROR] Failed to parse line: {line} | Error: {e}")
                continue

    # Second pass: build dependency tree with sub-dependencies (parallelized)
    dep_lines = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            # Remove inline comments
            line = line.split('#', 1)[0].strip()
            if not line or line.startswith('#'):
                continue
            # Skip lines that are not installable packages
            if (line.startswith('-') or line.startswith('--') or
                line.startswith('git+') or '://' in line or
                line.startswith('http') or line.startswith('https')):
                continue
            if line.startswith('-e') or line.startswith('-r') or line.startswith('-c'):
                continue
            # Remove environment markers (anything after ';')
            if ';' in line:
                line = line.split(';', 1)[0].strip()
            if not line:
                continue
            dep_lines.append(line)

    def build_dep(line):
        try:
            pkg_part = line
            version = 'latest'
            if '==' in line:
                pkg_part, version = line.split('==', 1)
            elif '>=' in line:
                pkg_part, version = line.split('>=', 1)
                version = version.strip()
            elif '<=' in line:
                pkg_part, version = line.split('<=', 1)
                version = 'flexible'
            elif '>' in line:
                pkg_part, version = line.split('>', 1)
                version = 'flexible'
            elif '<' in line:
                pkg_part, version = line.split('<', 1)
                version = 'flexible'
            elif '~=' in line:
                pkg_part, version = line.split('~=', 1)
                version = 'flexible'
            elif '===' in line:
                pkg_part, version = line.split('===', 1)
            pkg_name = pkg_part.split('[')[0].strip()
            if not re.match(r'^[a-zA-Z0-9_.-]+$', pkg_name):
                return None
            dep = {'name': pkg_name, 'version': version.strip(), 'type': 'python'}
            subdeps = fetch_pypi_subdependencies(
                dep['name'], depth=0, max_depth=max_depth, max_packages_per_level=max_packages_per_level,
                direct_deps=direct_deps
            )
            dep['subdependencies'] = subdeps  # type: ignore
            return dep
        except Exception as e:
            print(f"[ERROR] Failed to parse line: {line} | Error: {e}")
            return None

    # --- Old sequential system (commented out for rollback) ---
    # with open(filepath, 'r') as f:
    #     for line in f:
    #         ... (original sequential code here)
    #         dependencies.append(dep)

    # --- Parallelized system ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(build_dep, dep_lines))
    dependencies = [dep for dep in results if dep is not None]
    return dependencies


def clean_version_string(version_str):
    """Clean version string by removing comparison operators and quotes"""
    if not version_str or version_str == '*':
        return '*'
    
    # Remove quotes
    version_str = version_str.strip('"\'')
    
    # Remove common comparison operators
    operators = ['==', '>=', '<=', '>', '<', '~=', '!=']
    for op in operators:
        if version_str.startswith(op):
            return version_str[len(op):]
    
    return version_str

def extract_base_version(version_str):
    if not version_str or version_str == "*":
        return "flexible"
    version_str = str(version_str).strip()
    # Remove common specifiers and extract the first version number
    match = re.search(r"(\d+\.\d+(?:\.\d+)?)", version_str)
    if match:
        return match.group(1)
    return "flexible"

def split_name_version(dep_str):
    """Split dependency string into name and version, handling formats like 'package>=1.2.3'."""
    import re
    match = re.match(r'^([A-Za-z0-9_.-]+)', dep_str)
    if match:
        name = match.group(1)
        version = dep_str[len(name):].strip() or "*"
        return name, version
    return dep_str, "*"

def parse_pipfile(filepath, max_depth=1, max_packages_per_level=20):
    """Parse Python Pipfile file"""
    dependencies = []
    direct_deps = set()
    
    try:
        import toml
        with open(filepath, 'r') as f:
            data = toml.load(f)
        
        # Parse both [packages] and [dev-packages] sections
        for section in ['packages', 'dev-packages']:
            if section in data:
                for name, version_info in data[section].items():
                    direct_deps.add(name)
                    
                    # Handle different version formats
                    if isinstance(version_info, str):
                        version = clean_version_string(version_info)
                    elif isinstance(version_info, dict):
                        version = clean_version_string(version_info.get('version', '*'))
                    else:
                        version = '*'
                    
                    dep = {
                        'name': name,
                        'version': version,
                        'type': 'python',
                        'dev': section == 'dev-packages'
                    }
                    
                    # Fetch subdependencies
                    subdeps = fetch_pypi_subdependencies(
                        name, depth=0, max_depth=max_depth, max_packages_per_level=max_packages_per_level,
                        direct_deps=direct_deps
                    )
                    dep['subdependencies'] = subdeps
                    dependencies.append(dep)
                    
    except Exception as e:
        print(f"Error parsing Pipfile: {e}")
    
    return dependencies


def parse_pyproject_toml(filepath, max_depth=1, max_packages_per_level=20):
    """Parse pyproject.toml for dependencies (PEP 621 and Poetry)."""
    dependencies = []
    direct_deps = set()
    try:
        import toml
        with open(filepath, 'r') as f:
            data = toml.load(f)

        # Poetry dependencies
        poetry = data.get("tool", {}).get("poetry", {})
        for name, version in poetry.get("dependencies", {}).items():
            if name.lower() == "python":
                continue
            base_version = extract_base_version(version)
            direct_deps.add(name)
            dep = {
                'name': name,
                'version': base_version,
                'type': 'python',
                'dev': False
            }
            subdeps = fetch_pypi_subdependencies(
                name, depth=0, max_depth=max_depth, max_packages_per_level=max_packages_per_level,
                direct_deps=direct_deps
            )
            dep['subdependencies'] = subdeps
            dependencies.append(dep)
        for name, version in poetry.get("dev-dependencies", {}).items():
            base_version = extract_base_version(version)
            direct_deps.add(name)
            dep = {
                'name': name,
                'version': base_version,
                'type': 'python',
                'dev': True
            }
            subdeps = fetch_pypi_subdependencies(
                name, depth=0, max_depth=max_depth, max_packages_per_level=max_packages_per_level,
                direct_deps=direct_deps
            )
            dep['subdependencies'] = subdeps
            dependencies.append(dep)

        # PEP 621 dependencies
        project = data.get("project", {})
        for dep in project.get("dependencies", []):
            # dep is like "flask >=2.3.0" or "flask>=2.3.0" or just "flask"
            name, version = split_name_version(dep)
            base_version = extract_base_version(version)
            direct_deps.add(name)
            dep_obj = {
                'name': name,
                'version': base_version,
                'type': 'python',
                'dev': False
            }
            subdeps = fetch_pypi_subdependencies(
                name, depth=0, max_depth=max_depth, max_packages_per_level=max_packages_per_level,
                direct_deps=direct_deps
            )
            dep_obj['subdependencies'] = subdeps
            dependencies.append(dep_obj)
        # Optional dependencies (PEP 621)
        for opt_deps in project.get("optional-dependencies", {}).values():
            for dep in opt_deps:
                name, version = split_name_version(dep)
                base_version = extract_base_version(version)
                direct_deps.add(name)
                dep_obj = {
                    'name': name,
                    'version': base_version,
                    'type': 'python',
                    'dev': True
                }
                subdeps = fetch_pypi_subdependencies(
                    name, depth=0, max_depth=max_depth, max_packages_per_level=max_packages_per_level,
                    direct_deps=direct_deps
                )
                dep_obj['subdependencies'] = subdeps
                dependencies.append(dep_obj)
    except Exception as e:
        print(f"Error parsing pyproject.toml: {e}")
    return dependencies


def generate_spdx_sbom(dependencies, project_type, filename):
    """Generate SPDX format SBOM"""
    timestamp = datetime.now().isoformat()
    
    sbom = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: SBOM-Generator"],
            "licenseListVersion": "3.19"
        },
        "name": f"SBOM for {filename}",
        "dataLicense": "CC0-1.0",
        "packages": []
    }
    
    for i, dep in enumerate(dependencies):
        # Only use expected fields, ignore subdependencies
        package = {
            "SPDXID": f"SPDXRef-Package-{i+1}",
            "name": dep.get('name', ''),
            "versionInfo": dep.get('version', ''),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceType": f"{project_type}-package",
                    "referenceLocator": dep.get('name', '')
                }
            ]
        }
        sbom["packages"].append(package)
    
    return sbom


def flatten_dependencies_tree(dependencies):
    """Flatten the dependency tree to a list of top-level dependencies (no subdependencies)."""
    flat = []
    for dep in dependencies:
        flat.append({
            'name': dep.get('name', ''),
            'version': dep.get('version', ''),
            'type': dep.get('type', '')
        })
    return flat


def generate_sbom_from_file(filepath, project_type, max_depth=1, max_packages_per_level=20):
    """Generate SBOM from project dependency file with configurable depth limits"""
    filename = Path(filepath).name
    dependencies = []
    dependency_tree = []
    
    if project_type == 'python':
        # Determine the specific Python file type
        filename_lower = filename.lower()
        if 'pipfile' in filename_lower:
            dependency_tree = parse_pipfile(filepath, max_depth, max_packages_per_level)
        elif 'pyproject.toml' in filename_lower:
            dependency_tree = parse_pyproject_toml(filepath, max_depth, max_packages_per_level)
        else:
            # Default to requirements.txt parsing
            dependency_tree = parse_requirements_txt(filepath, max_depth, max_packages_per_level)
        dependencies = flatten_dependencies_tree(dependency_tree)
    else:
        raise ValueError(f"Unsupported project type: {project_type}")
    
    # Generate SPDX format SBOM
    sbom = generate_spdx_sbom(dependencies, project_type, filename)
    
    # Calculate performance metrics
    total_dependencies = count_total_dependencies(dependency_tree)
    max_depth_actual = calculate_actual_depth(dependency_tree)
    
    return {
        'format': 'SPDX',
        'dependencies_count': len(dependencies),
        'total_dependencies': total_dependencies,
        'max_depth_actual': max_depth_actual,
        'max_depth_requested': max_depth,
        'project_type': project_type,
        'generated_at': datetime.now().isoformat(),
        'sbom_data': sbom,
        'dependencies': dependencies,  # flat list for SPDX and consumers
        'dependency_tree': dependency_tree  # full tree with subdependencies
    }


def count_total_dependencies(dependency_tree):
    """Count total number of dependencies including sub-dependencies"""
    count = 0
    for dep in dependency_tree:
        count += 1  # Count the dependency itself
        if dep.get('subdependencies'):
            count += count_total_dependencies(dep['subdependencies'])
    return count


def calculate_actual_depth(dependency_tree, current_depth=0):
    """Calculate the actual maximum depth of the dependency tree"""
    if not dependency_tree:
        return current_depth
    
    max_depth = current_depth
    for dep in dependency_tree:
        if dep.get('subdependencies'):
            sub_depth = calculate_actual_depth(dep['subdependencies'], current_depth + 1)
            max_depth = max(max_depth, sub_depth)
    
    return max_depth


class SBOMAnalyzer:
    """Boilerplate for SBOM analysis operations"""
    def __init__(self):
        self.vulnerability_scanner = VulnerabilityScanner()
        self.github_fetcher = GitHubFetcher()
        self.package_health_checker = PackageHealthChecker()
    
    def scan_vulnerabilities(self, dependency_tree):
        """Scan all dependencies for vulnerabilities and return risk assessment and skipped dependencies."""
        flattened_deps, skipped = self._flatten_dependencies_for_scanning(dependency_tree)
        vuln_data = self.vulnerability_scanner.scan_dependencies(flattened_deps)
        return vuln_data, skipped
    
    def enrich_with_github_data(self, dependencies):
        """Enrich dependencies with GitHub repository information"""
        enriched_deps = []
        total_attempts = 0
        successes = 0
        
        for dep in dependencies:
            enriched_dep = dep.copy()
            # Only try to get GitHub data for Python packages with known versions
            if dep.get('type') == 'python' and dep.get('version') not in ['unknown', 'flexible', 'latest', '*']:
                total_attempts += 1
                try:
                    # Check if we have fresh cached GitHub data
                    db = VulnerabilityDatabase()
                    if db.is_github_cache_fresh(dep['name']):
                        cached_data = db.get_cached_github_data(dep['name'])
                        if cached_data:
                            enriched_dep['github'] = cached_data
                            print(f"✅ Using cached GitHub data for {dep['name']}")
                            successes += 1
                            enriched_deps.append(enriched_dep)
                            continue
                    # Fetch PyPI data to get project URLs
                    pypi_url = f"https://pypi.org/pypi/{dep['name']}/json"
                    pypi_response = requests.get(pypi_url, timeout=10)
                    if pypi_response.status_code == 200:
                        pypi_data = pypi_response.json()
                        # Extract repository information
                        repo_info = self.github_fetcher.extract_github_repo(dep['name'], pypi_data)
                        if repo_info:
                            # Fetch repository information
                            platform_info = self.github_fetcher.get_repo_info(repo_info)
                            if platform_info:
                                enriched_dep['github'] = platform_info
                                platform = repo_info.get('platform', 'unknown')
                                print(f"✅ Added {platform.title()} data for {dep['name']}")
                                # Cache the GitHub data for future use
                                db.cache_github_data(dep['name'], platform_info)
                                successes += 1
                            else:
                                print(f"⚠️ Could not fetch {repo_info.get('platform', 'unknown')} data for {dep['name']}")
                        else:
                            print(f"⚠️ No repository found for {dep['name']}")
                    else:
                        print(f"⚠️ Could not fetch PyPI data for {dep['name']}")
                except Exception as e:
                    print(f"❌ Error enriching {dep['name']} with GitHub data: {e}")
            enriched_deps.append(enriched_dep)
        # If all GitHub enrichments failed but other data was fetched, mark token as inactive in session
        if total_attempts > 0 and successes == 0:
            print("⚠️ All GitHub enrichments failed for this scan. Marking GitHub token as inactive in session.")
            session.pop('github_token', None)
            session.pop('github_user', None)
        return enriched_deps
    
    def check_package_health(self, dependencies):
        """Check health of all dependencies using PackageHealthChecker."""
        health_data = []
        for dep in dependencies:
            package_name = dep.get('name')
            version = dep.get('version')
            result = self.package_health_checker.check_package_health(package_name, version)
            if result:
                health_data.append(result)
        return health_data

    def _flatten_dependencies_for_scanning(self, dependencies):
        """Flatten dependency tree for vulnerability scanning, only including packages with known versions. Also collect skipped dependencies."""
        flattened = []
        seen_packages = set()  # Track packages to avoid duplicates
        skipped = set()  # Use a set to avoid duplicates with different capitalization
        direct_deps = {}  # Track direct dependencies with their versions

        def is_flexible_or_invalid_version(version):
            if not version:
                return True
            version = str(version)
            return not re.search(r'\d', version) or '*' in version

        # First pass: collect all direct dependencies with their versions
        for dep in dependencies:
            package_name = str(dep.get('name', '')).strip()
            version = str(dep.get('version', '')).strip()
            if package_name and not is_flexible_or_invalid_version(version):
                direct_deps[package_name.lower()] = version

        def add_dependency(dep, is_direct=False):
            package_name = str(dep.get('name', '')).strip()
            version = str(dep.get('version', '')).strip()

            # Debug Flask specifically
            if package_name.lower() == 'flask':
                print(f"🔍 FLASK DEBUG: version='{version}', is_direct={is_direct}")

            # Skip packages without names
            if not package_name:
                return

            # Check if this is a direct dependency with a specific version
            is_direct_with_version = (package_name.lower() in direct_deps and 
                                    not is_flexible_or_invalid_version(direct_deps[package_name.lower()]))

            # If this is a subdependency but we have a direct dependency with specific version, use the direct version
            if not is_direct and is_direct_with_version:
                original_version = version
                version = direct_deps[package_name.lower()]
                if package_name.lower() == 'flask':
                    print(f"🔍 FLASK DEBUG: Overriding '{original_version}' with direct version '{version}'")

            # Skip packages with flexible/invalid versions to avoid unnecessary API calls
            if is_flexible_or_invalid_version(version):
                if package_name.lower() == 'flask':
                    print(f"🔍 FLASK DEBUG: SKIPPING Flask with version '{version}'")
                print(f"⚠️ Skipping {package_name} - version '{version}' is flexible/invalid (N/A)")
                # Deduplicate in a case-insensitive way
                if not any(pkg.lower() == package_name.lower() for pkg in skipped):
                    skipped.add(package_name)
                return

            # Create unique key to avoid duplicates
            package_key = f"{package_name}=={version}"
            if package_key in seen_packages:
                if package_name.lower() == 'flask':
                    print(f"🔍 FLASK DEBUG: Already seen with key '{package_key}'")
                return
            seen_packages.add(package_key)

            if package_name.lower() == 'flask':
                print(f"🔍 FLASK DEBUG: Adding to scan list with version '{version}'")

            flattened.append({
                'name': package_name,
                'version': version
            })

            # Recursively add subdependencies with the same filtering
            subdeps = dep.get('subdependencies', [])
            if isinstance(subdeps, list):
                for subdep in subdeps:
                    add_dependency(subdep, is_direct=False)

        for dep in dependencies:
            add_dependency(dep, is_direct=True)

        print(f"🔍 Will scan {len(flattened)} packages with known versions")
        return flattened, sorted(skipped) 