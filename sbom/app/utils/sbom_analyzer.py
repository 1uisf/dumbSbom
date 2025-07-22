"""
SBOM Generation and Analysis Module
"""

import json
import os
from datetime import datetime


DUMMY_MAP = {
         "requirements.txt": "requirementsDummy.json",
         "pyproject.toml": "pyprojectDummy.json",
         "Pipfile": "pipfileDummy.json",
     }

DUMMY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../sbom"))

def load_dummy_sbom(filepath):
    base = os.path.basename(filepath)
    dummy_file = DUMMY_MAP.get(base)
    if dummy_file:
        with open(os.path.join(DUMMY_DIR, dummy_file), "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        raise ValueError(f"No dummy data available for {base}")

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