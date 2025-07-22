#!/usr/bin/env python3
"""
Setup script for SBOM Project
Helps users configure their GitHub API token
"""

import os
import sys
from pathlib import Path

def create_env_file():
    """Create .env file with GitHub token setup"""
    env_path = Path('.env')
    
    if env_path.exists():
        print("📁 .env file already exists")
        return
    
    print("🔧 Setting up GitHub API token...")
    print("\n📝 To enable GitHub repository data fetching, you need a GitHub Personal Access Token:")
    print("   1. Go to: https://github.com/settings/tokens")
    print("   2. Click 'Generate new token (classic)'")
    print("   3. Give it a name like 'SBOM Project'")
    print("   4. Select 'public_repo' scope")
    print("   5. Click 'Generate token'")
    print("   6. Copy the token (you won't see it again)")
    
    token = input("\n🔑 Enter your GitHub Personal Access Token (or press Enter to skip): ").strip()
    
    if token:
        with open(env_path, 'w') as f:
            f.write(f"GITHUB_API_TOKEN={token}\n")
        print("✅ .env file created with your token")
        print("🔒 Note: .env is in .gitignore for security")
    else:
        print("⚠️  No token provided. GitHub API calls will be rate-limited to 60/hour")
        print("💡 You can add a token later by creating a .env file manually")

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import requests
        import dotenv
        print("✅ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("💡 Run: pip install -r requirements.txt")
        return False

def main():
    """Main setup function"""
    print("🚀 SBOM Project Setup")
    print("=" * 30)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Create .env file
    create_env_file()
    
    print("\n🎉 Setup complete!")
    print("💡 Run 'python run.py' to start the application")

if __name__ == "__main__":
    main() 