import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Access the GitHub token
GITHUB_API_TOKEN = os.getenv('GITHUB_API_TOKEN')

# Check if token is available and provide guidance
def check_github_token():
    """Check if GitHub token is available and provide setup guidance"""
    if not GITHUB_API_TOKEN:
        print("⚠️  GitHub API token not found!")
        print("📝 To enable GitHub repository data fetching:")
        print("   1. Create a .env file in the sbom directory")
        print("   2. Add: GITHUB_API_TOKEN=your_token_here")
        print("   3. Get your token from: https://github.com/settings/tokens")
        print("   4. Select 'public_repo' scope")
        print("   Note: Without a token, GitHub API calls will be rate-limited to 60/hour")
        return False
    return True

# GitHub API configuration
GITHUB_CONFIG = {
    'token': GITHUB_API_TOKEN,
    'base_url': 'https://api.github.com',
    'headers': {
        'Accept': 'application/vnd.github.v3+json'
    }
}

# Add authorization header if token is available
if GITHUB_API_TOKEN:
    GITHUB_CONFIG['headers']['Authorization'] = f'token {GITHUB_API_TOKEN}'
