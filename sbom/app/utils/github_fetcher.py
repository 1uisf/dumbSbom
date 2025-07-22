"""
Simple GitHub Repository Fetcher
Fetches basic repository information for packages
"""

import requests
import re
import math
from datetime import datetime, timedelta
from typing import Dict, Optional
from config import GITHUB_CONFIG, check_github_token
from flask import session

class GitHubFetcher:
    """Simple GitHub repository information fetcher with health assessment"""
    
    def __init__(self):
        self.session = requests.Session()
        
        # Check for session token first, then fall back to environment variable
        session_token = None
        try:
            session_token = session.get('github_token')
            if session_token:
                print(f"🔑 Using session token: {session_token[:10]}...")
            else:
                print("🔑 No session token found")
        except:
            print("🔑 Not in Flask context, using environment token")
            pass  # Not in Flask context
        
        if session_token:
            # Use session token
            self.session.headers.update({
                'Authorization': f'token {session_token}',
                'Accept': 'application/vnd.github.v3+json'
            })
            self.has_token = True
            print(f"✅ Using session token for GitHub API calls")
        else:
            # Use environment token
            self.session.headers.update(GITHUB_CONFIG['headers'])
            self.has_token = bool(GITHUB_CONFIG.get('token'))
            if self.has_token:
                print(f"✅ Using environment token for GitHub API calls")
            else:
                print("⚠️ No GitHub token available")
                check_github_token()
        
        # Health assessment thresholds
        self.health_thresholds = {
            'popularity': {
                'high': 1000,      # 1000+ stars = popular
                'medium': 100,     # 100+ stars = moderately popular
                'low': 10          # 10+ stars = some popularity
            },
            'maintenance': {
                'issues_high': 100,    # 100+ open issues = concerning
                'issues_medium': 50,   # 50+ open issues = moderate concern
                'issues_low': 10       # 10+ open issues = some concern
            },
            'activity': {
                'recent': 30,          # Updated within 30 days = active
                'moderate': 90,        # Updated within 90 days = moderately active
                'stale': 365,          # Updated within 1 year = stale
                'abandoned': 730       # Not updated in 2 years = abandoned
            },
            'community': {
                'forks_high': 100,     # 100+ forks = strong community
                'forks_medium': 20,    # 20+ forks = moderate community
                'forks_low': 5         # 5+ forks = some community
            }
        }
    
    def extract_github_repo(self, package_name: str, pypi_data: Dict) -> Optional[Dict]:
        """Extract repository information from PyPI data (supports multiple platforms)"""
        if not pypi_data:
            return None
        
        # Check project URLs
        project_urls = pypi_data.get('info', {}).get('project_urls', {})
        home_page = pypi_data.get('info', {}).get('home_page', '')
        
        # Platform patterns
        platform_patterns = {
            'github': [
                r'https?://github\.com/([^/]+/[^/]+)',
                r'https?://www\.github\.com/([^/]+/[^/]+)',
                r'https?://raw\.githubusercontent\.com/([^/]+/[^/]+)'
            ],
            'gitlab': [
                r'https?://gitlab\.com/([^/]+/[^/]+)',
                r'https?://foss\.heptapod\.net/([^/]+/[^/]+)',
                r'https?://([^/]+)\.gitlab\.com/([^/]+/[^/]+)'
            ],
            'bitbucket': [
                r'https?://bitbucket\.org/([^/]+/[^/]+)'
            ]
        }
        
        # Check all URLs for platform patterns
        urls_to_check = [home_page] + list(project_urls.values())
        
        for url in urls_to_check:
            if not url:
                continue
            
            for platform, patterns in platform_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, url)
                    if match:
                        repo_path = match.group(1)
                        # Remove .git suffix if present
                        if repo_path.endswith('.git'):
                            repo_path = repo_path[:-4]
                        
                        return {
                            'platform': platform,
                            'repo_path': repo_path,
                            'url': url
                        }
        
        return None
    
    def assess_repository_health(self, repo_info: Dict) -> Dict:
        """Assess repository health based on metrics using improved formulas"""
        if not repo_info:
            return {'status': 'unknown', 'score': 0, 'details': 'No repository data available'}
        
        # Extract metrics
        stars = repo_info.get('stargazers_count', 0)
        forks = repo_info.get('forks_count', 0)
        open_issues = repo_info.get('open_issues_count', 0)
        closed_issues = repo_info.get('closed_issues_count', 0)  # We'll need to fetch this
        pushed_at = repo_info.get('pushed_at')
        
        # Calculate days since last update
        days_since_update = None
        if pushed_at:
            try:
                last_update = datetime.fromisoformat(pushed_at.replace('Z', '+00:00'))
                days_since_update = (datetime.now(last_update.tzinfo) - last_update).days
            except:
                days_since_update = None
        
        # IMPROVED POPULARITY SCORING: log2(stars + 1) + log2(forks + 1)
        popularity_raw = math.log2(stars + 1) + math.log2(forks + 1)
        
        # Normalize popularity to 1-4 scale (more user-friendly)
        # Based on typical GitHub repo distributions:
        # 0-2: Very small repos
        # 2-4: Small repos  
        # 4-6: Medium repos
        # 6-8: Popular repos
        # 8+: Very popular repos
        if popularity_raw >= 8:
            popularity_score = 4
            popularity_status = 'very_popular'
        elif popularity_raw >= 6:
            popularity_score = 3
            popularity_status = 'popular'
        elif popularity_raw >= 4:
            popularity_score = 2
            popularity_status = 'moderately_popular'
        else:
            popularity_score = 1
            popularity_status = 'unpopular'
        
        # IMPROVED MAINTENANCE SCORING: (1 - issue_ratio) * 0.5 + recency_score * 0.5
        # Calculate issue ratio (lower is better)
        total_issues = open_issues + closed_issues
        if total_issues > 0:
            issue_ratio = open_issues / total_issues
        else:
            issue_ratio = 0.0  # No issues = good maintenance
        
        # Calculate recency score (1 = updated today, 0 = not updated in a year)
        if days_since_update is not None:
            recency_score = max(0, 1 - days_since_update / 365)
        else:
            recency_score = 0.0  # Unknown = assume stale
        
        # Combine issue ratio and recency for maintenance score
        maintenance_raw = (1 - issue_ratio) * 0.5 + recency_score * 0.5
        
        # ADJUSTED: More lenient maintenance scoring thresholds (1-4 scale)
        # Most repos have some open issues and aren't updated daily, so we need more realistic thresholds
        if maintenance_raw >= 0.6:  # Was 0.8 - too strict
            maintenance_score = 4
            maintenance_status = 'well_maintained'
        elif maintenance_raw >= 0.4:  # Was 0.6 - too strict
            maintenance_score = 3
            maintenance_status = 'decently_maintained'
        elif maintenance_raw >= 0.2:  # Was 0.4 - too strict
            maintenance_score = 2
            maintenance_status = 'concerning'
        else:
            maintenance_score = 1
            maintenance_status = 'poorly_maintained'
        
        # Assess activity (based on last update) - 1-4 scale
        activity_score = 1  # Default to 1 instead of 0
        activity_status = 'unknown'
        if days_since_update is None:
            activity_score = 1
            activity_status = 'unknown_activity'
        elif days_since_update <= self.health_thresholds['activity']['recent']:
            activity_score = 4
            activity_status = 'very_active'
        elif days_since_update <= self.health_thresholds['activity']['moderate']:
            activity_score = 3
            activity_status = 'active'
        elif days_since_update <= self.health_thresholds['activity']['stale']:
            activity_score = 2
            activity_status = 'stale'
        else:
            activity_score = 1
            activity_status = 'abandoned'
        
        # Assess community (based on forks) - 1-4 scale
        community_score = 1  # Default to 1 instead of 0
        community_status = 'unknown'
        if forks >= self.health_thresholds['community']['forks_high']:
            community_score = 4
            community_status = 'strong_community'
        elif forks >= self.health_thresholds['community']['forks_medium']:
            community_score = 3
            community_status = 'moderate_community'
        elif forks >= self.health_thresholds['community']['forks_low']:
            community_score = 2
            community_status = 'some_community'
        else:
            community_score = 1
            community_status = 'weak_community'
        
        # Calculate overall health score (4-16, where 16 is perfect)
        overall_score = popularity_score + maintenance_score + activity_score + community_score
        
        # ADJUSTED: More balanced overall status thresholds (4-16 scale)
        # Most good repos should fall in the "good" or "moderate" range, not "poor"
        if overall_score >= 13:  # Was 9 - adjusted for 4-16 scale
            overall_status = 'excellent'
            recommendation = 'Highly recommended - well-maintained and popular'
        elif overall_score >= 10:  # Was 6 - adjusted for 4-16 scale
            overall_status = 'good'
            recommendation = 'Good choice - generally well-maintained'
        elif overall_score >= 7:  # Was 3 - adjusted for 4-16 scale
            overall_status = 'moderate'
            recommendation = 'Moderate risk - consider alternatives if possible'
        elif overall_score >= 4:  # Was 1 - adjusted for 4-16 scale
            overall_status = 'poor'
            recommendation = 'High risk - consider replacing with better alternatives'
        else:
            overall_status = 'critical'
            recommendation = 'Critical risk - strongly recommend finding alternatives'
        
        return {
            'overall_status': overall_status,
            'overall_score': overall_score,
            'max_score': 16,
            'recommendation': recommendation,
            'metrics': {
                'popularity': {
                    'score': popularity_score,
                    'status': popularity_status,
                    'stars': stars,
                    'forks': forks,
                    'raw_score': round(popularity_raw, 2),
                    'threshold': self.health_thresholds['popularity']
                },
                'maintenance': {
                    'score': maintenance_score,
                    'status': maintenance_status,
                    'open_issues': open_issues,
                    'closed_issues': closed_issues,
                    'issue_ratio': round(issue_ratio, 3),
                    'recency_score': round(recency_score, 3),
                    'raw_score': round(maintenance_raw, 3),
                    'days_since_update': days_since_update,
                    'threshold': self.health_thresholds['maintenance']
                },
                'activity': {
                    'score': activity_score,
                    'status': activity_status,
                    'days_since_update': days_since_update,
                    'threshold': self.health_thresholds['activity']
                },
                'community': {
                    'score': community_score,
                    'status': community_status,
                    'forks': forks,
                    'threshold': self.health_thresholds['community']
                }
            }
        }
    
    def get_repo_info(self, repo_info: Dict) -> Optional[Dict]:
        """Fetch repository information with health assessment (supports multiple platforms)"""
        try:
            platform = repo_info.get('platform')
            repo_path = repo_info.get('repo_path')
            url = repo_info.get('url')
            
            if platform == 'github':
                # Use GitHub API
                api_url = f"https://api.github.com/repos/{repo_path}"
                print(f"🔍 Fetching GitHub repo: {repo_path}")
                print(f"🔑 Using headers: {dict(self.session.headers)}")
                
                response = self.session.get(api_url)
                print(f"📡 GitHub API response status: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Basic repository info
                    repo_data = {
                        'name': data.get('name'),
                        'full_name': data.get('full_name'),
                        'description': data.get('description'),
                        'stargazers_count': data.get('stargazers_count', 0),
                        'forks_count': data.get('forks_count', 0),
                        'open_issues_count': data.get('open_issues_count', 0),
                        'closed_issues_count': data.get('closed_issues_count', 0), # Added closed issues
                        'language': data.get('language'),
                        'html_url': data.get('html_url'),
                        'pushed_at': data.get('pushed_at'),
                        'platform': 'github'
                    }
                    
                    # Add health assessment
                    health_assessment = self.assess_repository_health(repo_data)
                    repo_data['health'] = health_assessment
                    
                    return repo_data
                else:
                    print(f"⚠️ Could not fetch GitHub repo {repo_path}: {response.status_code}")
                    print(f"📄 Response text: {response.text[:200]}...")
                    return None
                    
            elif platform in ['gitlab', 'bitbucket']:
                # For now, return basic info without API calls
                # (GitLab/Bitbucket APIs require different authentication)
                return {
                    'name': repo_path.split('/')[-1] if repo_path else 'Unknown',
                    'full_name': repo_path or 'Unknown',
                    'description': f'Repository hosted on {platform.title()}',
                    'stargazers_count': 0,
                    'forks_count': 0,
                    'open_issues_count': 0,
                    'closed_issues_count': 0, # Added closed issues
                    'language': 'Unknown',
                    'html_url': url or '',
                    'pushed_at': None,
                    'platform': platform,
                    'health': {
                        'overall_status': 'unknown',
                        'overall_score': 0,
                        'max_score': 12,
                        'recommendation': f'Repository hosted on {platform.title()} - metrics not available',
                        'metrics': {
                            'popularity': {'status': 'unknown', 'score': 0},
                            'maintenance': {'status': 'unknown', 'score': 0},
                            'activity': {'status': 'unknown', 'score': 0},
                            'community': {'status': 'unknown', 'score': 0}
                        }
                    }
                }
            else:
                print(f"⚠️ Unsupported platform: {platform}")
                return None
                
        except Exception as e:
            print(f"❌ Error fetching repo {repo_path}: {e}")
            return None 