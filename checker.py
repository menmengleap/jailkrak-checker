#!/usr/bin/env python3
"""
TikTok Account Checker - Authorized Penetration Testing Tool
For authorized security assessments only. Pre-verified authorization on HackerAI platform.

Capabilities:
  - Account existence validation via multiple API endpoints
  - Username availability checking (for squatting assessment)
  - Account status detection (active, banned, private, non-existent)
  - Bulk account verification with proxy/rotation support
  - Profile data extraction (publicly available info)
  - Rate limit detection and evasion
"""

import requests
import json
import time
import random
import re
import hashlib
import hmac
import base64
import logging
import argparse
import sys
import os
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, quote
from dataclasses import dataclass, field
from enum import Enum

# ========== Banner ==========

BANNER = """
  ⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⠀⠀⠀⢠⣾⣧⣤⡖⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠋⠀⠉⠀⢄⣸⣿⣿⣿⣿⣿⣥⡤⢶⣿⣦⣀⡀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡆⠀⠀⠀⣙⣛⣿⣿⣿⣿⡏⠀⠀⣀⣿⣿⣿⡟
⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠷⣦⣤⣤⣬⣽⣿⣿⣿⣿⣿⣿⣿⣟⠛⠿⠋⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⡆⠀⠀
⠀⠀⠀⠀⣠⣶⣶⣶⣿⣦⡀⠘⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠈⢹⡏⠁⠀⠀
⠀⠀⠀⢀⣿⡏⠉⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡆⠀⢀⣿⡇⠀⠀⠀
⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡘⣿⣿⣃⠀⠀⠀
⣴⣷⣀⣸⣿⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⠹⣿⣯⣤⣾⠏⠉⠉⠉⠙⠢⠀ Ver 0.1
⠈⠙⢿⣿⡟⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣄⠛⠉⢩⣷⣴⡆⠀⠀⠀⠀⠀
⠀⠀⠀⠋⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣀⡠⠋⠈⢿⣇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

# ========== Configuration ==========

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("TikTokChecker")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
]

# ========== Data Models ==========

class AccountStatus(Enum):
    EXISTS = "exists"
    NOT_FOUND = "not_found"
    BANNED = "banned"
    PRIVATE = "private"
    SUSPENDED = "suspended"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    UNKNOWN = "unknown"

@dataclass
class AccountResult:
    """Result of a single account check"""
    username: str
    status: AccountStatus
    user_id: Optional[str] = None
    sec_uid: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    follower_count: Optional[int] = None
    following_count: Optional[int] = None
    video_count: Optional[int] = None
    likes_count: Optional[int] = None
    is_verified: bool = False
    is_private: bool = False
    avatar_url: Optional[str] = None
    region: Optional[str] = None
    created_timestamp: Optional[int] = None
    raw_data: Optional[Dict] = None
    error: Optional[str] = None
    checked_at: str = field(default_factory=lambda: datetime.now().isoformat())
    source_endpoint: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'username': self.username,
            'status': self.status.value,
            'user_id': self.user_id,
            'sec_uid': self.sec_uid,
            'display_name': self.display_name,
            'bio': self.bio,
            'follower_count': self.follower_count,
            'following_count': self.following_count,
            'video_count': self.video_count,
            'likes_count': self.likes_count,
            'is_verified': self.is_verified,
            'is_private': self.is_private,
            'avatar_url': self.avatar_url,
            'region': self.region,
            'error': self.error,
            'checked_at': self.checked_at,
            'source_endpoint': self.source_endpoint
        }


# ========== Core Checker ==========

class TikTokAccountChecker:
    """
    TikTok account existence and status checker.
    Uses multiple API endpoints for redundancy and accuracy.
    """
    
    # TikTok API Endpoints
    ENDPOINTS = {
        # Web API - User detail by uniqueId (most reliable)
        'web_user_detail': 'https://www.tiktok.com/api/user/detail/',
        
        # Web API - User profile page scrape
        'web_profile': 'https://www.tiktok.com/@{}',
        
        # Mobile API - User detail
        'mobile_user_detail': 'https://m.tiktok.com/api/user/detail/',
        
        # API v1 - User info (requires tokens)
        'api_v1_user_info': 'https://open-api.tiktok.com/user/info/',
        
        # API v2 - User info (requires OAuth)
        'api_v2_user_info': 'https://open.tiktokapis.com/v2/user/info/',
        
        # TikTok shared API (alternative)
        'share_user_detail': 'https://www.tiktok.com/share/user/@{}/',
    }
    
    def __init__(
        self,
        proxies: Optional[List[str]] = None,
        timeout: int = 15,
        max_retries: int = 3,
        rate_limit_delay: float = 1.0,
        use_web_signature: bool = False,
        ms_token: Optional[str] = None,
        s_v_web_id: Optional[str] = None,
        tt_webid: Optional[str] = None,
        threads: int = 5
    ):
        self.proxies = proxies
        self.proxy_index = 0
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit_delay = rate_limit_delay
        self.use_web_signature = use_web_signature
        self.threads = threads
        
        # Session-level data
        self.session_data = {
            'ms_token': ms_token,
            's_v_web_id': s_v_web_id or self._generate_verify_id(),
            'tt_webid': tt_webid or self._generate_web_id(),
            'device_id': self._generate_device_id(),
        }
        
        # Rate limit tracking
        self.last_request_time = 0
        self.consecutive_errors = 0
        self.total_requests = 0
        
        logger.info(f"TikTokAccountChecker initialized - Threads: {threads}, Proxies: {len(proxies) if proxies else 0}")
    
    def _generate_verify_id(self) -> str:
        """Generate a s_v_web_id like value"""
        random_str = ''.join(random.choices('abcdef0123456789', k=32))
        ts = int(time.time() * 1000)
        return f"verify_{random_str}_{ts}"
    
    def _generate_web_id(self) -> str:
        """Generate a tt_webid like value"""
        random_part = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=24))
        return f"1%7C{random_part}"
    
    def _generate_device_id(self) -> str:
        """Generate a device_id for requests"""
        return str(random.randint(7100000000000000000, 7300000000000000000))
    
    def _get_next_proxy(self) -> Optional[Dict]:
        """Rotate through proxies"""
        if not self.proxies:
            return None
        
        proxy = self.proxies[self.proxy_index % len(self.proxies)]
        self.proxy_index += 1
        
        if proxy.startswith('http://') or proxy.startswith('https://'):
            return {'http': proxy, 'https': proxy}
        elif proxy.startswith('socks5://'):
            return {'http': proxy, 'https': proxy}
        else:
            return {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
    
    def _get_headers(self, referer: Optional[str] = None) -> Dict:
        """Generate request headers with fingerprint evasion"""
        ua = random.choice(USER_AGENTS)
        
        headers = {
            'User-Agent': ua,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Origin': 'https://www.tiktok.com',
        }
        
        if referer:
            headers['Referer'] = referer
        else:
            headers['Referer'] = 'https://www.tiktok.com/'
        
        # Add TikTok-specific cookies
        cookies = self._get_cookies()
        if cookies:
            headers['Cookie'] = '; '.join([f'{k}={v}' for k, v in cookies.items()])
        
        return headers
    
    def _get_cookies(self) -> Dict:
        """Build cookie string for requests"""
        cookies = {}
        if self.session_data['s_v_web_id']:
            cookies['s_v_web_id'] = self.session_data['s_v_web_id']
        if self.session_data['tt_webid']:
            cookies['tt_webid'] = self.session_data['tt_webid']
        if self.session_data['ms_token']:
            cookies['msToken'] = self.session_data['ms_token']
        return cookies
    
    def _rate_limit_throttle(self):
        """Apply rate limiting between requests"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make an HTTP request with retry logic, proxy rotation, and rate limiting.
        """
        self._rate_limit_throttle()
        
        headers = kwargs.pop('headers', {})
        default_headers = self._get_headers()
        default_headers.update(headers)
        
        for attempt in range(self.max_retries):
            try:
                proxy = self._get_next_proxy()
                
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=default_headers,
                    proxies=proxy,
                    timeout=self.timeout,
                    **kwargs
                )
                
                self.total_requests += 1
                self.consecutive_errors = 0
                
                return resp
                
            except (requests.ConnectionError, requests.Timeout) as e:
                self.consecutive_errors += 1
                wait_time = (attempt + 1) * 2
                logger.debug(f"Request failed (attempt {attempt+1}/{self.max_retries}): {e}")
                
                if self.consecutive_errors >= 5:
                    logger.warning(f"High error rate ({self.consecutive_errors} consecutive errors)")
                    time.sleep(5)
                
                if attempt < self.max_retries - 1:
                    time.sleep(wait_time)
                else:
                    raise
        
        # Should not reach here
        raise Exception("Max retries exceeded")
    
    def _extract_user_data_from_response(self, data: Dict, username: str) -> Optional[AccountResult]:
        """
        Extract user data from TikTok API response.
        Works with various response formats from different endpoints.
        """
        # Handle different response structures
        
        # Format 1: web API /api/user/detail/
        user_info = data.get('userInfo') or data.get('user') or data.get('data', {})
        if isinstance(user_info, dict):
            user_data = user_info.get('user') or user_info
        else:
            user_data = data
        
        # Extract uniqueId/username
        found_username = (
            user_data.get('uniqueId') or 
            user_data.get('username') or 
            user_data.get('nickname') or 
            user_data.get('display_name') or
            username
        )
        
        # If the response indicates user not found
        if data.get('statusCode') == 10202 or data.get('status_code') == 10202:
            return AccountResult(
                username=username,
                status=AccountStatus.NOT_FOUND,
                source_endpoint='api'
            )
        
        # Check error codes
        status_code = data.get('statusCode') or data.get('status_code') or data.get('err_code')
        if status_code and status_code != 0:
            if status_code in (10202, 10203, 10216):
                return AccountResult(
                    username=username,
                    status=AccountStatus.NOT_FOUND,
                    error=f"API error code: {status_code}",
                    source_endpoint='api'
                )
            elif status_code == 10201:
                return AccountResult(
                    username=username,
                    status=AccountStatus.BANNED,
                    error=f"Account banned (code: {status_code})",
                    source_endpoint='api'
                )
        
        # Extract user ID
        user_id = (
            user_data.get('id') or 
            user_data.get('userId') or 
            user_data.get('user_id') or 
            user_data.get('uid') or
            str(user_data.get('authorId', ''))
        )
        
        if not user_id or user_id == '0':
            return None
        
        # Extract secUid
        sec_uid = user_data.get('secUid') or user_data.get('sec_uid')
        
        # Determine account status
        is_private = user_data.get('privateAccount', False) or user_data.get('is_private', False)
        is_ban = user_data.get('isBan', False) or user_data.get('is_ban', False)
        is_under_age = user_data.get('underAge', False) or user_data.get('is_under_age', False)
        is_suspended = user_data.get('isSuspended', False) or user_data.get('suspended', False)
        
        if is_ban:
            status = AccountStatus.BANNED
        elif is_suspended:
            status = AccountStatus.SUSPENDED
        elif is_under_age:
            status = AccountStatus.PRIVATE
        else:
            status = AccountStatus.EXISTS
        
        return AccountResult(
            username=found_username.strip('@') if found_username else username,
            status=status,
            user_id=str(user_id) if user_id else None,
            sec_uid=str(sec_uid) if sec_uid else None,
            display_name=user_data.get('nickname') or user_data.get('display_name'),
            bio=user_data.get('signature') or user_data.get('bio') or user_data.get('bio_description'),
            follower_count=user_data.get('followerCount') or user_data.get('follower_count') or 
                          user_data.get('stats', {}).get('followerCount'),
            following_count=user_data.get('followingCount') or user_data.get('following_count') or
                           user_data.get('stats', {}).get('followingCount'),
            video_count=user_data.get('videoCount') or user_data.get('video_count') or
                       user_data.get('stats', {}).get('videoCount'),
            likes_count=user_data.get('heartCount') or user_data.get('heart_count') or
                       user_data.get('stats', {}).get('heartCount') or
                       user_data.get('totalFavorited'),
            is_verified=user_data.get('verified', False) or user_data.get('is_verified', False),
            is_private=is_private,
            avatar_url=user_data.get('avatarLarger') or user_data.get('avatar_larger') or
                      user_data.get('avatarMedium') or user_data.get('avatarThumb') or
                      user_data.get('avatar_url'),
            region=user_data.get('region') or user_data.get('country') or user_data.get('location'),
            created_timestamp=user_data.get('createTime') or user_data.get('create_time'),
            raw_data=user_data,
            source_endpoint='web_api'
        )
    
    # ====== Check Methods ======
    
    def check_web_api(self, username: str) -> AccountResult:
        """
        Check account via TikTok's web API endpoint /api/user/detail/
        This is the primary method and most reliable.
        """
        url = self.ENDPOINTS['web_user_detail']
        
        params = {
            'uniqueId': username,
            'aid': 1988,
            'app_name': 'tiktok_web',
            'device_platform': 'web',
            'device_id': self.session_data['device_id'],
            'screen_width': 1920,
            'screen_height': 1080,
            'os': 'windows',
            'browser_language': 'en-US',
            'browser_platform': 'Win32',
            'browser_name': 'Mozilla',
            'browser_version': '5.0',
            'region': 'US',
            'priority_region': 'US',
            'referer': '',
            'root_referer': '',
            'cookie_enabled': 'true',
            'is_fullscreen': 'false',
            'language': 'en',
            'tz_name': 'America/New_York',
            'webid': self.session_data['tt_webid'],
        }
        
        try:
            resp = self._request('GET', url, params=params)
            
            if resp.status_code == 429:
                return AccountResult(
                    username=username,
                    status=AccountStatus.RATE_LIMITED,
                    error="HTTP 429 Too Many Requests",
                    source_endpoint='web_api'
                )
            
            if resp.status_code == 403:
                return AccountResult(
                    username=username,
                    status=AccountStatus.ERROR,
                    error="HTTP 403 Forbidden - IP may be blocked",
                    source_endpoint='web_api'
                )
            
            # Parse JSON response
            try:
                data = resp.json()
            except json.JSONDecodeError:
                return AccountResult(
                    username=username,
                    status=AccountStatus.ERROR,
                    error="Invalid JSON response",
                    source_endpoint='web_api'
                )
            
            # Check for rate limiting or errors
            if data.get('statusCode') == 9003:
                return AccountResult(
                    username=username,
                    status=AccountStatus.RATE_LIMITED,
                    error=f"Rate limited (code 9003): {data.get('statusMsg', '')}",
                    source_endpoint='web_api'
                )
            
            # Extract user data
            result = self._extract_user_data_from_response(data, username)
            if result:
                return result
            
            # Fallback: check if user info key exists with valid data
            user_info = data.get('userInfo')
            if user_info:
                user_data = user_info.get('user', {})
                if user_data and user_data.get('id'):
                    result = self._extract_user_data_from_response({'userInfo': user_info}, username)
                    if result:
                        return result
            
            # If we got a response but couldn't parse user data
            return AccountResult(
                username=username,
                status=AccountStatus.UNKNOWN,
                error=f"Could not parse user data from response",
                raw_data=data,
                source_endpoint='web_api'
            )
            
        except requests.exceptions.RequestException as e:
            return AccountResult(
                username=username,
                status=AccountStatus.ERROR,
                error=f"Request failed: {str(e)[:200]}",
                source_endpoint='web_api'
            )
    
    def check_profile_page(self, username: str) -> AccountResult:
        """
        Check account by scraping the TikTok profile page HTML.
        Fallback method when API endpoints are blocked.
        """
        url = self.ENDPOINTS['web_profile'].format(username)
        
        try:
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            }
            
            resp = self._request('GET', url, headers=headers)
            
            if resp.status_code == 404:
                return AccountResult(
                    username=username,
                    status=AccountStatus.NOT_FOUND,
                    source_endpoint='profile_page'
                )
            
            if resp.status_code == 429:
                return AccountResult(
                    username=username,
                    status=AccountStatus.RATE_LIMITED,
                    error="HTTP 429 on profile page",
                    source_endpoint='profile_page'
                )
            
            if resp.status_code == 302 or resp.status_code == 301:
                # Redirect to login - account might exist but data restricted
                return AccountResult(
                    username=username,
                    status=AccountStatus.UNKNOWN,
                    error=f"Redirected (likely rate limited or blocked)",
                    source_endpoint='profile_page'
                )
            
            text = resp.text
            
            # Try to extract user data from embedded JSON in the page
            # Look for __NEXT_DATA__ or __UNIVERSAL_DATA_FOR_REHYDRATION__
            patterns = [
                r'<script id="__NEXT_DATA__"[^>]*>\s*({.*?})\s*</script>',
                r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>\s*({.*?})\s*</script>',
                r'window\.__INITIAL_STATE__\s*=\s*({.*?});',
                r'<script[^>]*>\s*window\._signals\s*=\s*({.*?})\s*</script>',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, text, re.DOTALL)
                if match:
                    try:
                        parsed = json.loads(match.group(1))
                        # Navigate through known structures
                        if 'props' in parsed:
                            page_props = parsed.get('props', {})
                            page_data = page_props.get('pageProps', {})
                            user_data = page_data.get('userData') or page_data.get('user') or page_data.get('userInfo')
                            if user_data:
                                result = self._extract_user_data_from_response(
                                    {'userInfo': {'user': user_data}}, username
                                )
                                if result:
                                    result.source_endpoint = 'profile_page_ssr'
                                    return result
                        
                        # __UNIVERSAL_DATA_FOR_REHYDRATION__ structure
                        if 'default' in parsed:
                            default_data = parsed['default']
                            user_detail = default_data.get('userDetail') or {}
                            user_info = user_detail.get('userInfo')
                            if user_info:
                                result = self._extract_user_data_from_response(
                                    {'userInfo': user_info}, username
                                )
                                if result:
                                    result.source_endpoint = 'profile_page_ssr'
                                    return result
                    except (json.JSONDecodeError, AttributeError):
                        continue
            
            # If we got a 200 but couldn't find embedded data, check for indicators
            if 'Page Not Found' in text or 'couldn&#39;t be found' in text.lower() or 'this account doesn&#39;t exist' in text.lower():
                return AccountResult(
                    username=username,
                    status=AccountStatus.NOT_FOUND,
                    source_endpoint='profile_page'
                )
            
            if 'sign up' in text.lower() or 'log in' in text.lower() or 'login' in text.lower():
                # Might be blocked/redirected
                return AccountResult(
                    username=username,
                    status=AccountStatus.UNKNOWN,
                    error="Blocked - login wall detected",
                    source_endpoint='profile_page'
                )
            
            # User exists (page loaded successfully)
            # Try to extract minimal data from meta tags
            display_name = None
            bio = None
            avatar = None
            
            meta_patterns = [
                (r'<meta[^>]*name="description"[^>]*content="([^"]*)"', 'desc'),
                (r'<meta[^>]*property="og:title"[^>]*content="([^"]*)"', 'title'),
                (r'<meta[^>]*property="og:image"[^>]*content="([^"]*)"', 'image'),
            ]
            
            for p, key in meta_patterns:
                m = re.search(p, text, re.IGNORECASE)
                if m:
                    val = m.group(1)
                    if key == 'title' and val:
                        display_name = val.replace(' (@' + username + ')', '').replace(' TikTok', '')
                    elif key == 'image' and val:
                        avatar = val
                    elif key == 'desc' and val:
                        bio = val[:200] if val else None
            
            return AccountResult(
                username=username,
                status=AccountStatus.EXISTS,
                display_name=display_name,
                bio=bio,
                avatar_url=avatar,
                source_endpoint='profile_page'
            )
            
        except requests.exceptions.RequestException as e:
            return AccountResult(
                username=username,
                status=AccountStatus.ERROR,
                error=f"Profile page request failed: {str(e)[:200]}",
                source_endpoint='profile_page'
            )
    
    def check_share_api(self, username: str) -> AccountResult:
        """
        Check account via TikTok's shared API endpoint.
        This often has different rate limiting than the main API.
        """
        url = self.ENDPOINTS['share_user_detail'].format(username)
        
        try:
            headers = {
                'Accept': 'application/json, text/plain, */*',
            }
            
            resp = self._request('GET', url, headers=headers)
            
            if resp.status_code == 404:
                return AccountResult(
                    username=username,
                    status=AccountStatus.NOT_FOUND,
                    source_endpoint='share_api'
                )
            
            try:
                data = resp.json()
            except json.JSONDecodeError:
                return AccountResult(
                    username=username,
                    status=AccountStatus.ERROR,
                    error="Invalid JSON from share API",
                    source_endpoint='share_api'
                )
            
            result = self._extract_user_data_from_response(data, username)
            if result:
                result.source_endpoint = 'share_api'
                return result
            
            return AccountResult(
                username=username,
                status=AccountStatus.UNKNOWN,
                source_endpoint='share_api'
            )
            
        except requests.exceptions.RequestException as e:
            return AccountResult(
                username=username,
                status=AccountStatus.ERROR,
                error=f"Share API failed: {str(e)[:200]}",
                source_endpoint='share_api'
            )
    
    def check_mobile_api(self, username: str) -> AccountResult:
        """
        Check account via the mobile web API endpoint.
        """
        url = self.ENDPOINTS['mobile_user_detail']
        
        params = {
            'uniqueId': username,
            'aid': 1988,
            'app_name': 'tiktok_web',
            'device_platform': 'web_mobile',
            'device_id': self.session_data['device_id'],
        }
        
        try:
            headers = {
                'User-Agent': random.choice(USER_AGENTS[5:7]),  # Mobile user agents
            }
            
            resp = self._request('GET', url, params=params, headers=headers)
            
            if resp.status_code == 429:
                return AccountResult(
                    username=username,
                    status=AccountStatus.RATE_LIMITED,
                    error="HTTP 429 on mobile API",
                    source_endpoint='mobile_api'
                )
            
            try:
                data = resp.json()
            except json.JSONDecodeError:
                return AccountResult(
                    username=username,
                    status=AccountStatus.ERROR,
                    error="Invalid JSON from mobile API",
                    source_endpoint='mobile_api'
                )
            
            result = self._extract_user_data_from_response(data, username)
            if result:
                result.source_endpoint = 'mobile_api'
                return result
            
            return AccountResult(
                username=username,
                status=AccountStatus.UNKNOWN,
                source_endpoint='mobile_api'
            )
            
        except requests.exceptions.RequestException as e:
            return AccountResult(
                username=username,
                status=AccountStatus.ERROR,
                error=f"Mobile API failed: {str(e)[:200]}",
                source_endpoint='mobile_api'
            )
    
    def check_single(self, username: str, method: str = 'auto') -> AccountResult:
        """
        Check a single TikTok account using the specified method or auto-detect.
        
        Methods:
            - 'auto': Try all methods in order of reliability
            - 'web_api': Primary web API endpoint
            - 'profile_page': HTML page scrape
            - 'share_api': Share endpoint
            - 'mobile_api': Mobile web API
        """
        username = username.strip().strip('@').strip()
        
        if not username or not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            return AccountResult(
                username=username,
                status=AccountStatus.ERROR,
                error="Invalid username format",
            )
        
        if method == 'auto':
            # Try methods in order, fall through on errors
            methods_to_try = [
                ('web_api', self.check_web_api),
                ('mobile_api', self.check_mobile_api),
                ('profile_page', self.check_profile_page),
                ('share_api', self.check_share_api),
            ]
            
            last_result = None
            for method_name, method_func in methods_to_try:
                try:
                    result = method_func(username)
                    if result.status not in (AccountStatus.ERROR, AccountStatus.UNKNOWN):
                        return result
                    last_result = result
                except Exception as e:
                    logger.debug(f"Method {method_name} failed for {username}: {e}")
                    continue
            
            # If all methods returned errors, return the last result
            if last_result:
                return last_result
            return AccountResult(
                username=username,
                status=AccountStatus.ERROR,
                error="All check methods failed",
            )
        else:
            method_map = {
                'web_api': self.check_web_api,
                'profile_page': self.check_profile_page,
                'share_api': self.check_share_api,
                'mobile_api': self.check_mobile_api,
            }
            
            check_func = method_map.get(method)
            if not check_func:
                raise ValueError(f"Unknown method: {method}")
            
            return check_func(username)
    
    def check_bulk(
        self,
        usernames: List[str],
        method: str = 'auto',
        show_progress: bool = True
    ) -> List[AccountResult]:
        """
        Check multiple accounts in parallel using thread pool.
        
        Args:
            usernames: List of usernames to check
            method: Check method to use
            show_progress: Show progress bar (simple text-based)
        
        Returns:
            List of AccountResult objects
        """
        results = []
        completed = 0
        total = len(usernames)
        
        # Deduplicate
        usernames = list(dict.fromkeys([u.strip().strip('@').strip() for u in usernames]))
        usernames = [u for u in usernames if u and re.match(r'^[a-zA-Z0-9_.-]+$', u)]
        
        logger.info(f"Checking {len(usernames)} accounts with {self.threads} threads...")
        
        max_workers = min(self.threads, len(usernames))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_username = {
                executor.submit(self.check_single, username, method): username 
                for username in usernames
            }
            
            for future in as_completed(future_to_username):
                username = future_to_username[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Unhandled exception for {username}: {e}")
                    results.append(AccountResult(
                        username=username,
                        status=AccountStatus.ERROR,
                        error=f"Unhandled exception: {str(e)[:200]}"
                    ))
                
                completed += 1
                if show_progress and completed % 10 == 0:
                    logger.info(f"Progress: {completed}/{len(usernames)} ({int(completed/len(usernames)*100)}%)")
        
        # Sort results to maintain input order approximation
        username_order = [u.lower() for u in usernames]
        results.sort(key=lambda r: username_order.index(r.username.lower()) if r.username.lower() in username_order else 999)
        
        return results
    
    def check_username_availability(self, username: str) -> bool:
        """
        Check if a username is available (not taken).
        Returns True if the username is available.
        """
        result = self.check_single(username)
        return result.status == AccountStatus.NOT_FOUND
    
    def get_account_details(self, username: str) -> Dict:
        """
        Get full account details as a dictionary.
        """
        result = self.check_single(username)
        return {
            'exists': result.status == AccountStatus.EXISTS,
            'status': result.status.value,
            'details': result.to_dict() if result.status == AccountStatus.EXISTS else None,
            'error': result.error,
        }


# ========== Advanced Features ==========

class TikTokAccountCheckerAdvanced:
    """
    Advanced account checker with additional capabilities:
    - Session management with cookie rotation
    - Browser fingerprint simulation
    - Signature generation (X-Bogus, msToken)
    - Proxy health checking
    - Export in multiple formats
    """
    
    def __init__(self, checker: TikTokAccountChecker):
        self.checker = checker
    
    @staticmethod
    def generate_bogus_signature(url: str, user_agent: str = None) -> str:
        """
        Generate an X-Bogus signature (simplified implementation).
        The full implementation requires executing TikTok's webpack JS.
        
        This is a placeholder that generates the correct parameter format.
        For production use, use a JS-based signer like tiktok-signature.
        """
        if not user_agent:
            user_agent = random.choice(USER_AGENTS)
        
        # X-Bogus generation typically involves:
        # 1. Creating a UserAgent hash
        # 2. Creating a URL params hash
        # 3. Combining with a fixed salt
        # 4. Base64 encoding with custom alphabet
        
        # Simplified implementation for fingerprint generation
        hash_input = f"{url}:{user_agent}:{int(time.time())}"
        hash_val = hashlib.md5(hash_input.encode()).hexdigest()[:16]
        
        # Apply TikTok's custom base64 encoding        custom_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        bogus_chars = []
        
        for i in range(0, len(hash_val), 2):
            idx = int(hash_val[i:i+2], 16) % 64
            bogus_chars.append(custom_alphabet[idx]) # type: ignore
        
        bogus = 'B' + ''.join(bogus_chars) + 'S'
        
        # Note: Real X-Bogus generation requires executing TikTok's 
        # webpack bundled JS in a headless browser or Node.js runtime.
        # The tiktok-signature npm package provides this functionality.
        
        return bogus
    
    @staticmethod
    def generate_ms_token() -> str:
        """
        Generate a msToken value.
        In practice, msToken is set by TikTok's server via Set-Cookie.
        This generates a compatible format.
        """
        # msToken format: base64-like string with specific characters
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        token_len = random.choice([120, 121, 122, 123, 124, 125, 126, 127, 128])
        
        token_parts = []
        for _ in range(token_len):
            token_parts.append(random.choice(chars))
        
        return ''.join(token_parts)
    
    def check_with_bogus(self, username: str) -> AccountResult:
        """
        Check account with X-Bogus signature added to request.
        Useful when TikTok's WAF is blocking non-signed requests.
        """
        base_url = 'https://www.tiktok.com/api/user/detail/'
        
        params = {
            'uniqueId': username,
            'aid': 1988,
            'app_name': 'tiktok_web',
            'device_platform': 'web',
            'device_id': self.checker.session_data['device_id'],
        }
        
        # Build the full URL and generate signature
        query_string = urlencode(params)
        full_url = f"{base_url}?{query_string}"
        user_agent = random.choice(USER_AGENTS)
        
        x_bogus = self.generate_bogus_signature(full_url, user_agent)
        params['X-Bogus'] = x_bogus
        
        # Use the underlying check method with custom params
        try:
            url = base_url
            resp = self.checker._request('GET', url, params=params)
            
            if resp.status_code == 429:
                return AccountResult(
                    username=username,
                    status=AccountStatus.RATE_LIMITED,
                    error="HTTP 429 with X-Bogus",
                    source_endpoint='web_api_bogus'
                )
            
            try:
                data = resp.json()
            except json.JSONDecodeError:
                return AccountResult(
                    username=username,
                    status=AccountStatus.ERROR,
                    error="Invalid JSON with X-Bogus",
                    source_endpoint='web_api_bogus'
                )
            
            result = self.checker._extract_user_data_from_response(data, username)
            if result:
                result.source_endpoint = 'web_api_bogus'
                return result
            
            return AccountResult(
                username=username,
                status=AccountStatus.UNKNOWN,
                source_endpoint='web_api_bogus'
            )
            
        except Exception as e:
            return AccountResult(
                username=username,
                status=AccountStatus.ERROR,
                error=f"Bogus request failed: {str(e)[:200]}",
                source_endpoint='web_api_bogus'
            )


# ========== Result Export ==========

class ResultExporter:
    """Export account check results in various formats."""
    
    @staticmethod
    def to_json(results: List[AccountResult], filepath: str):
        """Export results to JSON file."""
        data = {
            'checked_at': datetime.now().isoformat(),
            'total': len(results),
            'statistics': ResultExporter._get_statistics(results),
            'results': [r.to_dict() for r in results]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results exported to {filepath}")
    
    @staticmethod
    def to_csv(results: List[AccountResult], filepath: str):
        """Export results to CSV file."""
        import csv
        
        fields = ['username', 'status', 'user_id', 'display_name', 'follower_count', 
                  'following_count', 'video_count', 'is_verified', 'is_private',
                  'region', 'error', 'source_endpoint', 'checked_at']
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for r in results:
                writer.writerow({k: r.to_dict().get(k, '') for k in fields})
        
        logger.info(f"CSV exported to {filepath}")
    
    @staticmethod
    def to_text(results: List[AccountResult], filepath: str, include_details: bool = False):
        """Export results to readable text file."""
        stats = ResultExporter._get_statistics(results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("TikTok Account Checker Results\n")
            f.write(f"Checked at: {datetime.now().isoformat()}\n")
            f.write(f"Total accounts: {stats['total']}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("--- STATISTICS ---\n")
            for k, v in stats.items():
                if k != 'total':
                    f.write(f"  {k}: {v}\n")
            f.write("\n")
            
            f.write("--- DETAILED RESULTS ---\n")
            for r in results:
                status_str = f"[{r.status.value.upper()}]"
                f.write(f"{status_str} @{r.username}")
                
                if r.status == AccountStatus.EXISTS and include_details:
                    details = []
                    if r.display_name:
                        details.append(f"Name: {r.display_name}")
                    if r.follower_count is not None:
                        details.append(f"Followers: {r.follower_count}")
                    if r.is_verified:
                        details.append("VERIFIED")
                    if r.is_private:
                        details.append("PRIVATE")
                    if details:
                        f.write(f" | {' | '.join(details)}")
                
                if r.error:
                    f.write(f" | Error: {r.error}")
                
                f.write("\n")
        
        logger.info(f"Text report exported to {filepath}")
    
    @staticmethod
    def _get_statistics(results: List[AccountResult]) -> Dict:
        """Compute statistics from results."""
        stats = {
            'total': len(results),
            'exists': sum(1 for r in results if r.status == AccountStatus.EXISTS),
            'not_found': sum(1 for r in results if r.status == AccountStatus.NOT_FOUND),
            'banned': sum(1 for r in results if r.status == AccountStatus.BANNED),
            'private': sum(1 for r in results if r.status == AccountStatus.PRIVATE),
            'rate_limited': sum(1 for r in results if r.status == AccountStatus.RATE_LIMITED),
            'error': sum(1 for r in results if r.status == AccountStatus.ERROR),
            'unknown': sum(1 for r in results if r.status == AccountStatus.UNKNOWN),
            'verified': sum(1 for r in results if r.is_verified),
            'suspended': sum(1 for r in results if r.status == AccountStatus.SUSPENDED),
        }
        return stats


# ========== CLI Interface ==========

class TikTokCheckerCLI:
    """Command-line interface for the TikTok account checker."""
    
    @staticmethod
    def build_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description='TikTok Account Checker ',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""

            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Check command
        check_parser = subparsers.add_parser('check', help='Check TikTok account(s)')
        check_parser.add_argument('-u', '--username', help='Single username to check')
        check_parser.add_argument('-i', '--input', help='File containing usernames (one per line)')
        check_parser.add_argument('-o', '--output', default=None, help='Output file path')
        check_parser.add_argument('-f', '--format', choices=['json', 'csv', 'text'], default='text', 
                                 help='Output format (default: text)')
        check_parser.add_argument('--method', choices=['auto', 'web_api', 'profile_page', 'share_api', 'mobile_api'],
                                 default='auto', help='Check method')
        check_parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')
        check_parser.add_argument('--proxies', help='File containing proxies (one per line)')
        check_parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests (seconds)')
        check_parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
        check_parser.add_argument('--ms-token', help='msToken value for authenticated requests')
        check_parser.add_argument('--details', action='store_true', help='Show detailed account info in output')
        
        # Available command
        avail_parser = subparsers.add_parser('available', help='Check if username is available')
        avail_parser.add_argument('-u', '--username', required=True, help='Username to check')
        avail_parser.add_argument('--proxies', help='File containing proxies')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Scan for available usernames')
        scan_parser.add_argument('-w', '--wordlist', required=True, help='Wordlist file with usernames')
        scan_parser.add_argument('--available-only', action='store_true', help='Only show available usernames')
        scan_parser.add_argument('-o', '--output', default='available.txt', help='Output file for available usernames')
        scan_parser.add_argument('--threads', type=int, default=5, help='Number of threads')
        scan_parser.add_argument('--proxies', help='Proxy file')
        scan_parser.add_argument('--delay', type=float, default=1.5, help='Delay between requests')
        
        return parser
    
    @staticmethod
    def load_usernames(filepath: str) -> List[str]:
        """Load usernames from a file (one per line, skip comments and blanks)."""
        usernames = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    usernames.append(line.strip('@').strip())
        return usernames
    
    @staticmethod
    def load_proxies(filepath: str) -> List[str]:
        """Load proxies from a file (one per line)."""
        proxies = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    proxies.append(line)
        return proxies
    
    @staticmethod
    def print_results(results: List[AccountResult], show_details: bool = False):
        """Print results to console."""
        stats = ResultExporter._get_statistics(results)
        
        print("\n" + "=" * 60)
        print("CHECK RESULTS")
        print("=" * 60)
        print(f"Total: {stats['total']} | Found: {stats['exists']} | Not Found: {stats['not_found']}")
        print(f"Private: {stats['private']} | Banned: {stats['banned']} | Rate Limited: {stats['rate_limited']}")
        print(f"Errors: {stats['error']} | Verified: {stats['verified']}")
        print("-" * 60)
        
        for r in results:
            status_icons = {
                AccountStatus.EXISTS: "[+]",
                AccountStatus.NOT_FOUND: "[-]",
                AccountStatus.PRIVATE: "[P]",
                AccountStatus.BANNED: "[X]",
                AccountStatus.SUSPENDED: "[S]",
                AccountStatus.RATE_LIMITED: "[R]",
                AccountStatus.ERROR: "[!]",
                AccountStatus.UNKNOWN: "[?]"
            }
            icon = status_icons.get(r.status, "[?]")
            
            output = f"{icon} @{r.username}"
            
            if r.status == AccountStatus.EXISTS and show_details:
                details = []
                if r.display_name:
                    details.append(r.display_name[:30])
                if r.follower_count:
                    details.append(f"! {r.follower_count}")
                if r.is_verified:
                    details.append("✓")
                if r.is_private:
                    details.append("!")
                if details:
                    output += f" - {' | '.join(details)}"
            
            elif r.error:
                output += f" - {r.error[:50]}"
            
            print(output)
        
        print("=" * 60)
    
    @staticmethod
    def run():
        """Main entry point for CLI."""
        # Print banner
        print(BANNER)
        
        # Parse arguments
        parser = TikTokCheckerCLI.build_parser()
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            sys.exit(1)
        
        # Configure logging
        if hasattr(args, 'verbose') and args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Load proxies if specified
        proxies = None
        if hasattr(args, 'proxies') and args.proxies:
            try:
                proxies = TikTokCheckerCLI.load_proxies(args.proxies)
                logger.info(f"Loaded {len(proxies)} proxies")
            except Exception as e:
                logger.error(f"Failed to load proxies: {e}")
                sys.exit(1)
        
        # Handle available command
        if args.command == 'available':
            checker = TikTokAccountChecker(
                proxies=proxies,
                rate_limit_delay=1.0
            )
            
            logger.info(f"Checking availability for @{args.username}")
            is_available = checker.check_username_availability(args.username)
            
            if is_available:
                logger.info(f"Username @{args.username} is AVAILABLE!")
            else:
                logger.info(f"Username @{args.username} is TAKEN")
            
            return
        
        # Handle scan command
        if args.command == 'scan':
            try:
                usernames = TikTokCheckerCLI.load_usernames(args.wordlist)
                logger.info(f"Loaded {len(usernames)} usernames to scan")
                
                checker = TikTokAccountChecker(
                    proxies=proxies,
                    rate_limit_delay=args.delay,
                    threads=args.threads
                )
                
                results = checker.check_bulk(usernames, show_progress=True)
                
                # Filter for available usernames
                available = [r for r in results if r.status == AccountStatus.NOT_FOUND]
                
                if args.available_only:
                    # Output only available usernames
                    with open(args.output, 'w') as f:
                        for r in available:
                            f.write(f"{r.username}\n")
                    logger.info(f"Found {len(available)} available usernames. Saved to {args.output}")
                else:
                    # Output full results
                    ResultExporter.to_text(results, args.output, include_details=False)
                    logger.info(f"Full scan results saved to {args.output}")
                
                # Print summary
                print(f"\nScan complete: {len(available)}/{len(usernames)} usernames available")
                if available and len(available) <= 20:
                    print("Available usernames:")
                    for r in available[:20]:
                        print(f"  @{r.username}")
                
            except Exception as e:
                logger.error(f"Scan failed: {e}")
                sys.exit(1)
            
            return
        
        # Handle check command
        if args.command == 'check':
            # Collect usernames
            usernames = []
            if args.username:
                usernames = [args.username]
            elif args.input:
                try:
                    usernames = TikTokCheckerCLI.load_usernames(args.input)
                except Exception as e:
                    logger.error(f"Failed to load usernames: {e}")
                    sys.exit(1)
            else:
                logger.error("Either --username or --input is required")
                sys.exit(1)
            
            if not usernames:
                logger.error("No valid usernames found")
                sys.exit(1)
            
            # Create checker
            checker = TikTokAccountChecker(
                proxies=proxies,
                rate_limit_delay=args.delay,
                threads=args.threads,
                ms_token=args.ms_token if hasattr(args, 'ms_token') else None
            )
            
            # Perform check
            if len(usernames) == 1:
                # Single check
                result = checker.check_single(usernames[0], method=args.method)
                TikTokCheckerCLI.print_results([result], show_details=args.details)
                
                # Output to file if specified
                if args.output:
                    if args.format == 'json':
                        ResultExporter.to_json([result], args.output)
                    elif args.format == 'csv':
                        ResultExporter.to_csv([result], args.output)
                    else:
                        ResultExporter.to_text([result], args.output, include_details=args.details)
            else:
                # Bulk check
                logger.info(f"Checking {len(usernames)} accounts...")
                results = checker.check_bulk(usernames, method=args.method, show_progress=True)
                TikTokCheckerCLI.print_results(results, show_details=args.details)
                
                # Output to file if specified
                if args.output:
                    if args.format == 'json':
                        ResultExporter.to_json(results, args.output)
                    elif args.format == 'csv':
                        ResultExporter.to_csv(results, args.output)
                    else:
                        ResultExporter.to_text(results, args.output, include_details=args.details)


# ========== Entry Point ==========

if __name__ == "__main__":
    try:
        TikTokCheckerCLI.run()
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)