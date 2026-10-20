from flask import Flask, render_template, request, jsonify
import requests
import ssl
import socket
import whois
import dns.resolver
from urllib.parse import urlparse
import re
import uuid
import os
import time
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import google.generativeai as genai
import json
from src.feature_extractor import get_phone_numbers, extract_email_addresses
from dotenv import load_dotenv
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from pymongo import MongoClient

load_dotenv()

# MongoDB connection
client = MongoClient(os.environ.get('MONGODB_URI'))
db = client["FraudWebsiteDetect"] 
contacts_collection = db["customer_care_db"]

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

CORS(app)  
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["10 per minute", "50 per hour", "100 per day"],
    storage_uri="memory://"
)

# Gemini AI setup
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
genai.configure(api_key=GEMINI_API_KEY)

try:
    gemini_model = genai.GenerativeModel('gemini-pro')
except Exception as e:
    print(f"Warning: Gemini AI initialization failed: {e}")
    gemini_model = None

def load_and_filter_keywords(json_file_path):
    """Load and categorize fraud keywords from JSON"""
    try:
        with open(json_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        raw_keywords = data.get('fradulent_words', [])
        
        # Filter common words
        common_words = {
            'a', 'and', 'at', 'be', 'for', 'from', 'has', 'in', 'is', 'it', 
            'of', 'on', 'that', 'the', 'to', 'will', 'you', 'your', 'us', 
            'all', 'any', 'are', 'as', 'been', 'by', 'can', 'had', 'have', 
            'he', 'her', 'his', 'how', 'i', 'if', 'into', 'may', 'no', 
            'not', 'or', 'she', 'such', 'than', 'their', 'them', 'there', 
            'these', 'they', 'this', 'was', 'were', 'what', 'when', 'where', 
            'who', 'would', 'up', 'out', 'here', 'one', 'make', 'get', 'use',
            'take', 'keep', 'meet', 'read', 'open', 'buy', 'new', 'last',
            'best', 'only', 'back', 'name', 'end', 'home', 'work', 'time',
            'today', 'now', 'thank', 'thanks', 'please', 'dear', 'subject'
        }
        
        # Clean keywords
        filtered_keywords = [
            word for word in raw_keywords 
            if word.lower() not in common_words 
            and len(word) > 2
            and not word.endswith(('?', ':', ','))
        ]
        
        # Risk categories
        high_risk_keywords = [
            'phishing', 'malware', 'virus', 'scam', 'fraud', 'blackmail',
            'suspended', 'compromised', 'breach', 'exploit', 'malicious',
            'urgent', 'immediate', 'emergency', 'act', 'winner', 'won',
            'congratulations', 'prize', 'reward', 'guaranteed', 'risk-free',
            'investment', 'profit', 'earnings', 'money-making', 'billions',
            'loan', 'credit', 'financial', 'banking', 'deposit', 'withdrawal',
            'password', 'pin', 'credentials', 'verify', 'confirm', 'update',
            'reconfirm', 'authenticate', 'validation', 'account', 'security'
        ]
        
        medium_risk_keywords = [
            'limited', 'exclusive', 'special', 'promotional', 'offer',
            'discount', 'free', 'bonus', 'gift', 'giveaway', 'opportunity',
            'income', 'earn', 'paid', 'payment', 'bill', 'invoice',
            'subscription', 'membership', 'activation', 'renewal',
            'expiration', 'expired', 'click', 'link', 'download'
        ]
        
        # Categorize keywords
        high_risk = [word for word in filtered_keywords if word.lower() in [w.lower() for w in high_risk_keywords]]
        medium_risk = [word for word in filtered_keywords if word.lower() in [w.lower() for w in medium_risk_keywords]]
        low_risk = [word for word in filtered_keywords if word not in high_risk and word not in medium_risk]
        
        return {
            'all_keywords': filtered_keywords,
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'total_original': len(raw_keywords),
            'total_filtered': len(filtered_keywords)
        }
        
    except Exception as e:
        print(f"Error loading keywords: {e}")
        return {
            'all_keywords': [],
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'total_original': 0,
            'total_filtered': 0
        }

keywords_data = load_and_filter_keywords("data.json")

def check_ssl_certificate(url):
    """SSL certificate verification"""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        if not hostname:
            return {
                'score': 0,
                'status': 'Invalid URL',
                'details': ['Could not extract hostname'],
                'certificate_info': None
            }
        
        # Handle HTTP vs HTTPS
        if parsed_url.scheme == 'https':
            port = parsed_url.port or 443
        elif parsed_url.scheme == 'http':
            return {
                'score': 20,
                'status': 'No SSL (HTTP)',
                'details': ['Website uses HTTP - not secure'],
                'certificate_info': None
            }
        else:
            port = 443
        
        # SSL connection
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        socket.setdefaulttimeout(15)
        
        try:
            with socket.create_connection((hostname, port), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'has_ssl': True,
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'not_after': cert.get('notAfter', 'Unknown')
                    }
                    
                    # Check expiry
                    try:
                        not_after_str = cert.get('notAfter', '')
                        if not_after_str:
                            for date_format in ['%b %d %H:%M:%S %Y %Z', '%b %d %H:%M:%S %Y GMT']:
                                try:
                                    not_after = datetime.strptime(not_after_str, date_format)
                                    break
                                except ValueError:
                                    continue
                            else:
                                not_after = datetime.strptime(not_after_str.replace(' GMT', ''), '%b %d %H:%M:%S %Y')
                            
                            days_until_expiry = (not_after - datetime.now()).days
                        else:
                            days_until_expiry = 0
                            not_after = None
                    except Exception:
                        days_until_expiry = 0
                        not_after = None
                    
                    # Calculate score
                    ssl_score = 100
                    ssl_details = []
                    
                    if not_after is None:
                        ssl_score -= 20
                        ssl_details.append("Could not verify expiration")
                    elif days_until_expiry < 0:
                        ssl_score = 0
                        ssl_details.append("Certificate expired")
                    elif days_until_expiry < 7:
                        ssl_score = 30
                        ssl_details.append(f"Expires very soon ({days_until_expiry} days)")
                    elif days_until_expiry < 30:
                        ssl_score = 70
                        ssl_details.append(f"Expires soon ({days_until_expiry} days)")
                    else:
                        ssl_details.append(f"Valid until {not_after.strftime('%Y-%m-%d') if not_after else 'Unknown'}")
                    
                    # Check issuer
                    trusted_issuers = ['Let\'s Encrypt', 'DigiCert', 'Comodo', 'GeoTrust', 'VeriSign', 'Symantec']
                    issuer_name = ssl_info['issuer'].get('organizationName', ssl_info['issuer'].get('O', ''))
                    
                    if issuer_name and any(trusted.lower() in issuer_name.lower() for trusted in trusted_issuers):
                        ssl_details.append(f"Trusted CA: {issuer_name}")
                    elif issuer_name:
                        ssl_score -= 10
                        ssl_details.append(f"Issuer: {issuer_name}")
                    else:
                        ssl_score -= 15
                        ssl_details.append("Issuer info unavailable")
                    
                    ssl_score = max(0, ssl_score)
                    
                    return {
                        'score': ssl_score,
                        'status': 'Valid' if ssl_score > 50 else 'Invalid' if ssl_score > 0 else 'Critical',
                        'details': ssl_details,
                        'certificate_info': ssl_info
                    }
                    
        except ssl.SSLError as ssl_err:
            return {'score': 0, 'status': 'SSL Error', 'details': [f"SSL failed: {str(ssl_err)}"], 'certificate_info': None}
        except socket.timeout:
            return {'score': 0, 'status': 'Timeout', 'details': ['Connection timed out'], 'certificate_info': None}
        except Exception as conn_err:
            return {'score': 0, 'status': 'Connection Failed', 'details': [f"Connection failed: {str(conn_err)}"], 'certificate_info': None}
                
    except Exception as e:
        return {'score': 0, 'status': 'Analysis Failed', 'details': [f"SSL analysis failed: {str(e)}"], 'certificate_info': None}

def analyze_domain_metadata(url):
    """Domain analysis with robust WHOIS handling"""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.replace('www.', '')

    try:
        time.sleep(1)  # Avoid rate limiting
        domain_info = whois.whois(domain)
        
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = next((d for d in creation_date if d is not None), None)
        
        domain_age_days = 0
        domain_age_years = 0
        age_status = "Unknown"
        unavailability_reason = ""
        
        if creation_date:
            try:
                if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo:
                    creation_date = creation_date.replace(tzinfo=None)
                
                domain_age_days = (datetime.now() - creation_date).days
                domain_age_years = domain_age_days / 365.25
                
                if domain_age_days < 0 or domain_age_years > 50:
                    domain_age_days = 0
                    domain_age_years = 0
                    creation_date = None
                    age_status = "Invalid date"
                    unavailability_reason = "WHOIS returned invalid date"
                else:
                    age_status = "Available"
            except Exception as date_error:
                domain_age_days = 0
                domain_age_years = 0
                creation_date = None
                age_status = "Error parsing date"
                unavailability_reason = f"Date parsing failed: {str(date_error)}"
        else:
            age_status = "Unavailable"
            unavailability_reason = "WHOIS creation date is null - likely due to privacy protection or registry restrictions"

        domain_score = 0
        domain_details = []

        if creation_date is None:
            domain_score += 30  # Neutral score for privacy
            domain_details.append("Domain age private or unavailable (common for legitimate sites)")
            domain_details.append(f"Reason: {unavailability_reason}")
        elif domain_age_years >= 5:
            domain_score += 40
            domain_details.append(f"Domain is {domain_age_years:.1f} years old (established)")
        elif domain_age_years >= 1:
            domain_score += 25
            domain_details.append(f"Domain is {domain_age_years:.1f} years old (moderate)")
        elif domain_age_years >= 0.25:
            domain_score += 10
            domain_details.append(f"Domain is {domain_age_days} days old (new)")
        else:
            domain_details.append(f"Domain is very new ({domain_age_days} days)")

        registrar = domain_info.registrar
        if registrar:
            trusted_registrars = ['GoDaddy', 'Namecheap', 'Google', 'Amazon', 'Cloudflare', 'Network Solutions']
            if any(trusted in str(registrar) for trusted in trusted_registrars):
                domain_score += 20
                domain_details.append(f"Trusted registrar: {registrar}")
            else:
                domain_score += 10
                domain_details.append(f"Registrar: {registrar}")
        else:
            domain_score += 10
            domain_details.append("Registrar information private or unavailable")

        if domain_info.org and 'privacy' not in str(domain_info.org).lower():
            domain_score += 10
            domain_details.append("Registration not privacy protected")
        else:
            domain_score += 15
            domain_details.append("Privacy protected registration (common for legitimate sites)")

        # DNS checks
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            if mx_records:
                domain_score += 10
                domain_details.append("Has email capability (MX records)")
        except:
            domain_details.append("No MX records found")

        try:
            a_records = dns.resolver.resolve(domain, 'A')
            if a_records:
                domain_score += 10
                domain_details.append("Has proper A records")
        except:
            domain_details.append("No A records found")

        return {
            'score': min(100, domain_score),
            'details': domain_details,
            'metadata': {
                'age_years': round(domain_age_years, 1) if creation_date else 'Private/Unavailable',
                'age_days': domain_age_days if creation_date else 'Private/Unavailable',
                'registrar': str(registrar) if registrar else 'Private/Unavailable',
                'creation_date': creation_date.strftime('%Y-%m-%d') if creation_date else 'Private/Unavailable',
                'expiration_date': 'Unknown',
                'age_status': age_status,
                'unavailability_reason': unavailability_reason if unavailability_reason else "Data available"
            }
        }

    except Exception as e:
        error_reason = f"WHOIS lookup failed: {str(e)}"
        print(f"WHOIS error for {domain}: {e}")
        return {
            'score': 50,  # Neutral score when WHOIS completely fails
            'details': [
                "Domain analysis limited - WHOIS data unavailable",
                f"Reason: {error_reason}",
                "This could be due to: rate limiting, server issues, or domain registry restrictions"
            ],
            'metadata': {
                'age_years': 'Unknown',
                'age_days': 'Unknown',
                'registrar': 'Unknown',
                'creation_date': 'Unknown',
                'expiration_date': 'Unknown',
                'age_status': 'Error',
                'unavailability_reason': error_reason
            }
        }

def verify_against_database(contacts):
    """Check contacts against fraud database"""
    try:
        matches = []
        
        for contact in contacts:
            if re.match(r'^\+?[\d\s\-()]+$', contact):
                clean_contact = re.sub(r'\D', '', contact)
                phone_match = contacts_collection.find_one({
                    'idnumber': {'$regex': f'.*{clean_contact}.*'}
                })
                if phone_match:
                    matches.append(contact)
                    continue

            email_name_match = contacts_collection.find_one({
                'suspectname': {'$regex': f'.*{re.escape(contact)}.*', '$options': 'i'}
            })
            if email_name_match:
                matches.append(contact)

        return {
            'match_count': len(matches),
            'matches': list(set(matches)),
            'score': 100 - (len(matches) * 25) if matches else 100
        }

    except Exception as e:
        print(f"MongoDB error: {e}")
        return {'match_count': 0, 'matches': [], 'score': 50}

def content_analysis(url, keywords_data):
    """Content analysis with risk-weighted keywords"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = ' '.join(soup.stripped_strings).lower()
        
        content_score = 100
        content_details = []
        issues_found = []
        keyword_matches = {'high': [], 'medium': [], 'low': []}
        
        # High-risk keywords
        for keyword in keywords_data['high_risk']:
            if keyword.lower() in text_content:
                content_score -= 25
                keyword_matches['high'].append(keyword)
                issues_found.append(f"High-risk keyword: '{keyword}'")
        
        # Medium-risk keywords
        for keyword in keywords_data['medium_risk']:
            if keyword.lower() in text_content:
                content_score -= 10
                keyword_matches['medium'].append(keyword)
                issues_found.append(f"Medium-risk keyword: '{keyword}'")
        
        # Low-risk keywords
        low_risk_matches = 0
        for keyword in keywords_data['low_risk']:
            if keyword.lower() in text_content:
                low_risk_matches += 1
                keyword_matches['low'].append(keyword)
        
        if low_risk_matches > 5:
            penalty = min(20, low_risk_matches * 2)
            content_score -= penalty
            issues_found.append(f"High keyword concentration: {low_risk_matches}")
        elif low_risk_matches > 0:
            content_score -= min(10, low_risk_matches)
            issues_found.append(f"Low-risk keywords: {low_risk_matches}")
        
        # Sensitive forms check
        forms = soup.find_all('form')
        sensitive_forms = 0
        for form in forms:
            inputs = form.find_all('input')
            for input_field in inputs:
                field_type = input_field.get('type', '').lower()
                field_name = input_field.get('name', '').lower()
                if (field_type in ['password', 'email'] or 
                    any(term in field_name for term in ['password', 'credit', 'card', 'ssn', 'bank'])):
                    sensitive_forms += 1
                    break
        
        if sensitive_forms > 0:
            content_score -= (sensitive_forms * 15)
            issues_found.append(f"Sensitive forms found: {sensitive_forms}")
        
        # URL pattern check
        parsed_url = urlparse(url)
        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # Multiple hyphens
            r'[a-z]+\d+[a-z]+\.',  # Mixed numbers/letters
            r'bit\.ly|tinyurl|t\.co|short',  # URL shorteners
            r'secure.*update|account.*verify'  # Phishing patterns
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, parsed_url.netloc, re.IGNORECASE):
                content_score -= 30
                issues_found.append("Suspicious URL pattern")
                break
        
        # Trust indicators
        positive_indicators = [
            r'privacy policy', r'terms of service', r'about us', 
            r'contact us', r'customer service', r'support',
            r'copyright \d{4}', r'all rights reserved'
        ]
        
        positive_count = 0
        for pattern in positive_indicators:
            if re.search(pattern, text_content):
                positive_count += 1
        
        if positive_count > 0:
            boost = min(25, positive_count * 5)
            content_score += boost
            content_details.append(f"Trust indicators: {positive_count} (+{boost})")
        
        content_score = max(0, min(100, content_score))
        
        # Risk level
        if content_score >= 80:
            risk_level = "LOW"
        elif content_score >= 60:
            risk_level = "MEDIUM"
        elif content_score >= 40:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        total_keyword_matches = sum(len(matches) for matches in keyword_matches.values())
        
        if issues_found:
            content_details.extend(issues_found)
        else:
            content_details.append("No suspicious patterns detected")
        
        return {
            'score': content_score,
            'risk_level': risk_level,
            'details': content_details,
            'keyword_matches': keyword_matches,
            'total_matches': total_keyword_matches,
            'sensitive_forms': sensitive_forms,
            'positive_indicators': positive_count,
            'issues_count': len(issues_found)
        }
        
    except Exception as e:
        return {
            'score': 50,
            'risk_level': "UNKNOWN",
            'details': [f"Content analysis failed: {str(e)}"],
            'keyword_matches': {'high': [], 'medium': [], 'low': []},
            'total_matches': 0,
            'sensitive_forms': 0,
            'positive_indicators': 0,
            'issues_count': 0
        }

def gemini_ai_analysis(url, content_summary):
    """Gemini AI risk assessment"""
    if not gemini_model:
        return {'score': 50, 'analysis': "AI unavailable", 'risk_level': 'Unknown'}
    
    try:
        prompt = f"""
        Analyze this website for fraud/scam indicators:
        
        URL: {url}
        Content Summary: {content_summary}
        
        Provide:
        1. Risk score 0-100 (0=fraudulent, 100=legitimate)
        2. Brief analysis
        3. Risk level (Low/Medium/High/Critical)
        
        Format:
        RISK_SCORE: [0-100]
        RISK_LEVEL: [Low/Medium/High/Critical]
        ANALYSIS: [analysis]
        """
        
        response = gemini_model.generate_content(prompt)
        ai_response = response.text
        
        # Parse response
        risk_score = 50
        risk_level = 'Medium'
        analysis = ai_response
        
        score_match = re.search(r'RISK_SCORE:\s*(\d+)', ai_response)
        if score_match:
            risk_score = int(score_match.group(1))
        
        level_match = re.search(r'RISK_LEVEL:\s*(\w+)', ai_response)
        if level_match:
            risk_level = level_match.group(1)
        
        analysis_match = re.search(r'ANALYSIS:\s*(.*)', ai_response, re.DOTALL)
        if analysis_match:
            analysis = analysis_match.group(1).strip()
        
        return {
            'score': risk_score,
            'analysis': analysis,
            'risk_level': risk_level
        }
        
    except Exception as e:
        return {'score': 50, 'analysis': f"AI failed: {str(e)}", 'risk_level': 'Unknown'}

def detect_major_red_flags(ssl_result, domain_result, content_result):
    """Detecting combinations of red flags that indicate high fraud risk"""
    red_flags = []
    risk_multiplier = 1.0
    
    # Check for new domain
    domain_age = domain_result['metadata'].get('age_years', 'Unknown')
    is_new_domain = False
    if isinstance(domain_age, (int, float)) and domain_age < 0.25:  # Less than 3 months
        is_new_domain = True
        red_flags.append("Very new domain (less than 3 months)")
    
    # Check for privacy protection
    has_privacy_protection = False
    if domain_age == 'Private/Unavailable' or 'private' in str(domain_result['details']).lower():
        has_privacy_protection = True
        red_flags.append("Privacy protected registration")
    
    # Check for poor SSL
    has_poor_ssl = False
    if ssl_result['score'] < 50:
        has_poor_ssl = True
        red_flags.append("Poor SSL certificate quality")
    
    # Check for suspicious content
    has_suspicious_content = False
    if content_result['score'] < 60 or content_result.get('issues_count', 0) > 0:
        has_suspicious_content = True
        red_flags.append("Suspicious content detected")
    
    # MAJOR RED FLAG COMBINATION
    if is_new_domain and has_privacy_protection and has_poor_ssl and has_suspicious_content:
        risk_multiplier = 0.3  # Severely reduce overall score
        red_flags.append(" MAJOR RED FLAG: New domain + Privacy + Poor SSL + Suspicious content")
    
    # Other concerning combinations
    elif is_new_domain and has_privacy_protection and (has_poor_ssl or has_suspicious_content):
        risk_multiplier = 0.6
        red_flags.append(" HIGH RISK: Multiple concerning factors detected")
    
    elif is_new_domain and has_suspicious_content:
        risk_multiplier = 0.7
        red_flags.append(" MODERATE RISK: New domain with suspicious content")
    
    return {
        'red_flags': red_flags,
        'risk_multiplier': risk_multiplier,
        'major_red_flag_detected': risk_multiplier <= 0.5
    }


def analyze_website(url):
    """Main website analysis with robust individual component error handling"""
    start_time = time.time()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Initialize default results for each component
    ssl_result = {'score': 0, 'status': 'Error', 'details': ['SSL analysis failed']}
    domain_result = {'score': 50, 'details': ['Domain analysis failed'], 'metadata': {'age_years': 'Unknown', 'unavailability_reason': 'Analysis failed'}}
    content_result = {'score': 50, 'details': ['Content analysis failed'], 'issues_count': 0, 'positive_indicators': 0}
    contact_result = {'score': 50, 'matches': [], 'match_count': 0}
    ai_result = {'score': 50, 'analysis': 'AI analysis failed', 'risk_level': 'Unknown'}

    # Try each analysis individually - failures won't break other components
    try:
        ssl_result = check_ssl_certificate(url)
        print(f"SSL analysis completed: {ssl_result['status']}")
    except Exception as e:
        print(f"SSL analysis failed: {e}")
    
    try:
        domain_result = analyze_domain_metadata(url)
        print(f"Domain analysis completed: {domain_result['metadata']['age_status']}")
    except Exception as e:
        print(f"Domain analysis failed: {e}")
        domain_result['details'] = [f"Domain analysis failed: {str(e)}"]
        domain_result['metadata']['unavailability_reason'] = f"Analysis error: {str(e)}"
    
    try:
        content_result = content_analysis(url, keywords_data)
        print(f"Content analysis completed: {content_result['risk_level']}")
    except Exception as e:
        print(f"Content analysis failed: {e}")
        content_result['details'] = [f"Content analysis failed: {str(e)}"]
    
    try:
        contacts = get_phone_numbers(url) + extract_email_addresses(url)
        contact_result = verify_against_database(contacts)
        print(f"Contact verification completed: {contact_result['match_count']} matches")
        
        # Immediate flag for known fraud contacts
        if contact_result['match_count'] > 0:
            return {
                "analysis_id": str(uuid.uuid4()),
                "url": url,
                "verdict": "Highly likely fraudulent - known bad contacts",
                "risk_level": "Critical Risk",
                "matched_contacts": contact_result['matches'],
                "processing_time": f"{time.time() - start_time:.2f} seconds",
                "immediate_flag": True
            }
    except Exception as e:
        print(f"Contact verification failed: {e}")
        contacts = []
        contact_result = {'score': 50, 'matches': [], 'match_count': 0}
    
    try:
        content_summary = f"""
        SSL: {ssl_result['status']}
        Domain Age: {domain_result['metadata'].get('age_years', 'Unknown')}
        Issues: {content_result['issues_count']}
        Trust Indicators: {content_result.get('positive_indicators', 0)}
        """
        ai_result = gemini_ai_analysis(url, content_summary)
        print(f"AI analysis completed: {ai_result['risk_level']}")
    except Exception as e:
        print(f"AI analysis failed: {e}")
        ai_result = {'score': 50, 'analysis': f"AI analysis failed: {str(e)}", 'risk_level': 'Unknown'}

    # Calculate overall score with safe defaults
    weights = {'ssl_score': 0.20, 'domain_score': 0.25, 'content_score': 0.25, 'contact_score': 0.15, 'ai_score': 0.15}
    scores = {
        'ssl_score': ssl_result.get('score', 0),
        'domain_score': domain_result.get('score', 50),
        'content_score': content_result.get('score', 50),
        'ai_score': ai_result.get('score', 50),
        'contact_score': contact_result.get('score', 50)
    }
    red_flag_analysis = detect_major_red_flags(ssl_result, domain_result, content_result)

    overall_score = sum(score * weights[key] for key, score in scores.items())
    overall_score *= red_flag_analysis['risk_multiplier']  # Apply red flag penalty

    # Determine verdict
    if red_flag_analysis['major_red_flag_detected']:
        verdict = "MAJOR RED FLAGS DETECTED - Highly likely fraudulent"
        risk_level = "Critical Risk"
    elif overall_score >= 80:
        verdict = "Highly likely legitimate"
        risk_level = "Low Risk"
    elif overall_score >= 60:
        verdict = "Likely legitimate but exercise caution"
        risk_level = "Medium Risk"
    elif overall_score >= 40:
        verdict = "Potentially fraudulent - proceed with caution"
        risk_level = "High Risk"
    else:
        verdict = "Highly likely fraudulent - avoid this website"
        risk_level = "Critical Risk"

    processing_time = time.time() - start_time

    # Auto-add risky contacts to database
    if overall_score < 40:
        try:
            new_entries = []
            for contact in contacts:
                if re.match(r'^\+?[\d\s\-()]+$', contact):
                    clean_contact = re.sub(r'\D', '', contact)
                    if not contacts_collection.find_one({'idnumber': clean_contact}):
                        new_entries.append({'idnumber': clean_contact, 'suspectname': 'Auto-added'})
                else:
                    clean_contact = contact.lower().strip()
                    if not contacts_collection.find_one({'suspectname': clean_contact}):
                        new_entries.append({'suspectname': clean_contact, 'idnumber': 'N/A'})
            if new_entries:
                contacts_collection.insert_many(new_entries)
                print(f"Added {len(new_entries)} risky contacts to DB")
        except Exception as e:
            print(f"MongoDB update error: {e}")

    return {
        "analysis_id": str(uuid.uuid4()),
        "url": url,
        "processing_time": f"{processing_time:.2f} seconds",
        "scores": {
            "overall": {"score": round(overall_score, 2), "verdict": verdict, "risk_level": risk_level},
            "ssl": ssl_result,
            "domain": domain_result,
            "content": content_result,
            "ai_analysis": ai_result,
            "contact_check": contact_result
        }
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
@limiter.limit("5 per minute")
def analyze_form():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415
        
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    try:
        result = analyze_website(url)
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({
            "error": "Analysis failed",
            "analysis_id": str(uuid.uuid4()),
            "url": url,
            "processing_time": "0.00 seconds",
            "scores": {
                "overall": {"score": 0, "verdict": "Analysis failed", "risk_level": "Unknown"},
                "ssl": {"score": 0, "status": "Error", "details": ["Analysis failed"]},
                "domain": {"score": 0, "details": ["Analysis failed"], "metadata": {}},
                "content": {"score": 0, "details": ["Analysis failed"], "issues_found": 0},
                "ai_analysis": {"score": 0, "analysis": "Analysis failed", "risk_level": "Unknown"},
                "contact_check": {"score": 0, "matches": [], "match_count": 0}
            }
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print("Starting fraud detection service...")
    app.run(host='0.0.0.0', port=port, debug=debug)
