import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def get_phone_numbers(url, timeout=10):
    """Extract phone numbers from webpage"""
    try:
        session = requests.Session()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        session.headers.update(headers)

        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = ' '.join(soup.stripped_strings)

        # Phone pattern
        phone_pattern = re.compile(r'''
            (?:(?:\+|00)[1-9]\d{0,3}[\s.-]?)?    # International prefix
            (?:\(?\d{1,4}\)?[\s.-]?)?            # Area code
            \d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{1,9}  # Main number
        ''', re.VERBOSE)
        
        phone_numbers = phone_pattern.findall(text_content)

        # Filter valid numbers
        filtered_numbers = set()
        for num in phone_numbers:
            cleaned_num = re.sub(r'\s+', ' ', num).strip()
            digits = ''.join(re.findall(r'\d', cleaned_num))
            if len(digits) >= 7 and not re.match(r'^(\d)\1+$', digits):
                filtered_numbers.add(cleaned_num)

        return list(filtered_numbers)
    except Exception as e:
        print(f"Error extracting phone numbers: {e}")
        return []

def extract_email_addresses(url, timeout=10):
    """Extract email addresses from webpage"""
    try:
        session = requests.Session()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        session.headers.update(headers)

        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = ' '.join(soup.stripped_strings)

        # Email pattern
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        emails = email_pattern.findall(text_content)
        
        # Filter fake emails
        filtered_emails = [
            email for email in emails 
            if not re.match(r'.*(@example\.|@test\.|@domain\.)', email)
        ]
        
        return list(set(filtered_emails))
    except Exception as e:
        print(f"Error extracting email addresses: {e}")
        return []
