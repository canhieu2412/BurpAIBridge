#!/usr/bin/env python3
"""
Burp AI Bridge Client v1.0.0
Python client for interacting with Burp AI Bridge extension

Author: Can Hieu
License: MIT
"""

import requests
import base64
import json
from typing import Optional, Dict, Any, List

class BurpBridge:
    """Client for Burp AI Bridge API"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8899):
        """
        Initialize Burp Bridge client
        
        Args:
            host: API host (default: 127.0.0.1)
            port: API port (default: 8899)
        """
        self.base_url = f"http://{host}:{port}"
    
    def health(self) -> Dict[str, Any]:
        """Check if Burp AI Bridge is running"""
        r = requests.get(f"{self.base_url}/health")
        return r.json()
    
    def get_history(self) -> List[Dict]:
        """Get all proxy history"""
        r = requests.get(f"{self.base_url}/history")
        return r.json()
    
    def get_history_item(self, index: int) -> Dict:
        """Get specific history item by index"""
        r = requests.get(f"{self.base_url}/history/{index}")
        return r.json()
    
    def get_stats(self) -> Dict:
        """Get traffic statistics"""
        r = requests.get(f"{self.base_url}/stats")
        return r.json()
    
    def analyze_for_vulns(self, history: List[Dict]) -> List[Dict]:
        """
        Analyze history for potential vulnerabilities
        
        Args:
            history: List of history items from get_history()
        
        Returns:
            List of findings with type, severity, and details
        """
        findings = []
        
        for item in history:
            url = item.get("url", "")
            method = item.get("method", "")
            request_text = item.get("request_text", "")
            
            # Check for SSRF indicators
            ssrf_params = ["url=", "path=", "file=", "src=", "img=", "load=", "uri=", "target="]
            if any(p in url.lower() for p in ssrf_params):
                findings.append({
                    "type": "Potential SSRF",
                    "severity": "HIGH",
                    "url": url,
                    "method": method,
                    "detail": "URL contains parameter that may accept user-controlled URLs"
                })
            
            # Check for SQL injection indicators
            sqli_params = ["id=", "user=", "name=", "order=", "sort=", "query=", "search="]
            if any(p in url.lower() for p in sqli_params):
                findings.append({
                    "type": "Potential SQL Injection",
                    "severity": "HIGH", 
                    "url": url,
                    "method": method,
                    "detail": "URL contains parameter that may be injectable"
                })
            
            # Check for sensitive data exposure
            sensitive_params = ["password", "token", "api_key", "secret", "auth", "key"]
            if any(p in url.lower() for p in sensitive_params):
                findings.append({
                    "type": "Sensitive Data in URL",
                    "severity": "MEDIUM",
                    "url": url,
                    "method": method,
                    "detail": "Sensitive parameter found in URL - may be logged"
                })
            
            # Check for file upload
            if "multipart/form-data" in request_text.lower():
                findings.append({
                    "type": "File Upload Detected",
                    "severity": "INFO",
                    "url": url,
                    "method": method,
                    "detail": "File upload functionality - check for unrestricted upload"
                })
            
            # Check for path traversal indicators
            path_params = ["file=", "path=", "page=", "include=", "template=", "dir="]
            if any(p in url.lower() for p in path_params):
                findings.append({
                    "type": "Potential Path Traversal",
                    "severity": "HIGH",
                    "url": url,
                    "method": method,
                    "detail": "URL contains file/path parameter - test for LFI/RFI"
                })
        
        return findings


def main():
    """Example usage of BurpBridge client"""
    
    print("=" * 50)
    print("Burp AI Bridge Client v1.0.0")
    print("Author: Can Hieu")
    print("=" * 50)
    
    burp = BurpBridge()
    
    # Check connection
    print("\n[*] Checking connection...")
    try:
        health = burp.health()
        print(f"[+] Connected to {health.get('extension')} v{health.get('version')}")
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed! Make sure Burp AI Bridge extension is loaded.")
        return
    except Exception as e:
        print(f"[-] Error: {e}")
        return
    
    # Get statistics
    print("\n[*] Fetching statistics...")
    stats = burp.get_stats()
    print(f"[+] Total requests captured: {stats['total_requests']}")
    print(f"[+] Hosts: {', '.join(stats['hosts']) if stats['hosts'] else 'None'}")
    print(f"[+] Methods: {stats['methods']}")
    
    # Get history
    print("\n[*] Fetching proxy history...")
    history = burp.get_history()
    print(f"[+] Retrieved {len(history)} requests")
    
    # Show recent requests
    if history:
        print("\n[*] Recent requests:")
        for item in history[-5:]:
            print(f"    {item['method']} {item['url'][:60]}... -> {item.get('status_code', '?')}")
    
    # Analyze for vulnerabilities
    print("\n[*] Analyzing for potential vulnerabilities...")
    findings = burp.analyze_for_vulns(history)
    
    if findings:
        print(f"[!] Found {len(findings)} potential issues:\n")
        severity_icons = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}
        
        for finding in findings:
            icon = severity_icons.get(finding['severity'], "❓")
            print(f"  {icon} [{finding['severity']}] {finding['type']}")
            print(f"     URL: {finding['url'][:70]}...")
            print(f"     Detail: {finding['detail']}")
            print()
    else:
        print("[+] No obvious vulnerabilities detected in captured traffic")
    
    print("=" * 50)
    print("Analysis complete!")
    print("=" * 50)


if __name__ == "__main__":
    main()
