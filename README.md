# Burp AI Bridge

🤖 **AI-powered security testing through Burp Suite**

A Burp Suite extension that exposes proxy history via HTTP API, enabling AI assistants and scripts to analyze captured traffic for security vulnerabilities.

## Features

- **HTTP API** - Access Burp proxy history via REST endpoints
- **Real-time capture** - Automatically captures all proxied requests/responses
- **AI Integration** - Designed for AI assistants to analyze traffic
- **Vulnerability Detection** - Built-in client with basic vulnerability checks
- **Cross-platform** - Works on Windows, macOS, and Linux

## Installation

### Prerequisites

- Burp Suite (Community or Professional)
- [Jython Standalone JAR](https://www.jython.org/download) (2.7.x recommended)
- Python 3.x (for client)

### Setup

1. **Download Jython**
   ```
   https://www.jython.org/download
   Download: jython-standalone-2.7.4.jar
   ```

2. **Configure Burp Suite**
   - Go to: `Extender` → `Options` → `Python Environment`
   - Select the Jython standalone JAR file

3. **Load Extension**
   - Go to: `Extender` → `Extensions` → `Add`
   - Extension Type: `Python`
   - Extension file: `burp_ai_bridge.py`

4. **Verify Installation**
   ```bash
   curl http://127.0.0.1:8899/health
   ```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check and version info |
| `/history` | GET | Get all captured requests |
| `/history/{index}` | GET | Get specific request by index |
| `/stats` | GET | Get traffic statistics |

### Examples

```bash
# Health check
curl http://127.0.0.1:8899/health

# Get statistics
curl http://127.0.0.1:8899/stats

# Get all history
curl http://127.0.0.1:8899/history

# Get specific request
curl http://127.0.0.1:8899/history/0
```

### Response Format

```json
{
  "index": 0,
  "host": "example.com",
  "port": 443,
  "protocol": "https",
  "method": "GET",
  "url": "https://example.com/api/users",
  "status_code": 200,
  "headers": ["GET /api/users HTTP/1.1", "Host: example.com"],
  "request": "base64_encoded_request",
  "response": "base64_encoded_response"
}
```

## Python Client

```python
from client_example import BurpBridge

# Initialize client
burp = BurpBridge()

# Check connection
print(burp.health())

# Get all history
history = burp.get_history()

# Analyze for vulnerabilities
findings = burp.analyze_for_vulns(history)
for finding in findings:
    print(f"[{finding['severity']}] {finding['type']}: {finding['url']}")
```

### Run Analysis

```bash
pip install requests
python client_example.py
```

## Security Considerations

⚠️ **Important Security Notes:**

- API listens only on `127.0.0.1` (localhost)
- No authentication required - for local use only
- Do NOT expose to network or internet
- Captured data may contain sensitive information

## File Structure

```
BurpAIBridge/
├── burp_ai_bridge.py    # Burp Suite extension
├── client_example.py    # Python client
├── README.md            # Documentation
├── LICENSE              # MIT License
```

## Troubleshooting

### Extension won't load

1. Ensure Jython JAR is properly configured
2. Check Burp Suite Extender → Errors tab
3. Verify Python 2.7 compatible syntax

### Connection refused

1. Verify extension is loaded (check Extender tab)
2. Check if port 8899 is available
3. Look for errors in Burp Suite output

### No history captured

1. Ensure Proxy → Intercept is working
2. Browse to target through Burp proxy
3. Check that requests are appearing in Proxy → HTTP history

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

**Can Hieu**

