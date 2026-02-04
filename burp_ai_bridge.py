# Burp AI Bridge Extension v1.0.0
# Exposes Burp Suite proxy history via HTTP API for AI integration
# 
# Author: Can Hieu
# License: MIT
# Repository: https://github.com/canhieu/BurpAIBridge
#
# Installation:
# 1. Download Jython standalone JAR: https://www.jython.org/download
# 2. Burp Suite -> Extender -> Options -> Python Environment -> Select Jython JAR
# 3. Burp Suite -> Extender -> Extensions -> Add -> Extension Type: Python -> Select this file

from burp import IBurpExtender, IHttpListener, IProxyListener
from java.io import PrintWriter
from java.net import ServerSocket, InetAddress
from java.lang import Thread, Runnable
import json
import base64
import re

VERSION = "1.0.0"
AUTHOR = "Can Hieu"

class BurpExtender(IBurpExtender, IProxyListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Burp AI Bridge")
        
        # Get stdout for logging
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Register proxy listener
        callbacks.registerProxyListener(self)
        
        # Store for history
        self._history = []
        self._max_history = 1000
        
        # Start HTTP server
        self._port = 8899
        self._running = True
        
        server_thread = Thread(HttpServerRunnable(self))
        server_thread.start()
        
        self._stdout.println("=" * 50)
        self._stdout.println("[+] Burp AI Bridge v%s" % VERSION)
        self._stdout.println("[+] Author: %s" % AUTHOR)
        self._stdout.println("[+] API running on http://127.0.0.1:%d" % self._port)
        self._stdout.println("=" * 50)
        self._stdout.println("[+] Available Endpoints:")
        self._stdout.println("    GET  /health      - Health check")
        self._stdout.println("    GET  /history     - Get all proxy history")
        self._stdout.println("    GET  /history/N   - Get specific request by index")
        self._stdout.println("    GET  /stats       - Get traffic statistics")
        self._stdout.println("=" * 50)
    
    def processProxyMessage(self, messageIsRequest, message):
        """Capture proxy messages"""
        if not messageIsRequest:
            # Only capture completed request/response pairs
            messageInfo = message.getMessageInfo()
            
            request = messageInfo.getRequest()
            response = messageInfo.getResponse()
            httpService = messageInfo.getHttpService()
            
            if request and response:
                entry = {
                    "index": len(self._history),
                    "host": httpService.getHost(),
                    "port": httpService.getPort(),
                    "protocol": httpService.getProtocol(),
                    "request": base64.b64encode(bytearray(request)).decode('utf-8'),
                    "response": base64.b64encode(bytearray(response)).decode('utf-8'),
                    "request_text": self._helpers.bytesToString(request),
                    "response_length": len(response)
                }
                
                # Parse request info
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                entry["method"] = requestInfo.getMethod()
                entry["url"] = str(requestInfo.getUrl())
                entry["headers"] = [str(h) for h in requestInfo.getHeaders()]
                
                # Parse response info
                if response:
                    responseInfo = self._helpers.analyzeResponse(response)
                    entry["status_code"] = responseInfo.getStatusCode()
                    entry["response_headers"] = [str(h) for h in responseInfo.getHeaders()]
                
                self._history.append(entry)
                
                # Limit history size
                if len(self._history) > self._max_history:
                    self._history.pop(0)
    
    def get_history(self):
        """Return all history"""
        return self._history
    
    def get_history_item(self, index):
        """Return specific history item"""
        if 0 <= index < len(self._history):
            return self._history[index]
        return None
    
    def get_stats(self):
        """Return statistics"""
        return {
            "version": VERSION,
            "author": AUTHOR,
            "total_requests": len(self._history),
            "hosts": list(set([h["host"] for h in self._history])),
            "methods": {m: sum(1 for h in self._history if h["method"] == m) 
                       for m in set([h["method"] for h in self._history])}
        }


class HttpServerRunnable(Runnable):
    """Simple HTTP server to expose API"""
    
    def __init__(self, extender):
        self._extender = extender
    
    def run(self):
        try:
            server = ServerSocket(self._extender._port, 50, InetAddress.getByName("127.0.0.1"))
            self._extender._stdout.println("[+] HTTP Server started on port %d" % self._extender._port)
            
            while self._extender._running:
                try:
                    client = server.accept()
                    handler = Thread(RequestHandler(self._extender, client))
                    handler.start()
                except Exception as e:
                    self._extender._stderr.println("[-] Server error: %s" % str(e))
        except Exception as e:
            self._extender._stderr.println("[-] Failed to start server: %s" % str(e))


class RequestHandler(Runnable):
    """Handle individual HTTP requests"""
    
    def __init__(self, extender, client):
        self._extender = extender
        self._client = client
    
    def run(self):
        try:
            input_stream = self._client.getInputStream()
            output_stream = self._client.getOutputStream()
            
            # Read request
            request_data = []
            while True:
                b = input_stream.read()
                if b == -1:
                    break
                request_data.append(chr(b))
                # Check for end of headers
                if len(request_data) >= 4:
                    last4 = ''.join(request_data[-4:])
                    if last4 == '\r\n\r\n':
                        break
            
            request = ''.join(request_data)
            
            # Parse request line
            lines = request.split('\r\n')
            if lines:
                parts = lines[0].split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
                    
                    # Route request
                    response_body = ""
                    status = "200 OK"
                    
                    # Add CORS headers
                    cors_headers = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n"
                    
                    if method == "OPTIONS":
                        response_body = ""
                    elif path == "/health":
                        response_body = json.dumps({
                            "status": "ok", 
                            "extension": "Burp AI Bridge",
                            "version": VERSION,
                            "author": AUTHOR
                        })
                    elif path == "/history":
                        response_body = json.dumps(self._extender.get_history(), indent=2)
                    elif path.startswith("/history/"):
                        try:
                            index = int(path.split("/")[-1])
                            item = self._extender.get_history_item(index)
                            if item:
                                response_body = json.dumps(item, indent=2)
                            else:
                                status = "404 Not Found"
                                response_body = json.dumps({"error": "Item not found"})
                        except:
                            status = "400 Bad Request"
                            response_body = json.dumps({"error": "Invalid index"})
                    elif path == "/stats":
                        response_body = json.dumps(self._extender.get_stats(), indent=2)
                    else:
                        status = "404 Not Found"
                        response_body = json.dumps({
                            "error": "Endpoint not found", 
                            "available": ["/health", "/history", "/history/N", "/stats"]
                        })
                    
                    # Send response
                    response = "HTTP/1.1 %s\r\n%sContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (
                        status, cors_headers, len(response_body), response_body
                    )
                    
                    output_stream.write(bytearray(response.encode('utf-8')))
                    output_stream.flush()
            
            self._client.close()
        except Exception as e:
            self._extender._stderr.println("[-] Request handler error: %s" % str(e))
            try:
                self._client.close()
            except:
                pass
