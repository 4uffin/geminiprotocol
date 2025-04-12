#!/usr/bin/env python3
import socketserver
import ssl
import requests
import re
import logging
import time
from html import unescape
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, unquote
from requests.adapters import HTTPAdapter, Retry

# ------------------------- Configuration -------------------------
PORT = 1965
CERTFILE = "server.crt"  # Provide your TLS certificate here
KEYFILE = "server.key"   # Provide your TLS key here

# Cache expiration in seconds (e.g., 300 sec = 5 minutes)
CACHE_TTL = 300
# In-memory cache: dict mapping URL -> (timestamp, gemtext content)
cache = {}

# Allowed hostnames for security: only allow GitHub domain(s)
ALLOWED_HOSTS = {"github.com", "www.github.com", "gist.github.com"}

# Timeout for HTTP requests
HTTP_TIMEOUT = 10

# ------------------------- Logging Setup -------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

# ------------------------- HTTP Session with Retry -------------------------
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))

# ------------------------- HTML to Gemtext Converter -------------------------
def html_to_gemtext(html):
    """
    Convert basic HTML content into a more structured Gemtext.
    This converter handles:
      - Headings: <h1> to <h3> as "# ", "## ", "### "
      - Lists: <ul> / <ol> list items prefixed with "* "
      - Links: Converts anchor text and URL into Gemini link syntax.
      - Preformatted code blocks: kept with a simple prefix.
    """
    soup = BeautifulSoup(html, "html.parser")
    # Remove scripts, styles, nav, footer, and aside.
    for tag in soup(["script", "style", "nav", "footer", "aside"]):
        tag.decompose()

    gemtext_lines = []

    def process_element(el):
        if el.name in ["h1", "h2", "h3"]:
            level = {"h1": "# ", "h2": "## ", "h3": "### "}[el.name]
            text = el.get_text(separator=" ", strip=True)
            gemtext_lines.append(level + text)
        elif el.name in ["p", "div"]:
            text = el.get_text(separator=" ", strip=True)
            if text:
                gemtext_lines.append(text)
        elif el.name in ["ul", "ol"]:
            for li in el.find_all("li", recursive=False):
                li_text = li.get_text(separator=" ", strip=True)
                gemtext_lines.append("* " + li_text)
        elif el.name == "pre":
            # Preserve code blocks.
            code = el.get_text()
            gemtext_lines.append("```")
            gemtext_lines.append(code)
            gemtext_lines.append("```")
        elif el.name == "a":
            href = el.get("href", "").strip()
            text = el.get_text(separator=" ", strip=True)
            if href and text:
                # Gemini link syntax: "=> URL link text"
                gemtext_lines.append(f"=> {href} {text}")
            elif href:
                gemtext_lines.append(f"=> {href}")
        elif hasattr(el, "contents"):
            # Recurse into children
            for child in el.contents:
                process_element(child)
        elif isinstance(el, str):
            line = el.strip()
            if line:
                gemtext_lines.append(line)

    # Process top-level elements from <body> if exists
    body = soup.body if soup.body else soup
    for child in body.contents:
        process_element(child)

    # Clean up: collapse multiple blank lines
    cleaned = []
    for line in gemtext_lines:
        if not cleaned or line.strip() or cleaned[-1].strip():
            cleaned.append(line.strip())
    return "\n".join(cleaned)

# ------------------------- Gemini Request Handler -------------------------
class GeminiRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            # Read the Gemini request (a single line, CRLF terminated)
            request_line = self.rfile.readline().decode("utf-8").strip()
            if not request_line:
                return

            logging.info("Received request: %s", request_line)
            parsed = urlparse(request_line)
            qs = parse_qs(parsed.query)
            target_url = qs.get("url", [None])[0]
            if not target_url:
                self.wfile.write(b"51 Invalid request: missing target URL\r\n")
                return

            # URL-decode the target URL
            target_url = unquote(target_url)
            url_parsed = urlparse(target_url)
            hostname = url_parsed.hostname or ""
            if hostname.lower() not in ALLOWED_HOSTS:
                logging.warning("Blocked URL: %s (host not allowed)", target_url)
                self.wfile.write(b"51 URL not allowed\r\n")
                return

            # Check cache first
            now = time.time()
            if target_url in cache:
                ts, content = cache[target_url]
                if now - ts < CACHE_TTL:
                    logging.info("Cache hit for %s", target_url)
                    header = "20 Cached GitHub content\r\n"
                    self.wfile.write(header.encode("utf-8"))
                    self.wfile.write(content.encode("utf-8"))
                    return
                else:
                    logging.info("Cache expired for %s", target_url)
                    del cache[target_url]

            logging.info("Fetching: %s", target_url)
            try:
                response = session.get(target_url, timeout=HTTP_TIMEOUT)
            except requests.exceptions.RequestException as e:
                logging.error("HTTP error: %s", e)
                self.wfile.write(f"51 HTTP error: {e}\r\n".encode("utf-8"))
                return

            if response.status_code != 200:
                error_msg = f"51 HTTP error: {response.status_code}\r\n"
                logging.error("HTTP error code %s for URL %s", response.status_code, target_url)
                self.wfile.write(error_msg.encode("utf-8"))
                return

            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type:
                gemtext_content = html_to_gemtext(response.text)
            else:
                # Fallback: deliver text directly.
                gemtext_content = response.text

            # Save to cache
            cache[target_url] = (now, gemtext_content)

            # Return successful Gemini response
            header = "20 Converted GitHub content\r\n"
            self.wfile.write(header.encode("utf-8"))
            self.wfile.write(gemtext_content.encode("utf-8"))

        except Exception as e:
            logging.exception("Unhandled error:")
            self.wfile.write(f"40 Error: {e}\r\n".encode("utf-8"))

# ------------------------- TLS Gemini Server -------------------------
class TLSGeminiServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        try:
            sslsocket = context.wrap_socket(newsocket, server_side=True)
        except ssl.SSLError as e:
            logging.error("SSL error: %s", e)
            newsocket.close()
            raise
        return sslsocket, fromaddr

if __name__ == "__main__":
    # Set up TLS context.
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

    # Optionally, enforce stronger TLS settings.
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    with TLSGeminiServer(("", PORT), GeminiRequestHandler) as server:
        logging.info("Gemini GitHub proxy server running on port %d", PORT)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logging.info("Server shutting down.")
