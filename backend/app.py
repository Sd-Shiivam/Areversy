from flask import Flask, send_from_directory, request, jsonify, send_file
from flask_cors import CORS
import os
import subprocess
import logging
import xml.etree.ElementTree as ET
import re
from werkzeug.utils import secure_filename

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('areversy.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
BUILD_DIR = '/app/frontend/build'
STATIC_DIR = os.path.join(BUILD_DIR, 'static')
UPLOAD_FOLDER = '/app/backend/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ZIPALIGN_FILE = "/app/backend/tools/androidtools/zipalign"
APKSIGNER_FILE = "/app/backend/tools/androidtools/apksigner"
KEYSTORE_FILE = "/app/backend/tools/arevrsy.jks"
ALLOWED_EXTENSIONS = {'apk', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


FULL_URL_PATTERNS = [
    (r'https?://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(/[^\s"\']*)?', 'Full URL'),
    (r'["\']https?://[^\"\']+["\']?', 'Quoted Full URL'),
]

RELATIVE_PATH_PATTERNS = [
    (r'["\'](/v[0-9]+/[^\"\']+)', 'Relative API Path'),
    (r'["\'](/api/[^\"\']+)', 'API Endpoint Path'),
    (r'["\'](/rest/[^\"\']+)', 'REST Endpoint Path'),
    (r'["\'](/service/[^\"\']+)', 'Service Endpoint Path'),
    (r'["\'](/webhook/[^\"\']+)', 'Webhook Endpoint Path'),
    (r'["\'](/graphql/[^\"\']*)', 'GraphQL Path'),
    (r'["\'](/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)', 'Relative Path Endpoint'),
    (r'["\'](/[a-zA-Z0-9_-]{2,})', 'Single Path Segment'),
]

REST_API_PATTERNS = [
    (r'["\']?(?:baseUrl|baseURL|base_url|API_URL|api_url|API_ENDPOINT|api_endpoint)["\']?\s*[:=]\s*["\']?(https?://[^\s"\']+)', 'REST Base URL'),
    (r'"(?:GET|POST|PUT|DELETE|PATCH)\s+(https?://[^\s"\']+)', 'REST Endpoint'),
    (r'https?://[^\s"\']+/api/[^\s"\']*', 'API Endpoint'),
    (r'https?://[^\s"\']+/v[0-9]+/[^\s"\']*', 'Versioned API'),
    (r'https?://[^\s"\']+(?:/api|/rest|/service|/webhook)[^\s"\']*', 'Service Endpoint'),
    (r'"endpoint"|\'endpoint\'|endpoint:\s*["\'][^"\']+["\']', 'Endpoint Declaration'),
    (r'(?:retrofit|okhttp|HttpUrl|HttpClient|URLConnection).*?(https?://[^\s"\']+)', 'HTTP Client URL'),
]

GRAPHQL_PATTERNS = [
    (r'https?://[^\s"\']+/graphql', 'GraphQL Endpoint'),
    (r'https?://[^\s"\']+/api/graphql', 'GraphQL API'),
    (r'["\']?graphql["\']?\s*[:=]\s*["\']?(https?://[^\s"\']+)', 'GraphQL URL Config'),
    (r'(?:apollo|graphql|RelayModern).*?(?:endpoint|uri|URL).*?["\'](https?://[^\s"\']+)', 'Apollo/GraphQL Client'),
    (r'"query"\s*:\s*"{[^}]*}"', 'Inline GraphQL Query'),
]

FIREBASE_PATTERNS = [
    (r'https?://[^\s"\']+\.firebase(io|database\.com)', 'Firebase URL'),
    (r'["\']?firebase_url["\']?\s*[:=]\s*["\']?([^\s"\']+)', 'Firebase Config'),
    (r'["\']?project_id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)', 'Firebase Project ID'),
    (r'["\']?api_key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})', 'Firebase API Key'),
    (r'["\']?databaseURL["\']?\s*[:=]\s*["\']?(https?://[^\s"\']+)', 'Firebase Database URL'),
    (r'["\']?storageBucket["\']?\s*[:=]\s*["\']?([^\s"\']+)', 'Firebase Storage'),
    (r'["\']?messagingSenderId["\']?\s*[:=]\s*["\']?([0-9]+)', 'Firebase Sender ID'),
    (r'["\']?appId["\']?\s*[:=]\s*["\']?([0-9:\-a-fA-F]+)', 'Firebase App ID'),
]

WEBSOCKET_PATTERNS = [
    (r'wss?://[^\s"\']+', 'WebSocket URL'),
    (r'socket\.io\s*[:=]\s*["\']?([^\s"\']+)', 'Socket.IO Endpoint'),
    (r'(?:WebSocket|SocketIO|Socket\.IO).*?(?:url|endpoint|URI).*?["\'](wss?://[^\s"\']+)', 'WebSocket Config'),
    (r'new\s+WebSocket\s*\(\s*["\'](wss?://[^\s"\']+)', 'WebSocket Initialization'),
    (r'(?:stomp|STOMP).*?(?:broker|endpoint).*?["\']([^\s"\']+)', 'STOMP Broker'),
]

CLOUD_STORAGE_PATTERNS = [
    (r'https?://[^\s"\']+\.s3\.amazonaws\.com[^\s"\']*', 'AWS S3 Bucket'),
    (r'https?://[^\s"\']+\.blob\.core\.windows\.net[^\s"\']*', 'Azure Blob Storage'),
    (r'https?://[^\s"\']+\.googleapis\.com/[^\s"\']*', 'Google Cloud Storage'),
    (r'https?://[^\s"\']+\.cloudfront\.net[^\s"\']*', 'CloudFront CDN'),
    (r'(?:aws_access_key|AWS_ACCESS_KEY|S3_BUCKET|S3_KEY).*?["\']?([^\s"\']+)', 'AWS Credentials'),
]

AUTH_PATTERNS = [
    (r'(?:Bearer|Token|Auth|Authorization).*?["\']([A-Za-z0-9_\-\.]+)', 'Auth Token'),
    (r'(?:api[_-]?key|API_KEY|apikey)[:=]\s*["\']?([A-Za-z0-9_-]{20,})', 'API Key'),
    (r'(?:oauth|OAuth|OAuth2|oauth2).*?(?:token|secret|key).*?["\']([^\s"\']+)', 'OAuth Credential'),
    (r'(?:jwt|JWT|JSON Web Token).*?["\']([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)', 'JWT Token'),
    (r'(?:session|SESSION|session_id|SESSION_ID)[:=]\s*["\']?([^\s"\']+)', 'Session ID'),
    (r'(?:refresh|REFRESH).*?token.*?["\']([^\s"\']+)', 'Refresh Token'),
    (r'(?:basic|Basic|BASIC).*?["\']([A-Za-z0-9+/=]{20,})', 'Basic Auth Header'),
    (r'(?:hmac|HMAC|Hmac).*?[:=]\s*["\']?([a-fA-F0-9]{20,})', 'HMAC Key'),
]

SOCIAL_API_PATTERNS = [
    (r'(?:graph\.facebook\.com|facebook\.com/api)[^\s"\']*', 'Facebook API'),
    (r'(?:api\.twitter\.com|twitter\.com)[^\s"\']*', 'Twitter API'),
    (r'(?:api\.instagram\.com|instagram\.com)[^\s"\']*', 'Instagram API'),
    (r'(?:api\.linkedin\.com|linkedin\.com)[^\s"\']*', 'LinkedIn API'),
    (r'(?:api\.github\.com|github\.com/api)[^\s"\']*', 'GitHub API'),
    (r'(?:googleapis\.com|accounts\.google\.com)[^\s"\']*', 'Google API'),
    (r'(?:api\.twilio\.com|twilio\.com)[^\s"\']*', 'Twilio API'),
    (r'(?:api\.stripe\.com|stripe\.com/api)[^\s"\']*', 'Stripe API'),
    (r'(?:sendgrid\.com|api\.sendgrid\.com)[^\s"\']*', 'SendGrid API'),
    (r'(?:mailgun\.org|api\.mailgun\.com)[^\s"\']*', 'Mailgun API'),
    (r'(?:nexmo\.com|api\.nexmo\.com)[^\s"\']*', 'Nexmo/Vonage API'),
    (r'(?:pusher\.com|api\.pusher\.com)[^\s"\']*', 'Pusher API'),
]


DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS': {'risk': 'HIGH', 'description': 'Can read all SMS messages'},
    'android.permission.SEND_SMS': {'risk': 'HIGH', 'description': 'Can send SMS (potential premium SMS fraud)'},
    'android.permission.READ_CONTACTS': {'risk': 'HIGH', 'description': 'Access to all contacts'},
    'android.permission.READ_CALL_LOG': {'risk': 'HIGH', 'description': 'Access to complete call history'},
    'android.permission.ACCESS_FINE_LOCATION': {'risk': 'HIGH', 'description': 'Precise GPS location access'},
    'android.permission.ACCESS_COARSE_LOCATION': {'risk': 'MEDIUM', 'description': 'Approximate location access'},
    'android.permission.RECORD_AUDIO': {'risk': 'HIGH', 'description': 'Can record audio'},
    'android.permission.CAMERA': {'risk': 'MEDIUM', 'description': 'Camera access'},
    'android.permission.READ_EXTERNAL_STORAGE': {'risk': 'MEDIUM', 'description': 'Read files from external storage'},
    'android.permission.WRITE_EXTERNAL_STORAGE': {'risk': 'HIGH', 'description': 'Write to external storage'},
    'android.permission.READ_PHONE_STATE': {'risk': 'HIGH', 'description': 'Access phone state and device identifiers'},
    'android.permission.PROCESS_OUTGOING_CALLS': {'risk': 'HIGH', 'description': 'Process outgoing calls (deprecated but dangerous)'},
    'android.permission.CALL_PHONE': {'risk': 'MEDIUM', 'description': 'Initiate phone calls without user confirmation'},
    'android.permission.GET_ACCOUNTS': {'risk': 'MEDIUM', 'description': 'Access to device accounts'},
    'android.permission.USE_FINGERPRINT': {'risk': 'LOW', 'description': 'Fingerprint authentication'},
    'android.permission.BODY_SENSORS': {'risk': 'HIGH', 'description': 'Access body sensors (heart rate, etc.)'},
    'android.permission.ACTIVITY_RECOGNITION': {'risk': 'MEDIUM', 'description': 'Activity recognition'},
    'android.permission.RECEIVE_BOOT_COMPLETED': {'risk': 'MEDIUM', 'description': 'Runs at device startup'},
    'android.permission.SYSTEM_ALERT_WINDOW': {'risk': 'HIGH', 'description': 'Display over other apps'},
    'android.permission.WRITE_SETTINGS': {'risk': 'MEDIUM', 'description': 'Modify system settings'},
    'android.permission.REQUEST_INSTALL_PACKAGES': {'risk': 'HIGH', 'description': 'Can request to install apps'},
    'android.permission.ACCESS_NOTIFICATION_POLICY': {'risk': 'MEDIUM', 'description': 'Access Do Not Disturb settings'},
}

INSECURE_CRYPTO_PATTERNS = {
    'MD5': {'risk': 'HIGH', 'description': 'MD5 is cryptographically broken and vulnerable to collisions'},
    'SHA1': {'risk': 'MEDIUM', 'description': 'SHA1 is considered weak for security purposes'},
    'DES': {'risk': 'HIGH', 'description': 'DES is cryptographically weak (56-bit key)'},
    'DESede': {'risk': 'MEDIUM', 'description': '3DES is slower and has security limitations'},
    'ECB': {'risk': 'MEDIUM', 'description': 'ECB mode reveals patterns in encrypted data'},
    'NoPadding': {'risk': 'MEDIUM', 'description': 'No padding can lead to padding oracle attacks'},
    'PKCS1Padding': {'risk': 'MEDIUM', 'description': 'Vulnerable to padding oracle attacks'},
    'RSA/ECB': {'risk': 'MEDIUM', 'description': 'RSA ECB mode is insecure'},
    'Random()': {'risk': 'MEDIUM', 'description': 'java.util.Random is not cryptographically secure'},
    'getInstance("MD5"': {'risk': 'HIGH', 'description': 'MD5 hash being created'},
    'getInstance("SHA-1"': {'risk': 'MEDIUM', 'description': 'SHA-1 hash being created'},
    'Key.getInstance("RSA")': {'risk': 'HIGH', 'description': 'RSA key without proper padding specification'},
    'Cipher.getInstance("AES")': {'risk': 'MEDIUM', 'description': 'AES without mode specification (defaults to ECB)'},
    'iv =': {'risk': 'LOW', 'description': 'Hardcoded initialization vector detected'},
    'IV_PARAMS': {'risk': 'MEDIUM', 'description': 'Hardcoded IV parameters'},
    'KeyStore.getInstance("BKS")': {'risk': 'MEDIUM', 'description': 'Using default keystore without password'},
    'TrustManager': {'risk': 'HIGH', 'description': 'Custom TrustManager that might skip validation'},
    'X509TrustManager': {'risk': 'HIGH', 'description': 'Custom TrustManager implementation'},
    'ALLOW_ALL_HOSTNAME_VERIFIER': {'risk': 'CRITICAL', 'description': 'Hostname verification disabled'},
    'setHostnameVerifier': {'risk': 'MEDIUM', 'description': 'Custom hostname verifier'},
}


HARDCODED_SECRET_PATTERNS = [
    (r'["\']?(?:api[_-]?key|apikey|API_KEY)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', 'API Key', 'CRITICAL'),
    (r'["\']?(?:secret[_-]?key|SECRET_KEY|secret_key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', 'Secret Key', 'CRITICAL'),
    (r'["\']?(?:password|pwd|pass|PASSWORD)["\']?\s*[:=]\s*["\']?([^\'"}\s]{8,})', 'Password', 'CRITICAL'),
    (r'["\']?(?:token|auth[_-]?token|auth_token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})', 'Auth Token', 'CRITICAL'),
    (r'(?:aws[_-]?)?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})', 'AWS Access Key ID', 'CRITICAL'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Secret Key Pattern', 'CRITICAL'),
    (r'(?:aws[_-]?)?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+]{40})', 'AWS Secret Access Key', 'CRITICAL'),
    (r'["\']?firebase[_-]?config["\']?\s*[:=]\s*["\']?([^\'"}\s]+)', 'Firebase Config', 'HIGH'),
    (r'["\']?GOOGLE_API_KEY["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})', 'Google API Key', 'HIGH'),
    (r'["\']?(?:private[_-]?key|PRIVATE_KEY)["\']?\s*[:=]\s*["\']?-----BEGIN[A-Z\s]+-----', 'Private Key', 'CRITICAL'),
    (r'(?:client[_-]?secret|client_secret|CLIENT_SECRET)["\']?\s*[:=]\s*["\']?([^\'"}\s]{16,})', 'OAuth Client Secret', 'CRITICAL'),
    (r'(?:encryption[_-]?key|ENCRYPTION_KEY|encryption_key)["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{16,})', 'Encryption Key', 'CRITICAL'),
    (r'(?:master[_-]?key|MASTER_KEY)["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{16,})', 'Master Key', 'CRITICAL'),
    (r'(?:hmac[_-]?key|HMAC_KEY|hmac_key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{20,})', 'HMAC Key', 'HIGH'),
    (r'(?:jwt[_-]?secret|JWT_SECRET)["\']?\s*[:=]\s*["\']?([^\'"}\s]{16,})', 'JWT Secret', 'CRITICAL'),
    (r'session[_-]?secret["\']?\s*[:=]\s*["\']?([^\'"}\s]{16,})', 'Session Secret', 'HIGH'),
    (r'(?:slack[_-]?token|SLACK_TOKEN)["\']?xox[baprs]-([0-9a-zA-Z]{10,})', 'Slack Token', 'HIGH'),
    (r'(?:twilio[_-]?auth[_-]?token|TWILIO_AUTH)["\']?([a-zA-Z0-9]{20,})', 'Twilio Auth Token', 'HIGH'),
    (r'(?:stripe[_-]?live[_-]?key|STRIPE_LIVE)["\']?(?:sk|pk)_(?:live|test)_[A-Za-z0-9]+', 'Stripe Key', 'HIGH'),
    (r'sendgrid[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{22}', 'SendGrid API Key', 'HIGH'),
    (r'mailgun[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?key-[A-Za-z0-9]{32}', 'Mailgun API Key', 'HIGH'),
    (r'mapbox[_-]?access[_-]?token["\']?\s*[:=]\s*["\']?pk\.[A-Za-z0-9]{30,}', 'Mapbox Access Token', 'HIGH'),
    (r'github[_-]?token["\']?\s*[:=]\s*["\']?(?:gh[goprs]_[A-Za-z0-9_]{36,})', 'GitHub Token', 'HIGH'),
    (r'telegram[_-]?bot[_-]?token["\']?\s*[:=]\s*["\']?[0-9]{8,10}:[A-Za-z0-9_-]{35}', 'Telegram Bot Token', 'HIGH'),
    (r'discord[_-]?token["\']?\s*[:=]\s*["\']?[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}', 'Discord Token', 'HIGH'),
    (r'shopify[_-]?access[_-]?token["\']?\s*[:=]\s*["\']?shpat_[a-fA-F0-9]{32}', 'Shopify Access Token', 'HIGH'),
    (r'paypal[_-]?client[_-]?id["\']?\s*[:=]\s*["\']?(?:sb|live)?[A-Za-z0-9_-]{20,}', 'PayPal Client ID', 'MEDIUM'),
    (r'paypal[_-]?client[_-]?secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}', 'PayPal Client Secret', 'CRITICAL'),
    (r'["\']?rsa[_-]?private[_-]?key["\']?\s*[:=]\s*["\']?-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key', 'CRITICAL'),
    (r'["\']?ecdsa[_-]?private[_-]?key["\']?\s*[:=]\s*["\']?-----BEGIN EC PRIVATE KEY-----', 'ECDSA Private Key', 'CRITICAL'),
    (r'(?:connection[_-]?string|CONNECTION_STRING|db[_-]?password)["\']?\s*[:=]\s*["\']?(?:postgres|mysql|oracle|sqlserver|mongodb)://[^\s"\']+', 'Database Connection String', 'CRITICAL'),
]


VULNERABLE_LIBRARIES = {
    'okhttp': {'versions': ['<4.0.0'], 'cve': 'CVE-2021-0341, CVE-2020-29582', 'risk': 'HIGH', 'description': 'HTTP client with various protocol vulnerabilities'},
    'okio': {'versions': ['<3.0.0'], 'cve': 'Potential heap overflow', 'risk': 'MEDIUM', 'description': 'I/O library with potential vulnerabilities'},
    'retrofit': {'versions': ['<2.9.0'], 'cve': 'CVE-2020-27840', 'risk': 'MEDIUM', 'description': 'REST client library'},
    'picasso': {'versions': ['<2.8'], 'cve': 'CVE-2020-28502', 'risk': 'MEDIUM', 'description': 'Image loading library'},
    'glide': {'versions': ['<4.12.0', '<4.13.0'], 'cve': 'CVE-2020-27840, CVE-2022-22977', 'risk': 'MEDIUM', 'description': 'Image loading library'},
    'gson': {'versions': ['<2.8.9'], 'cve': 'CVE-2022-25647', 'risk': 'HIGH', 'description': 'JSON parser with deserialization vulnerabilities'},
    'moshi': {'versions': ['<1.12.0'], 'cve': 'CVE-2022-25647', 'risk': 'HIGH', 'description': 'JSON library with deserialization issues'},
    'jackson-databind': {'versions': ['<2.13.0'], 'cve': 'Multiple CVEs', 'risk': 'HIGH', 'description': 'JSON processing library with deserialization flaws'},
    'jackson-core': {'versions': ['<2.13.0'], 'cve': 'Various', 'risk': 'MEDIUM', 'description': 'Jackson core library'},
    'apache httpclient': {'versions': ['<4.5.13'], 'cve': 'CVE-2020-13956', 'risk': 'MEDIUM', 'description': 'Deprecated HTTP client'},
    'commons-httpclient': {'versions': ['any'], 'cve': 'Deprecated', 'risk': 'HIGH', 'description': 'Completely deprecated HTTP client'},
    'log4j': {'versions': ['<2.17.0'], 'cve': 'CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, CVE-2021-44832', 'risk': 'CRITICAL', 'description': 'Log4j 2.x RCE vulnerabilities - IMMEDIATE ACTION REQUIRED'},
    'log4j-api': {'versions': ['<2.17.0'], 'cve': 'CVE-2021-44228', 'risk': 'CRITICAL', 'description': 'Log4j API component'},
    'log4j-core': {'versions': ['<2.17.0'], 'cve': 'CVE-2021-44228', 'risk': 'CRITICAL', 'description': 'Log4j core component'},
    'log4j-1.2': {'versions': ['any'], 'cve': 'CVE-2019-17571', 'risk': 'HIGH', 'description': 'Log4j 1.2 is completely deprecated'},
    'commons-logging': {'versions': ['<1.2'], 'cve': 'CVE-2018-1324', 'risk': 'MEDIUM', 'description': 'Jakarta Commons Logging'},
    'fastjson': {'versions': ['<1.2.83'], 'cve': 'CVE-2022-25845, CVE-2022-35914', 'risk': 'HIGH', 'description': 'FastJSON with deserialization vulnerabilities'},
    'xstream': {'versions': ['<1.4.20'], 'cve': 'Multiple CVEs', 'risk': 'HIGH', 'description': 'XML deserialization library'},
    'xmlbeans': {'versions': ['<2.3.0'], 'cve': 'CVE-2013-4002', 'risk': 'MEDIUM', 'description': 'XML processing library'},
    'xmlpull': {'versions': ['<1.1.3.1'], 'cve': 'Various', 'risk': 'MEDIUM', 'description': 'XML pull parser'},
    'dom4j': {'versions': ['<2.1.3'], 'cve': 'CVE-2018-1000192', 'risk': 'MEDIUM', 'description': 'XML processing library'},
    'groovy': {'versions': ['<3.0.9', '<2.5.14'], 'cve': 'Multiple CVEs', 'risk': 'MEDIUM', 'description': 'Scripting language with deserialization risks'},
    'snakeyaml': {'versions': ['<1.26'], 'cve': 'CVE-2022-1471', 'risk': 'MEDIUM', 'description': 'YAML parser with deserialization issues'},
    'jsoup': {'versions': ['<1.15.3'], 'cve': 'CVE-2022-36033', 'risk': 'MEDIUM', 'description': 'HTML parser with XSS vulnerabilities'},
    'spring-framework': {'versions': ['<5.3.18', '<5.2.20', '<4.3.30'], 'cve': 'CVE-2022-22965, CVE-2022-22950', 'risk': 'HIGH', 'description': 'Spring Framework RCE vulnerabilities'},
    'spring-core': {'versions': ['<5.3.18'], 'cve': 'CVE-2022-22965', 'risk': 'HIGH', 'description': 'Spring Core with RCE'},
    'spring-beans': {'versions': ['<5.3.18'], 'cve': 'CVE-2022-22965', 'risk': 'HIGH', 'description': 'Spring Beans'},
    'cglib': {'versions': ['<3.3.0'], 'cve': 'Deserialization risks', 'risk': 'MEDIUM', 'description': 'Byte code generation library'},
    'javassist': {'versions': ['<3.29.0'], 'cve': 'Various', 'risk': 'MEDIUM', 'description': 'Bytecode manipulation library'},
    'bcprov': {'versions': ['<1.70'], 'cve': 'CVE-2020-28928', 'risk': 'MEDIUM', 'description': 'Bouncy Castle crypto provider'},
    'bcpkix': {'versions': ['<1.70'], 'cve': 'CVE-2020-28928', 'risk': 'MEDIUM', 'description': 'Bouncy Castle PKI library'},
    'spongycastle': {'versions': ['<1.53.0'], 'cve': 'Various', 'risk': 'MEDIUM', 'description': 'Bouncy Castle for Android (deprecated)'},
    'leakcanary': {'versions': ['<2.7'], 'cve': 'Memory leak detection (disable in release)', 'risk': 'LOW', 'description': 'Debug-only library - remove in production'},
    'butterknife': {'versions': ['<10.2.3'], 'cve': 'Deprecated', 'risk': 'LOW', 'description': 'Deprecated view binding - migrate to View Binding'},
    'dagger': {'versions': ['<2.40.5'], 'cve': 'Various', 'risk': 'LOW', 'description': 'Dependency injection - ensure up to date'},
    'hilt': {'versions': ['<2.44'], 'cve': 'Various', 'risk': 'LOW', 'description': 'Hilt DI framework'},
}


WEBVIEW_VULNERABILITIES = [
    ('setJavaScriptEnabled', {'risk': 'HIGH', 'description': 'JavaScript enabled in WebView - allows XSS and JS injection attacks'}),
    ('setAllowFileAccess', {'risk': 'MEDIUM', 'description': 'File access enabled in WebView - can expose local files'}),
    ('setAllowUniversalAccessFromFileURLs', {'risk': 'CRITICAL', 'description': 'Universal file URL access from file:// URLs - allows cross-origin attacks'}),
    ('setAllowFileAccessFromFileURLs', {'risk': 'HIGH', 'description': 'File URL access from file:// URLs - restricted but still dangerous'}),
    ('addJavascriptInterface', {'risk': 'HIGH', 'description': 'JavaScript interface added - allows Java code execution from JS'}),
    ('setWebContentsDebuggingEnabled', {'risk': 'MEDIUM', 'description': 'Web debugging enabled in production'}),
    ('setMixedContentMode', {'risk': 'MEDIUM', 'description': 'Mixed content handling - allows HTTP content in HTTPS pages'}),
    ('setDOMStorageEnabled', {'risk': 'MEDIUM', 'description': 'DOM storage enabled - sensitive data in localStorage'}),
    ('setCacheMode', {'risk': 'LOW', 'description': 'Cache mode setting - ensure no sensitive data cached'}),
    ('savePassword', {'risk': 'HIGH', 'description': 'Password saving in WebView - insecure storage'}),
    ('saveFormData', {'risk': 'MEDIUM', 'description': 'Form data saving in WebView'}),
    ('setLoadWithOverviewMode', {'risk': 'LOW', 'description': 'Overview mode loading'}),
    ('useWideViewPort', {'risk': 'LOW', 'description': 'Wide viewport enabled'}),
    ('loadDataWithBaseURL', {'risk': 'MEDIUM', 'description': 'Loading data with base URL'}),
    ('WebViewClient', {'risk': 'LOW', 'description': 'Custom WebViewClient implemented'}),
    ('shouldOverrideUrlLoading', {'risk': 'MEDIUM', 'description': 'URL loading override'}),
    ('setGeolocationEnabled', {'risk': 'HIGH', 'description': 'Geolocation enabled in WebView'}),
    ('evaluateJavascript', {'risk': 'HIGH', 'description': 'JavaScript evaluation'}),
]


INTENT_VULNERABILITIES = [
    ('startActivity', {'risk': 'HIGH', 'description': 'Activity started without verification'}),
    ('startService', {'risk': 'HIGH', 'description': 'Service started without verification'}),
    ('sendBroadcast', {'risk': 'HIGH', 'description': 'Broadcast sent without protection'}),
    ('sendOrderedBroadcast', {'risk': 'MEDIUM', 'description': 'Ordered broadcast sent'}),
    ('registerReceiver', {'risk': 'HIGH', 'description': 'Receiver registered dynamically'}),
    ('PendingIntent', {'risk': 'HIGH', 'description': 'PendingIntent created'}),
    ('getParcelableExtra', {'risk': 'MEDIUM', 'description': 'Parcelable extra retrieved'}),
    ('setComponent', {'risk': 'MEDIUM', 'description': 'Intent component set'}),
    ('setPackage', {'risk': 'LOW', 'description': 'Intent package set'}),
    ('Intent.ACTION_VIEW', {'risk': 'MEDIUM', 'description': 'View action intent'}),
    ('Intent.ACTION_SEND', {'risk': 'LOW', 'description': 'Send action intent'}),
    ('FLAG_GRANT_READ_URI_PERMISSION', {'risk': 'MEDIUM', 'description': 'URI permission granted'}),
    ('FLAG_GRANT_WRITE_URI_PERMISSION', {'risk': 'HIGH', 'description': 'Write URI permission granted'}),
    ('FLAG_INCLUDE_STOPPED_PACKAGES', {'risk': 'MEDIUM', 'description': 'Stopped packages included'}),
    ('FLAG_DEBUG_LOG_RESOLUTION', {'risk': 'MEDIUM', 'description': 'Debug logging enabled'}),
    ('setDataAndType', {'risk': 'MEDIUM', 'description': 'Intent data and type set'}),
    ('createChooser', {'risk': 'LOW', 'description': 'Chooser created'}),
]

DATA_STORAGE_PATTERNS = [
    ('getSharedPreferences', {'risk': 'MEDIUM', 'description': 'SharedPreferences usage'}),
    ('MODE_WORLD_READABLE', {'risk': 'CRITICAL', 'description': 'World readable file mode - DEPRECATED and insecure'}),
    ('MODE_WORLD_WRITABLE', {'risk': 'CRITICAL', 'description': 'World writable file mode - DEPRECATED and insecure'}),
    ('openFileOutput', {'risk': 'MEDIUM', 'description': 'File output opened'}),
    ('openFileInput', {'risk': 'MEDIUM', 'description': 'File input opened'}),
    ('getExternalStorageDirectory', {'risk': 'HIGH', 'description': 'External storage access'}),
    ('getExternalFilesDir', {'risk': 'MEDIUM', 'description': 'External app files directory'}),
    ('getExternalCacheDir', {'risk': 'MEDIUM', 'description': 'External cache directory'}),
    ('SQLiteDatabase', {'risk': 'MEDIUM', 'description': 'SQLite database usage'}),
    ('rawQuery', {'risk': 'HIGH', 'description': 'Raw SQL query'}),
    ('execSQL', {'risk': 'HIGH', 'description': 'SQL execution'}),
    ('ContentValues', {'risk': 'LOW', 'description': 'ContentValues usage'}),
    ('CursorLoader', {'risk': 'LOW', 'description': 'Cursor loader usage'}),
    ('Realm', {'risk': 'MEDIUM', 'description': 'Realm database usage'}),
    ('Room', {'risk': 'LOW', 'description': 'Room database usage'}),
    ('DataStore', {'risk': 'LOW', 'description': 'DataStore usage'}),
    ('EncryptedSharedPreferences', {'risk': 'LOW', 'description': 'Encrypted shared preferences'}),
    ('Keystore', {'risk': 'LOW', 'description': 'Android Keystore usage'}),
    ('SecureRandom', {'risk': 'LOW', 'description': 'SecureRandom usage'}),
    ('KeyGenerator', {'risk': 'MEDIUM', 'description': 'Key generator usage'}),
    ('Cipher', {'risk': 'MEDIUM', 'description': 'Cipher usage'}),
    ('TrustAllX509TrustManager', {'risk': 'CRITICAL', 'description': 'Trusts all certificates - EXTREMELY DANGEROUS'}),
    ('AllHostsNameVerifier', {'risk': 'CRITICAL', 'description': 'Verifies all hostnames - MITM vulnerable'}),
]


DYNAMIC_CODE_PATTERNS = [
    ('DexClassLoader', {'risk': 'HIGH', 'description': 'Dynamic class loading from external source'}),
    ('PathClassLoader', {'risk': 'MEDIUM', 'description': 'Path class loading'}),
    ('InMemoryDexClassLoader', {'risk': 'HIGH', 'description': 'In-memory dex loading'}),
    ('loadClass', {'risk': 'MEDIUM', 'description': 'Class loading'}),
    ('defineClass', {'risk': 'HIGH', 'description': 'Dynamic class definition'}),
    ('eval', {'risk': 'HIGH', 'description': 'Code evaluation using eval'}),
    ('System.load', {'risk': 'HIGH', 'description': 'Native library loading'}),
    ('System.loadLibrary', {'risk': 'MEDIUM', 'description': 'Native library loading'}),
    ('Runtime.exec', {'risk': 'HIGH', 'description': 'Command execution'}),
    ('ProcessBuilder', {'risk': 'HIGH', 'description': 'Process building'}),
    ('exec', {'risk': 'HIGH', 'description': 'Shell command execution'}),
]

REFLECTION_PATTERNS = [
    ('getDeclaredField', {'risk': 'HIGH', 'description': 'Access to private fields via reflection'}),
    ('getDeclaredMethod', {'risk': 'HIGH', 'description': 'Access to private methods via reflection'}),
    ('setAccessible', {'risk': 'HIGH', 'description': 'Making fields/methods accessible'}),
    ('invoke', {'risk': 'HIGH', 'description': 'Method invocation via reflection'}),
    ('Class.forName', {'risk': 'HIGH', 'description': 'Dynamic class loading'}),
    ('Method.invoke', {'risk': 'HIGH', 'description': 'Method invocation'}),
    ('Field.get', {'risk': 'MEDIUM', 'description': 'Field access via reflection'}),
    ('Field.set', {'risk': 'HIGH', 'description': 'Field modification via reflection'}),
]

ROOT_DETECTION_PATTERNS = [
    ('/system/bin/su', {'risk': 'LOW', 'description': 'Checking for root binary'}),
    ('/system/xbin/su', {'risk': 'LOW', 'description': 'Checking for root binary'}),
    ('/sbin/su', {'risk': 'LOW', 'description': 'Checking for root binary'}),
    ('isRooted', {'risk': 'LOW', 'description': 'Root detection method'}),
    ('isDeviceRooted', {'risk': 'LOW', 'description': 'Rooted device check'}),
    ('RootBeer', {'risk': 'LOW', 'description': 'RootBeer library usage'}),
    ('checkRoot', {'risk': 'LOW', 'description': 'Root check method'}),
    ('Build.TAGS', {'risk': 'LOW', 'description': 'Checking build tags for test-keys'}),
    ('test-keys', {'risk': 'LOW', 'description': 'Test-keys detection'}),
    ('emulator', {'risk': 'LOW', 'description': 'Emulator detection'}),
    ('Build.MODEL', {'risk': 'LOW', 'description': 'Checking for emulator models'}),
    ('Build.MANUFACTURER', {'risk': 'LOW', 'description': 'Checking manufacturer'}),
    ('android.os.Build.HARDWARE', {'risk': 'LOW', 'description': 'Hardware check'}),
    ('genymotion', {'risk': 'LOW', 'description': 'Genymotion detection'}),
    ('BlueStacks', {'risk': 'LOW', 'description': 'BlueStacks detection'}),
    ('nox', {'risk': 'LOW', 'description': 'Nox emulator detection'}),
]


TAMPERING_PATTERNS = [
    ('android:debuggable="true"', {'risk': 'CRITICAL', 'description': 'Debuggable flag set to true in manifest'}),
    ('debuggable', {'risk': 'HIGH', 'description': 'Debuggable flag check in code'}),
    ('Application.isDebuggerConnected', {'risk': 'LOW', 'description': 'Debugger detection'}),
    ('Debug.isDebuggerConnected', {'risk': 'LOW', 'description': 'Debugger connected check'}),
    ('Debug.waitForDebugger', {'risk': 'MEDIUM', 'description': 'Debugger waiting'}),
    ('StrictMode', {'risk': 'LOW', 'description': 'StrictMode enabled'}),
    ('setAppWidgetId', {'risk': 'LOW', 'description': 'Widget ID manipulation'}),
    ('FLAG_SECURE', {'risk': 'LOW', 'description': 'Secure flag for screenshots prevention'}),
    ('setMediaPlaybackID', {'risk': 'LOW', 'description': 'Media playback ID'}),
]


CRYPTO_WEAKNESS_PATTERNS = [
    ('KeyPairGenerator', {'risk': 'HIGH', 'description': 'Key pair generation'}),
    ('KeyGenerator', {'risk': 'MEDIUM', 'description': 'Key generation'}),
    ('Mac.getInstance', {'risk': 'MEDIUM', 'description': 'MAC computation'}),
    ('SecretKeySpec', {'risk': 'HIGH', 'description': 'Secret key specification'}),
    ('PBEKeySpec', {'risk': 'MEDIUM', 'description': 'Password-based key derivation'}),
    ('IvParameterSpec', {'risk': 'MEDIUM', 'description': 'IV specification'}),
    ('AlgorithmParameters', {'risk': 'MEDIUM', 'description': 'Algorithm parameters'}),
    ('CertificateFactory', {'risk': 'MEDIUM', 'description': 'Certificate handling'}),
    ('X509Certificate', {'risk': 'MEDIUM', 'description': 'X.509 certificate usage'}),
    ('TrustManagerFactory', {'risk': 'MEDIUM', 'description': 'Trust manager factory'}),
    ('SSLContext', {'risk': 'MEDIUM', 'description': 'SSL context initialization'}),
    ('HostnameVerifier', {'risk': 'HIGH', 'description': 'Hostname verification'}),
]


PRIVACY_PATTERNS = [
    ('android_id', {'risk': 'MEDIUM', 'description': 'Android ID usage'}),
    ('getDeviceId', {'risk': 'HIGH', 'description': 'IMEI/Device ID access'}),
    ('getSubscriberId', {'risk': 'HIGH', 'description': 'SIM subscriber ID access'}),
    ('getLine1Number', {'risk': 'HIGH', 'description': 'Phone number access'}),
    ('getSimSerialNumber', {'risk': 'HIGH', 'description': 'SIM serial number access'}),
    ('getMacAddress', {'risk': 'MEDIUM', 'description': 'MAC address access'}),
    ('getSimOperator', {'risk': 'LOW', 'description': 'SIM operator info'}),
    ('getNetworkOperator', {'risk': 'LOW', 'description': 'Network operator info'}),
    ('TelephonyManager', {'risk': 'HIGH', 'description': 'Telephony manager usage'}),
    ('ClipboardManager', {'risk': 'MEDIUM', 'description': 'Clipboard access'}),
    ('AccessibilityService', {'risk': 'HIGH', 'description': 'Accessibility service usage'}),
    ('UsageStatsManager', {'risk': 'HIGH', 'description': 'Usage stats access'}),
    ('DevicePolicyManager', {'risk': 'MEDIUM', 'description': 'Device policy management'}),
    ('FingerprintManager', {'risk': 'LOW', 'description': 'Fingerprint authentication'}),
    ('BiometricPrompt', {'risk': 'LOW', 'description': 'Biometric authentication'}),
]

DEEPLINK_PATTERNS = [
    ('android:scheme', {'risk': 'MEDIUM', 'description': 'Custom URL scheme defined'}),
    ('android:host', {'risk': 'LOW', 'description': 'Deep link host defined'}),
    ('android:path', {'risk': 'LOW', 'description': 'Deep link path defined'}),
    ('android:pathPrefix', {'risk': 'LOW', 'description': 'Path prefix defined'}),
    ('android:pathPattern', {'risk': 'MEDIUM', 'description': 'Path pattern defined'}),
    ('android:exported="true"', {'risk': 'HIGH', 'description': 'Activity/receiver exported'}),
    ('intent-filter', {'risk': 'MEDIUM', 'description': 'Intent filter defined'}),
    ('data android:scheme', {'risk': 'MEDIUM', 'description': 'Data scheme defined'}),
    ('category android:android.intent.category.BROWSABLE', {'risk': 'MEDIUM', 'description': 'BROWSABLE category - can be opened from browser'}),
    ('category android:android.intent.category.DEFAULT', {'risk': 'LOW', 'description': 'DEFAULT category'}),
]

IPC_PATTERNS = [
    ('ContentResolver', {'risk': 'MEDIUM', 'description': 'Content resolver usage'}),
    ('ContentProvider', {'risk': 'MEDIUM', 'description': 'Content provider defined'}),
    ('exported="true"', {'risk': 'HIGH', 'description': 'Component exported'}),
    ('android:permission', {'risk': 'LOW', 'description': 'Permission defined for component'}),
    ('android:readPermission', {'risk': 'LOW', 'description': 'Read permission defined'}),
    ('android:writePermission', {'risk': 'LOW', 'description': 'Write permission defined'}),
    ('android:grantUriPermissions', {'risk': 'MEDIUM', 'description': 'URI permissions granted'}),
    ('android:pathPermission', {'risk': 'MEDIUM', 'description': 'Path-based permission defined'}),
    ('Messenger', {'risk': 'LOW', 'description': 'Messenger IPC usage'}),
    ('AIDL', {'risk': 'MEDIUM', 'description': 'AIDL interface defined'}),
    ('Binder', {'risk': 'MEDIUM', 'description': 'Binder IPC usage'}),
    ('ServiceConnection', {'risk': 'MEDIUM', 'description': 'Service connection defined'}),
]

EXPORTED_COMPONENT_PATTERNS = [
    ('<activity', {'risk': 'MEDIUM', 'description': 'Activity component defined'}),
    ('<service', {'risk': 'MEDIUM', 'description': 'Service component defined'}),
    ('<receiver', {'risk': 'MEDIUM', 'description': 'Broadcast receiver defined'}),
    ('<provider', {'risk': 'MEDIUM', 'description': 'Content provider defined'}),
    ('android:exported', {'risk': 'MEDIUM', 'description': 'Export status defined'}),
    ('android:enabled', {'risk': 'LOW', 'description': 'Component enabled status'}),
    ('android:permission', {'risk': 'LOW', 'description': 'Permission required for component'}),
    ('android:protectionLevel', {'risk': 'LOW', 'description': 'Protection level defined'}),
    ('android:multiprocess', {'risk': 'MEDIUM', 'description': 'Multi-process enabled'}),
    ('android:launchMode', {'risk': 'MEDIUM', 'description': 'Launch mode defined'}),
]


NETWORK_PATTERNS = [
    ('usesCleartextTraffic', {'risk': 'MEDIUM', 'description': 'Cleartext HTTP traffic allowed'}),
    ('trustUserCertificates', {'risk': 'HIGH', 'description': 'User certificates trusted'}),
    ('debug-overrides', {'risk': 'MEDIUM', 'description': 'Debug certificate overrides'}),
    ('base-config', {'risk': 'LOW', 'description': 'Base network security config'}),
    ('domain-config', {'risk': 'LOW', 'description': 'Domain-specific config'}),
    ('certificatePins', {'risk': 'LOW', 'description': 'Certificate pinning defined'}),
    ('cleartextTrafficPermitted', {'risk': 'HIGH', 'description': 'Cleartext traffic permitted'}),
    ('trust-anchors', {'risk': 'LOW', 'description': 'Trust anchors defined'}),
]


BACKUP_PATTERNS = [
    ('android:allowBackup="true"', {'risk': 'MEDIUM', 'description': 'Backup allowed - data can be extracted'}),
    ('android:allowBackup="false"', {'risk': 'LOW', 'description': 'Backup disabled'}),
    ('android:fullBackupContent', {'risk': 'MEDIUM', 'description': 'Full backup content defined'}),
    ('android:dataExtractionRules', {'risk': 'MEDIUM', 'description': 'Data extraction rules defined'}),
    ('android:backupAgent', {'risk': 'LOW', 'description': 'Custom backup agent defined'}),
    ('android:restoreAnyVersion', {'risk': 'LOW', 'description': 'Restore any version allowed'}),
    ('android:killAfterRestore', {'risk': 'LOW', 'description': 'Kill after restore'}),
]

MISC_PATTERNS = [
    ('Toast', {'risk': 'LOW', 'description': 'Toast notification usage'}),
    ('Log.', {'risk': 'MEDIUM', 'description': 'Logging statement found'}),
    ('System.out.print', {'risk': 'MEDIUM', 'description': 'System output statement'}),
    ('printStackTrace', {'risk': 'MEDIUM', 'description': 'Stack trace printing'}),
    ('AsyncTask', {'risk': 'LOW', 'description': 'AsyncTask usage (deprecated)'}),
    ('Handler', {'risk': 'LOW', 'description': 'Handler usage'}),
    ('Thread', {'risk': 'LOW', 'description': 'Thread creation'}),
    ('Executor', {'risk': 'LOW', 'description': 'Executor usage'}),
    ('BroadcastReceiver', {'risk': 'LOW', 'description': 'Broadcast receiver usage'}),
    ('Broadcast', {'risk': 'MEDIUM', 'description': 'Broadcast sent'}),
    ('Activity', {'risk': 'LOW', 'description': 'Activity implementation'}),
    ('Fragment', {'risk': 'LOW', 'description': 'Fragment usage'}),
    ('WebView', {'risk': 'HIGH', 'description': 'WebView usage'}),
]


SQL_INJECTION_PATTERNS = [
    (r'SELECT\s+.*\+.*FROM', 'SQL concatenation in SELECT statement'),
    (r'INSERT\s+INTO\s+.*\+', 'SQL concatenation in INSERT statement'),
    (r'UPDATE\s+.*SET\s+.*\+', 'SQL concatenation in UPDATE statement'),
    (r'DELETE\s+FROM\s+.*\+', 'SQL concatenation in DELETE statement'),
    (r'WHERE\s+.*\+.*=', 'SQL concatenation in WHERE clause'),
    (r'execSQL\s*\(\s*[^?].*\+', 'execSQL with string concatenation'),
    (r'rawQuery\s*\(\s*[^?].*\+', 'rawQuery with string concatenation'),
    (r'query\s*\(\s*.*\+', 'Database query with string concatenation'),
]

LOGGING_PATTERNS = [
    (r'Log\.d\s*\(.*password', 'Debug log containing password'),
    (r'Log\.d\s*\(.*token', 'Debug log containing token'),
    (r'Log\.d\s*\(.*key', 'Debug log containing key'),
    (r'Log\.d\s*\(.*secret', 'Debug log containing secret'),
    (r'Log\.e\s*\(.*Exception', 'Error log with exception details'),
    (r'System\.out\.print.*password', 'System output containing password'),
    (r'System\.out\.print.*token', 'System output containing token'),
    (r'printStackTrace\(\)', 'Stack trace printing to stdout'),
]


def extract_apis_from_content(content):
    """Extract all API endpoints and URLs from content - Enhanced for all URL types"""
    apis = []
    seen = set()
    
    all_patterns = (
        FULL_URL_PATTERNS +
        RELATIVE_PATH_PATTERNS +
        REST_API_PATTERNS +
        GRAPHQL_PATTERNS +
        FIREBASE_PATTERNS +
        WEBSOCKET_PATTERNS +
        CLOUD_STORAGE_PATTERNS +
        AUTH_PATTERNS +
        SOCIAL_API_PATTERNS
    )
    
    for pattern, api_type in all_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0] if match else None
            if match and len(match) < 500:
                # Clean up the URL
                match = match.strip('\'"')
                if match not in seen:
                    seen.add(match)
                    # Determine risk level
                    if match.startswith('/'):
                        # Relative path - likely internal API
                        risk = 'MEDIUM'
                    elif match.startswith('https'):
                        risk = 'LOW'
                    else:
                        risk = 'HIGH'
                    
                    if any(x in match.lower() for x in ['token', 'auth', 'secret', 'key', 'password', 'credential']):
                        risk = 'CRITICAL'
                    
                    apis.append({
                        'endpoint': match,
                        'type': api_type,
                        'risk': risk,
                        'description': f'{api_type} endpoint found'
                    })
    
    return apis

def extract_endpoints_from_manifest(manifest_path):
    """Extract deep link endpoints from manifest"""
    endpoints = []
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        
        for activity in root.findall('.//activity'):
            name = activity.get('{http://schemas.android.com/apk/res/android}name', 
                              activity.get('name', 'Unknown'))
            exported = activity.get('{http://schemas.android.com/apk/res/android}exported', 'false')
            
            # Check for deep link schemes
            for intent_filter in activity.findall('.//intent-filter'):
                schemes = []
                for data in intent_filter.findall('.//data'):
                    scheme = data.get('{http://schemas.android.com/apk/res/android}scheme')
                    host = data.get('{http://schemas.android.com/apk/res/android}host')
                    path = data.get('{http://schemas.android.com/apk/res/android}path')
                    
                    if scheme:
                        scheme_str = f"{scheme}://"
                        if host:
                            scheme_str += host
                            if path:
                                scheme_str += path
                        schemes.append(scheme_str)
                
                if schemes:
                    endpoints.append({
                        'activity': name,
                        'schemes': schemes,
                        'exported': exported == 'true',
                        'risk': 'HIGH' if exported == 'true' else 'MEDIUM'
                    })
    
    except Exception as e:
        logger.debug(f"Error parsing manifest for endpoints: {e}")
    
    return endpoints


def scan_file_for_patterns(file_path, patterns, findings_list):
    """Scan a file for specific patterns"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for pattern, description, risk in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match else 'Match found'
                    if match and len(match) > 3:
                        findings_list.append({
                            'type': description,
                            'match': str(match)[:100],
                            'risk': risk
                        })
    except Exception as e:
        logger.debug(f"Error scanning file {file_path}: {e}")

def scan_smali_for_vulnerabilities(smali_dir):
    """Perform comprehensive security scan of smali code"""
    findings = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'apis': [],
        'endpoints': [],
        'vulnerable_libraries': [],
        'webview_issues': [],
        'intent_vulnerabilities': [],
        'crypto_issues': [],
        'hardcoded_secrets': [],
        'data_storage_issues': [],
        'dynamic_code_issues': [],
        'reflection_issues': [],
        'root_detection': [],
        'tampering_detection': [],
        'privacy_violations': [],
        'deeplink_issues': [],
        'ipc_issues': [],
        'exported_components': [],
        'network_issues': [],
        'backup_issues': [],
        'misc_issues': [],
        'sql_injection': [],
        'logging_issues': [],
    }
    
    total_files = 0
    total_lines = 0
    
    try:
        if not os.path.exists(smali_dir):
            logger.warning(f"Smali directory not found: {smali_dir}")
            return findings
        
        for root, dirs, files in os.walk(smali_dir):
            for file in files:
                if file.endswith('.smali'):
                    total_files += 1
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            total_lines += len(content.split('\n'))
                            
                            # Extract APIs and endpoints - NOW ENHANCED WITH RELATIVE PATH SUPPORT
                            apis = extract_apis_from_content(content)
                            findings['apis'].extend(apis[:5])  # Limit to 5 per file
                            
                            # Scan for all vulnerability patterns
                            scan_file_for_patterns(file_path, HARDCODED_SECRET_PATTERNS, findings['hardcoded_secrets'])
                            
                            # Check for dangerous permissions
                            for perm, info in DANGEROUS_PERMISSIONS.items():
                                if perm in content:
                                    findings[info['risk'].lower()].append({
                                        'permission': perm,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for insecure crypto
                            for pattern, info in INSECURE_CRYPTO_PATTERNS.items():
                                if pattern in content.upper():
                                    findings['crypto_issues'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for WebView vulnerabilities
                            for pattern, info in WEBVIEW_VULNERABILITIES:
                                if pattern in content:
                                    findings['webview_issues'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Intent vulnerabilities
                            for pattern, info in INTENT_VULNERABILITIES:
                                if pattern in content:
                                    findings['intent_vulnerabilities'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Data Storage issues
                            for pattern, info in DATA_STORAGE_PATTERNS:
                                if pattern in content:
                                    findings['data_storage_issues'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Dynamic Code Loading
                            for pattern, info in DYNAMIC_CODE_PATTERNS:
                                if pattern in content:
                                    findings['dynamic_code_issues'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Reflection issues
                            for pattern, info in REFLECTION_PATTERNS:
                                if pattern in content:
                                    findings['reflection_issues'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Root Detection
                            for pattern, info in ROOT_DETECTION_PATTERNS:
                                if pattern in content:
                                    findings['root_detection'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Tampering Detection
                            for pattern, info in TAMPERING_PATTERNS:
                                if pattern in content:
                                    findings['tampering_detection'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Privacy Violations
                            for pattern, info in PRIVACY_PATTERNS:
                                if pattern in content:
                                    findings['privacy_violations'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Deep Link issues
                            for pattern, info in DEEPLINK_PATTERNS:
                                if pattern in content:
                                    findings['deeplink_issues'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for IPC issues
                            for pattern, info in IPC_PATTERNS:
                                if pattern in content:
                                    findings['ipc_issues'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Network issues
                            for pattern, info in NETWORK_PATTERNS:
                                if pattern in content:
                                    findings['network_issues'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for Backup issues
                            for pattern, info in BACKUP_PATTERNS:
                                if pattern in content:
                                    findings['backup_issues'].append({
                                        'pattern': pattern,
                                        'description': info['description'],
                                        'risk': info['risk']
                                    })
                            
                            # Check for SQL injection
                            for pattern, description in SQL_INJECTION_PATTERNS:
                                if re.search(pattern, content, re.IGNORECASE):
                                    findings['sql_injection'].append({
                                        'pattern': description,
                                        'risk': 'HIGH'
                                    })
                            
                            # Check for logging issues
                            for pattern, description in LOGGING_PATTERNS:
                                if re.search(pattern, content, re.IGNORECASE):
                                    findings['logging_issues'].append({
                                        'pattern': description,
                                        'risk': 'MEDIUM'
                                    })
                            
                            # Check for vulnerable libraries
                            content_lower = content.lower()
                            for lib, info in VULNERABLE_LIBRARIES.items():
                                if lib in content_lower:
                                    findings['vulnerable_libraries'].append({
                                        'library': lib,
                                        'cve': info['cve'],
                                        'risk': info['risk'],
                                        'description': info['description']
                                    })
                    
                    except Exception as e:
                        logger.debug(f"Error scanning smali file {file_path}: {e}")
    
    except Exception as e:
        logger.error(f"Error in security scan: {e}")
    
    # Deduplicate findings
    for key in findings:
        if isinstance(findings[key], list):
            seen = set()
            unique = []
            for item in findings[key]:
                if isinstance(item, dict):
                    key_str = str(sorted(item.items()))
                else:
                    key_str = str(item)
                if key_str not in seen:
                    seen.add(key_str)
                    unique.append(item)
            findings[key] = unique
    
    # Add total counts
    findings['total_files_scanned'] = total_files
    findings['total_lines_scanned'] = total_lines
    
    return findings

def analyze_manifest_security(manifest_path):
    findings = {
        'exported_components': [],
        'debuggable': [],
        'allow_backup': [],
        'uses_cleartext': [],
        'network_security': [],
        'permissions': [],
        'deep_links': [],
        'backup_rules': [],
        'extraction_rules': [],
    }
    
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        
        # Check for exported components
        for elem_type, tag_name in [('activity', 'Activity'), ('receiver', 'BroadcastReceiver'), 
                                     ('service', 'Service'), ('provider', 'ContentProvider')]:
            for elem in root.findall(f'.//{elem_type}'):
                name = elem.get('{http://schemas.android.com/apk/res/android}name', elem.get('name', 'Unknown'))
                exported = elem.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                
                if exported == 'true':
                    findings['exported_components'].append({
                        'component': tag_name,
                        'name': name,
                        'risk': 'HIGH',
                        'description': f'{tag_name} is exported and may be accessible by other apps'
                    })
                
                # Check for intent filters (deep links)
                if elem.find('.//intent-filter') is not None:
                    for data in elem.findall('.//data'):
                        scheme = data.get('{http://schemas.android.com/apk/res/android}scheme')
                        host = data.get('{http://schemas.android.com/apk/res/android}host')
                        if scheme:
                            findings['deep_links'].append({
                                'component': name,
                                'scheme': scheme,
                                'host': host or '*',
                                'risk': 'MEDIUM',
                                'description': f'Deep link scheme: {scheme}://{host or "*"}'
                            })
        
        # Check for debuggable
        app_elem = root.find('.//application')
        if app_elem is not None:
            debuggable = app_elem.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')
            if debuggable == 'true':
                findings['debuggable'].append({
                    'risk': 'CRITICAL',
                    'description': 'Application is debuggable - enables runtime analysis and tampering'
                })
            
            allow_backup = app_elem.get('{http://schemas.android.com/apk/res/android}allowBackup', 'true')
            if allow_backup == 'true':
                findings['allow_backup'].append({
                    'risk': 'MEDIUM',
                    'description': 'Application backup is enabled - data can be extracted via ADB'
                })
            
            uses_cleartext = app_elem.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic', 'false')
            if uses_cleartext == 'true':
                findings['uses_cleartext'].append({
                    'risk': 'MEDIUM',
                    'description': 'Cleartext (HTTP) traffic is allowed - vulnerable to MITM attacks'
                })
            
            # Check permissions
            for perm in root.findall('.//uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
                if perm_name in DANGEROUS_PERMISSIONS:
                    info = DANGEROUS_PERMISSIONS[perm_name]
                    findings['permissions'].append({
                        'permission': perm_name,
                        'risk': info['risk'],
                        'description': info['description']
                    })
    
    except Exception as e:
        logger.error(f"Error analyzing manifest: {e}")
    
    return findings


@app.route('/')
def serve_react():
    logger.debug(f"Serving index.html from {BUILD_DIR}")
    return send_from_directory(BUILD_DIR, 'index.html')

@app.route('/static/js/<path:path>')
def serve_js(path):
    logger.debug(f"Serving JS file: /static/js/{path}")
    return send_from_directory(os.path.join(STATIC_DIR, 'js'), path)

@app.route('/static/css/<path:path>')
def serve_css(path):
    logger.debug(f"Serving CSS file: /static/css/{path}")
    return send_from_directory(os.path.join(STATIC_DIR, 'css'), path)

@app.route('/static/media/<path:path>')
def serve_media(path):
    logger.debug(f"Serving media file: /static/media/{path}")
    return send_from_directory(os.path.join(STATIC_DIR, 'media'), path)

@app.route('/<path:path>')
def serve_root_files(path):
    logger.debug(f"Serving root file: /{path}")
    return send_from_directory(BUILD_DIR, path)

@app.route('/uploads/<path:path>')
def serve_uploads(path):
    full_path = os.path.join(UPLOAD_FOLDER, path.lstrip('/'))
    logger.debug(f"Serving uploaded file: /uploads/{path}, resolved to {full_path}")
    if not os.path.exists(full_path):
        logger.error(f"Upload file not found: {full_path}")
        return "File not found", 404
    return send_from_directory(UPLOAD_FOLDER, path.lstrip('/'))

@app.route('/upload', methods=['POST'])
def upload_apk():
    if 'apk' not in request.files:
        logger.error('No APK file provided in request')
        return jsonify({'error': 'No APK file provided'}), 400
    
    apk_file = request.files['apk']
    if not allowed_file(apk_file.filename):
        logger.error(f"Invalid file type for {apk_file.filename}")
        return jsonify({'error': 'Invalid file type'}), 400
    
    apk_filename = secure_filename(apk_file.filename)
    apk_path = os.path.join(UPLOAD_FOLDER, apk_filename)
    logger.info(f"Saving uploaded APK to {apk_path}")
    apk_file.save(apk_path)
    
    decompiled_dir = os.path.join(UPLOAD_FOLDER, 'decompiled_' + apk_filename.rsplit('.', 1)[0])
    logger.info(f"Decompiling APK to {decompiled_dir}")
    try:
        subprocess.run(['java', '-jar', 'tools/apktool.jar', 'd', apk_path, '-o', decompiled_dir, '-f'], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to decompile APK: {e}")
        return jsonify({'error': 'Decompilation failed'}), 500
    
    icons = []
    assets = []
    res_dir = os.path.join(decompiled_dir, 'res')
    logger.debug(f"Scanning {res_dir} for icons and assets")
    for root, _, files in os.walk(res_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if 'mipmap' in root or 'drawable' in root:
                if file.endswith(('.png', '.jpg', '.jpeg')) and 'icon' in file.lower():
                    icons.append(file_path.replace(UPLOAD_FOLDER, ''))
                elif file.endswith(('.png', '.jpg', '.jpeg')):
                    assets.append(file_path.replace(UPLOAD_FOLDER, ''))
    
    manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    logger.debug(f"Parsing manifest at {manifest_path}")
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        permissions = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] 
                       for elem in root.findall('.//uses-permission')]
        listeners = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] 
                     for elem in root.findall('.//receiver') + root.findall('.//service')]
        activities = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] 
                       for elem in root.findall('.//activity')]
    except ET.ParseError as e:
        logger.error(f"Failed to parse manifest: {e}")
        return jsonify({'error': 'Manifest parsing failed'}), 500
    
    logger.debug(f"Completed Parsing manifest at {manifest_path}")

    background_workers = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] 
                         for elem in root.findall('.//service')]
    

    smali_dir = os.path.join(decompiled_dir, 'smali')
    lines_of_code = 0
    total_classes = 0

    try:
        if os.path.exists(smali_dir):
            for root, dirs, files in os.walk(smali_dir):
                for file in files:
                    if file.endswith('.smali'):
                        with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                            lines_of_code += sum(1 for line in f if line.strip())
                        total_classes += 1

    except Exception as e:
        print(f"Error processing smali files: {e}")
        return None

    stats = {
        'lines_of_code': lines_of_code,
        'total_permissions': len(permissions),
        'total_listeners': len(listeners),
        'total_activities': len(activities),
        'background_workers': len(background_workers),
        'total_classes': total_classes,
        'total_icons': len(icons),
        'total_assets': len(assets)
    }
    
    logger.info(f"APK decompiled successfully. Stats: {stats}")
    return jsonify({
        'message': 'APK decompiled',
        'decompiled_dir': decompiled_dir,
        'icons': icons,
        'assets': assets,
        'permissions': permissions,
        'listeners': listeners,
        'stats': stats
    })

@app.route('/security-scan', methods=['POST'])
def security_scan():
    data = request.json
    decompiled_dir = data.get('decompiled_dir')
    
    if not decompiled_dir or not os.path.exists(decompiled_dir):
        return jsonify({'error': 'Decompiled directory not found'}), 400
    
    logger.info(f"Starting comprehensive security scan for {decompiled_dir}")
    
    results = {
        'scan_summary': {
            'total_files_scanned': 0,
            'total_lines_scanned': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'total_apis_found': 0,
            'total_vulnerabilities': 0,
        },
        'smali_findings': {},
        'manifest_findings': {},
        'all_apis': [],
        'security_score': 0,
        'risk_assessment': {},
    }
    
    # Scan smali code
    smali_dir = os.path.join(decompiled_dir, 'smali')
    smali_results = scan_smali_for_vulnerabilities(smali_dir)
    results['smali_findings'] = smali_results
    
    # Count findings by risk level
    for finding_type, items in smali_results.items():
        if isinstance(items, list):
            for item in items:
                risk = item.get('risk', 'LOW')
                if risk == 'CRITICAL':
                    results['scan_summary']['critical_count'] += 1
                elif risk == 'HIGH':
                    results['scan_summary']['high_count'] += 1
                elif risk == 'MEDIUM':
                    results['scan_summary']['medium_count'] += 1
                else:
                    results['scan_summary']['low_count'] += 1
    
    results['scan_summary']['total_files_scanned'] = smali_results.get('total_files_scanned', 0)
    results['scan_summary']['total_lines_scanned'] = smali_results.get('total_lines_scanned', 0)
    results['scan_summary']['total_apis_found'] = len(smali_results.get('apis', []))
    results['scan_summary']['total_vulnerabilities'] = (
        results['scan_summary']['critical_count'] +
        results['scan_summary']['high_count'] +
        results['scan_summary']['medium_count'] +
        results['scan_summary']['low_count']
    )
    
    # Collect APIs - NOW INCLUDES RELATIVE PATHS LIKE /mpb/hgyg
    results['all_apis'] = smali_results.get('apis', [])[:50]
    
    # Analyze manifest
    manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    manifest_results = analyze_manifest_security(manifest_path)
    results['manifest_findings'] = manifest_results
    
    # Add manifest findings to counts
    for finding_type, items in manifest_results.items():
        if isinstance(items, list):
            for item in items:
                risk = item.get('risk', 'LOW')
                if risk == 'CRITICAL':
                    results['scan_summary']['critical_count'] += 1
                elif risk == 'HIGH':
                    results['scan_summary']['high_count'] += 1
                elif risk == 'MEDIUM':
                    results['scan_summary']['medium_count'] += 1
                else:
                    results['scan_summary']['low_count'] += 1
    
    # Calculate security score (0-100, higher is better)
    total_findings = results['scan_summary']['total_vulnerabilities']
    if total_findings == 0:
        results['security_score'] = 100
    else:
        # Penalize based on severity
        penalty = (
            results['scan_summary']['critical_count'] * 25 +
            results['scan_summary']['high_count'] * 10 +
            results['scan_summary']['medium_count'] * 5 +
            results['scan_summary']['low_count'] * 1
        )
        results['security_score'] = max(0, 100 - min(penalty, 100))
    
    # Risk assessment
    if results['scan_summary']['critical_count'] > 0:
        results['risk_assessment'] = {
            'level': 'CRITICAL',
            'summary': 'Critical vulnerabilities detected - immediate action required',
            'action': 'Do not use this app in production until critical issues are fixed'
        }
    elif results['scan_summary']['high_count'] > 5:
        results['risk_assessment'] = {
            'level': 'HIGH',
            'summary': 'Multiple high-risk vulnerabilities detected',
            'action': 'Address all high-risk issues before production deployment'
        }
    elif results['scan_summary']['high_count'] > 0:
        results['risk_assessment'] = {
            'level': 'MEDIUM',
            'summary': 'Some high-risk vulnerabilities detected',
            'action': 'Review and address high-risk issues'
        }
    elif results['scan_summary']['medium_count'] > 10:
        results['risk_assessment'] = {
            'level': 'MEDIUM',
            'summary': 'Multiple medium-risk issues detected',
            'action': 'Consider addressing these for improved security posture'
        }
    else:
        results['risk_assessment'] = {
            'level': 'LOW',
            'summary': 'Few security issues detected',
            'action': 'Continue with security best practices'
        }
    
    
    logger.info(f"Security scan completed. Score: {results['security_score']}, Findings: {results['scan_summary']}")
    return jsonify(results)

@app.route('/replace_logo', methods=['POST'])
def replace_logo():
    if 'logo' not in request.files or 'decompiled_dir' not in request.form or 'old_logo' not in request.form:
        logger.error('Missing logo, decompiled_dir, or old_logo in request')
        return jsonify({'error': 'Missing logo, decompiled_dir, or old_logo'}), 400
    
    logo_file = request.files['logo']
    decompiled_dir = request.form['decompiled_dir']
    old_logo_path = os.path.join(UPLOAD_FOLDER, request.form['old_logo'].lstrip('/'))
    
    if not allowed_file(logo_file.filename):
        logger.error(f"Invalid logo file type: {logo_file.filename}")
        return jsonify({'error': 'Invalid file type'}), 400
    if not os.path.exists(old_logo_path):
        logger.error(f"Old logo path does not exist: {old_logo_path}")
        return jsonify({'error': 'Old logo not found'}), 400
    
    logger.info(f"Replacing logo at {old_logo_path}")
    logo_file.save(old_logo_path)
    return jsonify({'message': 'Logo replaced successfully'})

@app.route('/replace_asset', methods=['POST'])
def replace_asset():
    if 'asset' not in request.files or 'decompiled_dir' not in request.form or 'old_asset' not in request.form:
        logger.error('Missing asset, decompiled_dir, or old_asset in request')
        return jsonify({'error': 'Missing asset, decompiled_dir, or old_asset'}), 400
    
    asset_file = request.files['asset']
    decompiled_dir = request.form['decompiled_dir']
    old_asset_path = os.path.join(UPLOAD_FOLDER, request.form['old_asset'].lstrip('/'))
    
    if not allowed_file(asset_file.filename):
        logger.error(f"Invalid asset file type: {asset_file.filename}")
        return jsonify({'error': 'Invalid file type'}), 400
    if not os.path.exists(old_asset_path):
        logger.error(f"Old asset path does not exist: {old_asset_path}")
        return jsonify({'error': 'Old asset not found'}), 400
    
    logger.info(f"Replacing asset at {old_asset_path}")
    asset_file.save(old_asset_path)
    return jsonify({'message': 'Asset replaced successfully'})

@app.route('/modify_manifest', methods=['POST'])
def modify_manifest():
    data = request.json
    decompiled_dir = data['decompiled_dir']
    manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    
    if not os.path.exists(manifest_path):
        logger.error(f"Manifest file not found at {manifest_path}")
        return jsonify({'error': 'Manifest file not found'}), 404
    
    logger.debug(f"Modifying manifest at {manifest_path}")
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}

        current_perms = {elem.attrib[f'{{{ns["android"]}}}name'] for elem in root.findall('.//uses-permission')}
        new_perms = set(data.get('permissions', []))
        logger.debug(f"Current permissions: {current_perms}, New permissions: {new_perms}")
        
        for elem in root.findall('.//uses-permission'):
            perm_name = elem.attrib[f'{{{ns["android"]}}}name']
            if perm_name not in new_perms:
                root.remove(elem)
                logger.info(f"Removed permission: {perm_name}")
        
        for perm in new_perms - current_perms:
            ET.SubElement(root, 'uses-permission', {f'{{{ns["android"]}}}name': perm})
            logger.info(f"Added permission: {perm}")

        for tag in ('receiver', 'service'):
            current_listeners = {elem.attrib[f'{{{ns["android"]}}}name'] for elem in root.findall(f'.//{tag}')}
            new_listeners = set(data.get('listeners', []))
            logger.debug(f"Current {tag}s: {current_listeners}, New {tag}s: {new_listeners}")
            
            for elem in root.findall(f'.//{tag}'):
                name = elem.attrib[f'{{{ns["android"]}}}name']
                if name not in new_listeners:
                    root.remove(elem)
                    logger.info(f"Removed {tag}: {name}")
            for listener in new_listeners - current_listeners:
                ET.SubElement(root, tag, {f'{{{ns["android"]}}}name': listener})
                logger.info(f"Added {tag}: {listener}")

        tree.write(manifest_path, xml_declaration=True, encoding='utf-8')
        logger.info('Manifest updated successfully')
    except Exception as e:
        logger.error(f"Failed to modify manifest: {e}")
        return jsonify({'error': 'Manifest modification failed'}), 500
    
    return jsonify({'message': 'Manifest updated'})

@app.route('/rebuild', methods=['POST'])
def rebuild_apk():
    data = request.json
    decompiled_dir = data['decompiled_dir']
    rebuilt_apk = os.path.join(UPLOAD_FOLDER, 'rebuilt.apk')
    aligned_apk = os.path.join(UPLOAD_FOLDER, 'aligned.apk')
    signed_apk = os.path.join(UPLOAD_FOLDER, 'signed_rebuild.apk')
    
    logger.info(f"Rebuilding APK from {decompiled_dir}")
    
    try:
        subprocess.run(['java', '-jar', 'tools/apktool.jar', 'b', decompiled_dir, '-o', rebuilt_apk], check=True)
        logger.info(f"APK rebuilt to {rebuilt_apk}")

        subprocess.run([ZIPALIGN_FILE, '-v', '4', rebuilt_apk, aligned_apk], check=True)
        logger.info(f"APK zipaligned to {aligned_apk}")

        # Step 3: Sign the APK
        subprocess.run([
            APKSIGNER_FILE, 'sign', 
            '--ks', KEYSTORE_FILE, 
            '--ks-pass', 'pass:areversy',
            '--key-pass', 'pass:areversy', 
            '--out', signed_apk, 
            aligned_apk
        ], check=True)
        logger.info(f"APK signed successfully: {signed_apk}")
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to rebuild, zipalign, or sign APK: {e}")
        return jsonify({'error': 'Rebuild, zipalign, or signing failed'}), 500
    
    return send_file(signed_apk, as_attachment=True, download_name='modified_signed.apk')


if __name__ == '__main__':
    logger.info('Starting AReversy Flask application')
    app.run(host='0.0.0.0', port=5000, debug=True)
