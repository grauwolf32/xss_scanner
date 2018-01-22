import logging

logger = logging.getLogger('xss logger')
logger.setLevel(logging.INFO)
logger.addHandler(logging.FileHandler(filename="scanner_log.log"))

email = "email"
password = "password"
target_email = "target_email"
smtp_server = "smtp_server"

maxurllen = 2000
chrome_path = '/usr/local/bin/chromedriver'

prefs = {"profile.managed_default_content_settings.images":2}

chrome_options = Options()  
chrome_options.add_argument("--headless")  
chrome_options.add_argument('--ignore-certificate-errors')
chrome_options.add_argument('--disable-web-security')
chrome_options.add_argument('--disable-xss-auditor')
chrome_options.add_experimental_option("prefs",prefs)