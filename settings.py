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

redis_conn = redis.StrictRedis(host='localhost', port=6379, db=1)

cookies = browsercookie.chrome()
driver_cookies = cookiejar_to_webdriver(cookies)
redis_conn.set('crawler/cookie', json.dumps(driver_cookies))