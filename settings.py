import browsercookie
import logging
import redis
import json

from selenium.webdriver.chrome.options import Options

def cookiejar_to_webdriver(cookies):
    cookie_list = list()
    for cookie in cookies:
        driver_cookie = dict()
        for attr_name in ("domain", "secure", "value", "path", "name"):
            driver_cookie[attr_name] = getattr(cookie, attr_name)

        driver_cookie["expiry"] = cookie.expires
        
        if cookie.get_nonstandard_attr("HttpOnly"):
            driver_cookie["httpOnly"] = True
        else:
            driver_cookie["httpOnly"] = False
        cookie_list.append(driver_cookie)
        
    return cookie_list

logger = logging.getLogger('xss logger')
logger.setLevel(logging.INFO)
logger.addHandler(logging.FileHandler(filename="scanner.log"))

email = "pentester8928236@mail.ru"
password = "qwerty12345"
target_email = "pentester8928236@mail.ru"
smtp_server = "smtp.mail.ru:465"

maxurllen = 2000
chrome_path = '/usr/local/bin/chromedriver'

prefs = {"profile.managed_default_content_settings.images":2}

chrome_options = Options()  
#chrome_options.add_argument('--headless')  
chrome_options.add_argument('--ignore-certificate-errors')
chrome_options.add_argument('--disable-web-security')
chrome_options.add_argument('--disable-xss-auditor')
chrome_options.add_experimental_option("prefs",prefs)

redis_conn = redis.StrictRedis(host='localhost', port=6379, db=1)

if redis_conn.get('crawler/cookie') == None:
    cookies = browsercookie.chrome()
    driver_cookies = cookiejar_to_webdriver(cookies)
    redis_conn.set('crawler/cookie', json.dumps(driver_cookies))
