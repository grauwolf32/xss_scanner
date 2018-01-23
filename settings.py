import browsercookie
import logging
import redis
import json
import re

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
password = ""
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
    try:
        cookies = browsercookie.chrome()
        driver_cookies = cookiejar_to_webdriver(cookies)
        redis_conn.set('crawler/cookie', json.dumps(driver_cookies))
        logger.info("Load Chromium cookies")
    except:
        logger.info("Could not load Chromium cookies")


default_xss_payloads = ['''<img src=x id/=' onerror=alert(1)//'>''',
                '''<svg onload=alert(1)>''',
                '''<img src=x onerror=alert(1)>''',
                '''<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>''',
                '''data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==''',
                '''PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==''',
                '''javascript:alert(1)''',
                '''<script>alert(1)</script>''',
                '''<script>alert(1)<\/script>''',
                '''"`><img src=xx onerror=alert(1)//">''',
                '''"><img src=xx onerror=alert(1)//">''',
                '''alert(1);''']

xss_payloads = []
for payload in redis_conn.scan_iter("crawler/payloads/*"):
    xss_payloads.append(redis_conn.get(payload))

if len(xss_payloads) == 0:
    logger.info("Could not load payloads from redis, using default")
    xss_payloads = default_xss_payloads


js_var_extractors = [
                     re.compile(r"([a-zA-Z_]\w*)\[([a-zA-Z_]\w*)*\w*\]"), # array regexp
                     re.compile(r"var\s+([a-zA-Z_]\w*)"),                 # var name regexp   
                     re.compile(r"([a-zA-Z_]\w*)\.([a-zA-Z_]\w*)\.*"),    # class hierarchy
                     re.compile(r"([a-zA-Z_]\w*)\s*=\s*\w"),              # name = value
                     re.compile(r"\w+\s*=\s*([a-zA-Z_]\w*)"),             # smth = name 
                     re.compile(r'''[\"\']([a-zA-Z_]\w*)[\"\']:[\"\']\w*[\"\']''') # "name":"value"
                    ]

js_keywords = set([
                        'abstract','arguments','boolean','break','byte',
                        'case','catch','char','class*','const',
                        'continue','debugger','default','delete','do',
                        'double','else','enum*','eval','export*',
                        'extends*','false','final','finally','float',
                        'for','function','goto','if','implements',
                        'import','in','instanceof','int','interface',
                        'let','long','native','new','null',
                        'package','private','protected','public','return',
                        'short','static','super*','switch','synchronized',
                        'this','throw','throws','transient','true',
                        'try','typeof','var','void','volatile',
                        'while','with','yield'
                    ])

js_datatypes = set(["Array", "Date" ,"function",
                    "hasOwnProperty", "Infinity","isFinite", "isNaN",
                    "isPrototypeOf","Math","NaN",
                    "Number","Object","prototype"
                    "String","toString","undefined","valueOf"])

js_keywords.update(js_datatypes)

reserved_keywords = set(["alert", "all", "anchor", "anchors",
                         "area", "assign", "blur", "button",
                         "checkbox", "clearInterval", "clearTimeout", "clientInformation",
                         "close", "closed", "confirm","constructor",
                         "crypto", "decodeURI", "decodeURIComponent", "defaultStatus",
                         "document","element","elements", "embed",
                         "embeds","encodeURI","encodeURIComponent","escape",
                         "event","fileUpload","focus","form",
                         "forms","frame","innerHeight","innerWidth",
                         "layer","layers","link","location",
                         "mimeTypes","navigate","navigator","frames",
                         "frameRate","hidden", "history", "image",
                         "images","offscreenBuffering","open","opener",
                         "option","outerHeight","outerWidth","packages",
                         "pageXOffset","pageYOffset","parent","parseFloat",
                         "parseInt","password","pkcs11","plugin",
                         "prompt","propertyIsEnum", "radio","reset",
                         "screenX","screenY","scroll","secure",
                         "select","self","setInterval","setTimeout",
                         "status","submit","taint","text",
                         "textarea","top","unescape","untaint","window"])

reserved_small = set(["alert","innerHTML","self","setTimeout","window","clearTimeout"])
js_keywords.update(reserved_small)

content_ext = set(["jpeg", "xml", "jpg", "png" , "gif" , "bmp" , "svg", "ico" , "js" , "css", "exe", "tar", "gz"])
# payload_alerts = set("1")