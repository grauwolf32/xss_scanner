import os
import re
import sys
import json
import redis
import logging

from selenium.webdriver.chrome.options import Options

# Logging settings 
infologger = logging.getLogger('xss')
infologger.setLevel(logging.INFO)
infologger.addHandler(logging.FileHandler(filename="xss.log"))
infologger.addHandler(logging.StreamHandler())

# Chrome browser options
chrome_path = '/Users/r.bomin/work/chromedriver'
chrome_dir  = '/Users/r.bomin/work/chromedata'

def get_options(headless=False, proxy=None, load_cookies=False, load_images=False):
    chrome_options = Options() 
    if headless:
        chrome_options.add_argument('--headless')
    
    if proxy: # 'socks5://127.0.0.1:1999'
        chrome_options.add_argument('--proxy-server={}'.format(proxy))

    if load_images:
        prefs = {"profile.managed_default_content_settings.images":2}
        chrome_options.add_experimental_option("prefs", prefs)

    if load_cookies:
        chrome_options.add_argument("user-data-dir={}".format(chrome_dir)) 

    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--disable-web-security')
    chrome_options.add_argument('--disable-xss-auditor')

    return chrome_options

# Redis options
redis_host = 'localhost'
redis_port = 6379
redis_db = 1

# Generator
const_get_maxlen = 1000
const_post_maxlen = 5000
postproxy = "http://localhost:5000" # Special web-page for post requests

# Notification settings
smtp_server = "smtp.mail.ru:465"
credfile = "./creds"

# Queues
task_queue = "xss/queue/"
processing_queue = "xss/processing/"
done_queue = "xss/done/"

payloads_queue = "xss/payloads/"
variables_queue = "xss/variables/"

# Packer values
const_use_crawler     = 1 << 2
const_use_extractor   = 1 << 3
const_use_post    = 1 << 5
const_use_get     = 1 << 6

requests_timeout = 2