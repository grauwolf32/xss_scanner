import os
import re
import sys
import json
import logging

from selenium.webdriver.chrome.options import Options

# Logging settings 
infologger = logging.getLogger('xss')
infologger.setLevel(logging.INFO)
infologger.addHandler(logging.FileHandler(filename="xss.log"))
infologger.addHandler(logging.StreamHandler())

# Chrome browser options
chrome_path = './chromedriver'
chrome_dir  = './chromedata'

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
    chrome_options.add_argument('--enable-logging')
    chrome_options.add_argument('--v=1')

    return chrome_options

# Generator
const_get_maxlen = 1000
const_post_maxlen = 5000
postproxy = "http://localhost:5000" # Special web-page for post requests

# Notification settings
smtp_server = "smtp.mail.ru:465"
main_page = "https://mail.ru"
credfile = "./creds"

# Request settings
requests_timeout = 0.5
driver_timeout = 5

#DOM XSS Marker
domxss_marker="marker1337"

#Screenshoots
img_path = "./screenshoots/"
if not os.path.exists(img_path):
    os.mkdir(img_path)