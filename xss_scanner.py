import re
import sys
import time
import json
import smtplib
import selenium
import lxml.html as html

from urlparse import urlparse
from selenium import webdriver
from selenium.common.exceptions import *

from email.header import Header
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import settings
import argparse

from settings import logger

driver = webdriver.Chrome(settings.chrome_path, chrome_options=settings.chrome_options) 
redis_conn = settings.redis_conn

js_var_extractors = settings.js_var_extractors
js_keywords = settings.js_keywords
xss_payloads = settings.xss_payloads
content_ext = settings.content_ext

def extract_jsvar_fast(script):
    vlist = list()
    for regexp in js_var_extractors:
        for match in re.findall(regexp,script):
            for vname in match:
                vlist.append(vname)

    return set(vlist)

def reset_driver():
    global driver
    global redis_conn
    
    if driver:
        driver.quit()

    driver = webdriver.Chrome(settings.chrome_path , chrome_options=settings.chrome_options) 
    driver_cookies = redis_conn.get('crawler/cookie')

    if driver_cookies:
        try:
            driver.get("https://ya.ru") # Hack, couldnot set up cookie other way
            driver_cookies = json.loads(driver_cookies)
            for cookie in driver_cookies:
                driver.add_cookie(cookie)
        except:
            logger.info("Cookie was not loaded")

def send_report(user_email,password,mail_to,subject,data,server_name):
    server = smtplib.SMTP_SSL(server_name)
    server.login(user_email, password)
    mail_from = user_email
    msg = MIMEMultipart()

    msg["Subject"] = Header(subject,"utf-8")
    msg["From"] = mail_from
    msg["To"] = mail_to

    msg_text = MIMEText(data.encode("utf-8"), "plain", "utf-8")
    msg.attach(msg_text)
    
    logger.info("Sending mail to {}".format(mail_to))
    server.sendmail(mail_from , mail_to, msg.as_string())
    server.quit()

def notify(data, subject):
    email = settings.email
    password = settings.password 
    target_email = settings.target_email
    smtp_server = settings.smtp_server
    
    send_report(email,password,target_email,subject, data,smtp_server)

def check_url(redis_conn, url):
    if redis_conn.get("".join(("crawler/queue/", url))) != None:
        return False
    if redis_conn.get("".join(("crawler/processing/", url))) != None:
        return False
    if redis_conn.get("".join(("crawler/done/", url))) != None:
        return False
    return True

def update_payloads(redis_conn):
    xss_payloads = []
    for payload in redis_conn.scan_iter("crawler/payloads/*"):
        xss_payloads.append(redis_conn.get(payload))

    if len(xss_payloads) == 0:
        logger.info("Could not load payloads from redis, using default")
        xss_payloads = default_xss_payloads
    return xss_payloads

class InvalidUrlException(Exception):
    pass

def extract_links(parsed_url, doc, domains):
    page_links = []
    page_links += doc.xpath(".//*/@href")
    page_links += doc.xpath(".//*/@src")
    page_links += doc.xpath(".//*/@action")

    links = set()
    params = set()
    param_vars = list()

    for link in page_links:
        in_domains = False
        for domain in domains:
            if link.find(domain) != -1:
                in_domains = True
        if in_domains == False:
            continue

        tmp = link.split('?')
        if len(tmp) > 1:
            params.add(tmp[1])
            
        main_part = tmp[0]
        main_part = main_part.strip().split('#')[0]
    
        if main_part.split('.')[-1] not in content_ext:
            if main_part.startswith('http') == False:
                if main_part.startswith('//'):
                    main_part = "".join((parsed_url.scheme,'://', main_part[2:]))
                else:
                    if main_part.startswith('/'):
                        main_part = "".join((parsed_url.scheme,'://', parsed_url.netloc, main_part))

            links.add(main_part)

        for p in list(params):
            tmp = p.split('&')
            for i in tmp:
                param_vars.append(i.split('=')[0])

    return links, param_vars   
    

def process_url(url, task , worker_name):
    parsed_url = urlparse(url)

    task_params = dict()
    task_params["worker"] = str(worker_name)
    task_params["crawler"] = task["crawler"] # inherit crawler
    task_params["extract_js"] = task["extract_js"] # and js extractor parameters
    task_params["params"] = ""
    task_params = json.dumps(task_params)

    logger.info("Url: {} \nUse crawler: {}\nUse extractor: {}".format(url, task["crawler"], task["extract_js"]))

    try:
        driver.get(url)
        doc = html.fromstring(driver.page_source)

    except UnexpectedAlertPresentException:
        alert = driver.switch_to.alert
        alert.accept()
        doc = html.fromstring(driver.page_source)
        logger.info("Unexpected alert on url: {}".format(url))

    except:
        reset_driver()
        driver.get(url)
        doc = html.fromstring(driver.page_source)
        logger.info("236: Exception on url: {}".format(url))

    all_variables = set()

    if task["crawler"] == True:
        domains = set()
        for domain in redis_conn.scan_iter("crawler/domains/*"):
            domain = domain.replace("crawler/domains/","")
            domains.add(domain)

        links, param_vars = extract_links(parsed_url, doc, domains)
        all_variables.update(set(param_vars))
        for link in links:
            if check_url(redis_conn, link):
                redis_conn.set("".join(("crawler/queue/", link)), task_params)
    
    if task["extract_js"] == True: # extract varnames from js
        doc_scripts = doc.xpath(".//script/text()")
        for script in doc_scripts:
            all_variables.update(extract_jsvar_fast(script))

    for var in redis_conn.scan_iter("crawler/variables/*"): # load varnames from redis
        var = var.replace("crawler/variables/","")
        all_variables.add(var)

    xss_requests = []
    req = "".join((url,"?"))

    # xss_payloads = update_payloads(redis_conn)

    # Generate payloads
    for payload in xss_payloads:
        for var in all_variables:
            tmp = "".join((var,"=",payload,"&"))
            if len(req) + len(tmp) > settings.maxurllen:
                xss_requests.append(req[:-1])
                req = "".join((url,"?"))
                req += tmp
            else:
                req += tmp

    # Do requests
    for req in xss_requests:
        try:
            driver.get(req)
        except UnexpectedAlertPresentException:
            alert = driver.switch_to.alert
            data = "Alert {} was found on {}".format(alert.text,req)
            notify(data=data,subject="XSS was found!")
            logger.info(data)

            alert.accept()
            driver.get(req)
            
        except:
            logger.info("289: Exception on url: {}".format(req))
            logger.info(sys.exc_info()[0])
            reset_driver()
        
    try:
        alert = driver.switch_to.alert
        data = "Alert {} was found on {}".format(alert.text,req)
        notify(data=data,subject="XSS was found!")
        alert.accept()

    except NoAlertPresentException:
        pass

    except:
        logger.info("302: Exception on url: {}".format(req))
        logger.info(sys.exc_info()[0])
        reset_driver()
    
def main():
    parser = argparse.ArgumentParser(description='xss scanner worker')
    parser.add_argument('--name', type=str, default="Noname")
    args = parser.parse_args()

    worker_name = args.name

    while True:
        try:
            key = next(redis_conn.scan_iter("crawler/queue/*"))
        except StopIteration:
            time.sleep(5.0)
            continue
        
        task = json.loads(redis_conn.get(key))
        url = key.replace("crawler/queue/","")
        processing_key = "".join(("crawler/processing/", url))

        redis_conn.set(processing_key, str(worker_name))
        redis_conn.delete(key)

        try:
            process_url(url,task, worker_name)
            redis_conn.delete(processing_key)
            redis_conn.set("".join(("crawler/done/",url)), str(worker_name))

            for domain_key in redis_conn.scan_iter("crawler/domains/*"): # Count processed domains
                domain = domain_key.replace("crawler/domains/","")
                if url.find(domain) != -1:
                    redis_conn.incr(domain_key)
 
        except KeyboardInterrupt:
            if driver:
                driver.quit()
                redis_conn.delete(processing_key)
                redis_conn.set(key, json.dumps(task))
            return

        except: #TODO Add smarter exception handler
            logger.info("Error on url: {}".format(url))
            logger.info(sys.exc_info())
            redis_conn.delete(processing_key)
            redis_conn.incr("crawler/errors")
            #redis_conn.set(key, json.dumps(task))
            reset_driver()

if __name__ == "__main__":
    main()
