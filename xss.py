#!/usr/bin/env python3

import os
import sys
import time
import urllib3
import argparse
import settings
import requests
import subprocess

from extractjs import *
from selenium import webdriver
from selenium.common.exceptions import *
from selenium.webdriver.remote.command import Command
from settings import infologger

import lxml.html as html

requests.packages.urllib3.disable_warnings()

def load_driver():
    global driver
    global chrome_options

    driver = webdriver.Chrome(settings.chrome_path, chrome_options=chrome_options)
    driver.set_page_load_timeout(settings.driver_timeout)
    driver.get(settings.main_page)

def reload_driver():
    global driver
    if driver:
        driver.quit()
    load_driver()

def process_exception(func):
    global driver
    def wrapper(*args, **kwargs):
        try:
           func(*args, **kwargs)

        except WebDriverException as e:
            infologger.info(str(e))
            reload_driver()

        except KeyboardInterrupt:
            if driver:
                driver.quit()
            sys.exit(1)

        except Exception as e:
            infologger.info(str(e))

        except:
            infologger.info("Unknown exception!\n")
    
    return wrapper

def check_xss(func):
    global driver
    
    def call(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except UnexpectedAlertPresentException:
            alert = driver.switch_to.alert
            report = dict()
            report["alert"] = alert.text
            report["args"] = args
            report["kwargs"] = kwargs
            message = json.dumps(report)

            infologger.info(message)
            alert.accept()

    return call

@process_exception
@check_xss
def do_post_request(url, data, timeout=2):
    global driver
    driver.get(settings.postproxy)

    eq = data.find('=')
    if eq != -1:
        varname, varvalue = data[:eq], data[eq+1:]
    else:
        varname, varvalue = data, ""

    varname = varname.replace('"', '\\"')
    varvalue = varvalue.replace('"', '\\"')
    post_js = '''var f = document.createElement("form");
                f.setAttribute('method',"post");
                f.setAttribute('action',"{}");
                f.setAttribute('enctype','text/plain');

                var i = document.createElement("input");
                i.setAttribute('type',"hidden");
                i.setAttribute('name', "{}");
                i.setAttribute('value', "{}");

                var s = document.createElement("input"); 
                s.setAttribute('type',"submit");
                s.setAttribute('value',"Submit");
                s.setAttribute('id',"deadbeef");

                f.appendChild(i);
                f.appendChild(s);
                document.getElementsByTagName('body')[0].appendChild(f);
            '''.format(url, varname, varvalue)

    driver.execute_script(post_js)
    button = driver.find_element_by_id("deadbeef")
    button.click()
    time.sleep(timeout)

@process_exception
@check_xss
def do_get_request(url, data, timeout=2):
    global driver
    target_url = "{}?{}".format(url, data)
    driver.get(target_url)
    time.sleep(timeout)


@process_exception
@check_xss
def check_postmessage(url, message, timeout=2):
    global driver
    driver.get(url)
    postmessage_js = '''window.postMessage("{}","*");'''.format(message)
    driver.execute_script(postmessage_js)
    time.sleep(timeout)

@process_exception
@check_xss
def check_domxss(url, payload, timeout=2):
    global driver
    base_url = url
    sharp = url.find("#")
    payload = payload.strip(" ")
    
    if sharp != -1:
        base_url = url[:sharp]
    
    target_url = "#".join((base_url, payload))
    print("domxss {} with sharp".format(target_url))
    driver.get(target_url)
    time.sleep(timeout)

    quemark = base_url.find("?")
    if quemark != -1:
        base_url = base_url[:quemark]
    
    if base_url[-1] != "/":
        base_url += "/"

    target_url = "".join((base_url, payload))
    print("domxss {} with quemark".format(target_url))

    driver.get(target_url)
    time.sleep(timeout)

@process_exception
@check_xss
def validate(url, timeout=2, save_images=True):
    driver.get(url)
    time.sleep(timeout)

    if save_images:
        filtered_url = url.replace("/", "|")[:25]
        fimage_name  = ".".join((filtered_url, "png"))
        driver.get_screenshot_as_file(settings.img_path + fimage_name)

def main(urls, payloads, variables, args):
    global driver
    global chrome_options
    
    load_driver()
    variables = set(variables)

    for url in urls:
        if args.extractjs:
            print("extractjs {}".format(url))
            js_scripts = get_scripts(url)
            for js in js_scripts:
                variables.update(extractjs_fast(js))

        if args.get or args.all:
            request_payloads = gen_payloads(list(payloads), list(variables), settings.const_get_maxlen)
            for payload in request_payloads:
                do_get_request(url, payload,timeout=settings.requests_timeout)

        if args.post or args.all:
            request_payloads = gen_payloads(list(payloads), list(variables), settings.const_post_maxlen)
            for payload in request_payloads:
                do_post_request(url, payload, timeout=settings.requests_timeout)

        if args.pm or args.all:
            print("pm {}".format(url))
            check_postmessage(url, settings.domxss_marker, timeout=settings.requests_timeout)

        if args.domxss or args.all:
            for payload in payloads:
                print("domxss {} {}".format(url, payload))
                check_domxss(url, payload, timeout=settings.requests_timeout)

        if args.validate:
            print("validate {}".format(url))
            validate(url, timeout=settings.requests_timeout, save_images=args.save_images)

def gen_payloads(payloads, variables, maxlength):
    get_requests = []
    m = len(payloads)
    n = len(variables)

    req_len = 0
    last_vid = 0
    request = []

    for pid in range(0, m):
        for vid in range(0, n):
            payload = payloads[pid]
            variable = variables[vid]

            tmp = "".join((variable,"=",payload))
            request.append(tmp)
            req_len += len(tmp)

            if req_len > maxlength or last_vid == vid:
                get_requests.append("&".join(request))
                last_vid = vid
                request = []
                req_len = 0

    return get_requests

def get_scripts(url, timeout=3):
    parsed_url = urllib3.util.url.parse_url(url)
    r = requests.get(url, verify=False, timeout=timeout)
    doc = html.fromstring(r.text)
    scripts = list()

    for script in doc.xpath(".//script"):
        if "src" in script.attrib:
            script_src = script.attrib["src"]
            if script_src.startswith("//"):
                script_src = "".join((parsed_url.scheme, ":", script_src))
            elif script_src.startswith("/"):
                script_src = "".join((url, script_src))

            try:
                t = requests.get(script_src, verify=False, timeout=timeout)
                script_data = r.text
            except:
                continue

            scripts.append(script_data)

        scripts += script.xpath(".//text()")
    return scripts

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--visible', help='show chome browser', action='store_true')
    parser.add_argument('--proxy', help='specify proxy', type=str, default=None)
    parser.add_argument('--cookies', help='load cookies from previous sessions', action='store_true')
    parser.add_argument('--load_images', help='load images from sites', action='store_true')

    parser.add_argument('--get', help='Do get requests', action='store_true')
    parser.add_argument('--post', help='Do post requests', action='store_true')
    parser.add_argument('--pm', help='Do check postMessage', action='store_true')
    parser.add_argument('--domxss', help='Do checks for DOM XSS', action='store_true')
    parser.add_argument('--all', help='Do  all checks', action='store_true')
    parser.add_argument('--validate', help='Validate supported urls for reflectd xss', action='store_true')
    parser.add_argument('--save_images', help='Save images to the file', action='store_true')
    
    parser.add_argument('--payloads', type=str, default=None)
    parser.add_argument('--variables', type=str, default=None)
    parser.add_argument('--extractjs', help='extract variable name from js-scripts', action='store_true')
    parser.add_argument('--urls', type=str, default=None)
    parser.add_argument('--url', type=str, default=None)
    parser.add_argument('--kill', action='store_true')

    args = parser.parse_args()

    if args.kill:
        os.system("/usr/bin/pgrep chromedriver | /usr/bin/xargs -I {} kill -9 {}")
        os.system("/usr/bin/pgrep Chrome | /usr/bin/xargs -I {} kill -9 {}")
  
    urls = []
    payloads = []
    variables = []

    chrome_options = settings.get_options(headless=(not args.visible), proxy=args.proxy, load_cookies=args.cookies, load_images=args.load_images)
    
    if args.payloads:
        if not os.path.isfile(args.payloads):
            infologger.info("No such file (payloads) {}".format(args.payloads))
        else:
            with open(args.payloads, "r") as f:
                payloads += f.read().split("\n")

    if args.variables:
        if not os.path.isfile(args.variables):
            infologger.info("No such file (variables) {}".format(args.variables))
        else:
            with open(args.variables, "r") as f:
                variables += f.read().split("\n")

    if args.urls:
        if not os.path.isfile(args.urls):
            infologger.info("No such file (urls) {}".format(args.urls))
        else:
            with open(args.urls, "r") as f:
                urls += f.read().split("\n")

    if args.url:
        urls += [args.url]
    
    try:
        main(urls, payloads, variables, args)
    
    except Exception as e:
        infologger.info(str(e))

    if args.visible:
        try:
            while True:
                time.sleep(1)
        except:
            pass
    
    if driver:
        driver.quit()