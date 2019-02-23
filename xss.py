import redis
import argparse
import settings
import requests

from aux import *
from extractjs import *
from selenium import webdriver
from selenium.common.exceptions import *
from settings import infologger

import lxml.html as html

requests.packages.urllib3.disable_warnings()

def load_driver():
    global driver
    global chrome_options
    driver = webdriver.Chrome(settings.chrome_path, chrome_options=chrome_options)

def reload_driver():
    global driver
    if driver:
        driver.quit()
    load_driver()

def process_exception(func):
    def wrapper(*args, **kwargs):
        try:
           func(*args, **kwargs)

        except WebDriverException as e:
            infologger.info(str(e))
            reload_driver()

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
            notify(message, "XSS scanner report")
            alert.accept()

    return call

@process_exception
@check_xss
def do_post_request(url, data):
    global driver
    driver.get(settings.postproxy)

    eq = data.find('=')
    if eq != -1:
        varname, varvalue = data[:eq], data[eq+1:]
    else:
        varname, varvalue = data, ""

    post_js = '''var f = document.createElement("form");
                f.setAttribute('method',"post");
                f.setAttribute('action',"{}");
                f.setAttribute('enctype','text/plain');

                var i = document.createElement("input");
                i.setAttribute('type',"hidden");
                i.setAttribute('name','{}');
                i.setAttribute('value','{}');

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

@process_exception
@check_xss
def do_get_request(url, data):
    global driver
    targer_url = "{}?{}".format(url, data)
    driver.get(targer_url)

def main():
    global driver
    global conn 

    load_driver()

    for task_key in conn.scan_iter("{}*".format(settings.task_queue)):
        processing = redis_get_hashes(conn, settings.processing_queue)
        task_hash = task_key.decode('utf-8').split('/')[-1]
        
        if task_hash not in processing:
            process_task(task_key, conn)

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

def process_task(task_key, conn):
    task = json.loads(conn.get(task_key))
    processing_key = "".join((settings.processing_queue, task["id"]))
    conn.set(processing_key, 1) # Mark as processing

    try:
        url = task["url"]
        params = task["params"]

        payloads  = redis_get_values(conn, settings.payloads_queue)
        variables = redis_get_values(conn, settings.variables_queue)

        use_extractor = params and settings.const_use_extractor

        if use_extractor:
            r = requests.get(url, verify=False, timeout=settings.requests_timeout)
            doc = html.fromstring(r.text)

            js_scripts = doc.xpath(".//script/text()")
            for js in js_scripts:
                variables.update(extractjs_fast(js))

        use_post = params and settings.const_use_post
        use_get  = params and settings.const_use_get

        if use_get:
            request_payloads = gen_payloads(list(payloads), list(variables), settings.const_get_maxlen)
            for payload in request_payloads:
                do_get_request(url, payload)

        if use_post:
            request_payloads = gen_payloads(list(payloads), list(variables), settings.const_post_maxlen)

            for payload in request_payloads:
                do_post_request(url, payload)

        conn.set(("".join((settings.done_queue, task["id"]))), 1)
        redis_del(conn, settings.task_queue, [task["id"]])

    except Exception as e:
        infologger.info(str(e))
    
    finally:
        conn.delete(processing_key)
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', type=str, help='list of emails to send report to', default=None)
    parser.add_argument('--extractjs', help='extract variable name from js-scripts', action='store_true')
    parser.add_argument('--visible', help='show chome browser', action='store_true')
    parser.add_argument('--proxy', help='specify proxy', type=str, default=None)
    parser.add_argument('--cookies', help='load cookies from previous sessions', action='store_true')
    parser.add_argument('--load_images', help='load images from sites', action='store_true')
    parser.add_argument('--workerid', type=str, default="0")

    args = parser.parse_args()

    chrome_options = settings.get_options(headless=(not args.visible), proxy=args.proxy, load_cookies=args.cookies, load_images=args.load_images)
    conn = redis.StrictRedis(host=settings.redis_host, port=settings.redis_port, db=settings.redis_db)
    
    main()

    if driver:
        driver.quit()