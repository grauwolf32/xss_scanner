import redis
import random
import json
import argparse

from urlparse import urlparse

def main():
    parser = argparse.ArgumentParser(description='Add task to the scanner')
    parser.add_argument('--xss_payloads', type=str, default=None)
    parser.add_argument('--var_list', type=str, default=None)
    parser.add_argument('--urls', type=str, default=None)
    parser.add_argument('--url', type=str, default=None)

    parser.add_argument('--without_crawler')
    parser.add_argument('--without_extractor')
    args = parser.parse_args()

    crawler = True
    extractor = True

    if args.without_crawler:
        crawler = False
    if args.without_extractor:
        extractor = False

    redis_conn = redis.StrictRedis(host='localhost', port=6379, db=1)
    tasks = dict()

    domains = set()
    for domain in redis_conn.scan_iter("crawler/domains/*"):
        domain = domain.replace("crawler/domains/","")
        domains.add(domain)

    if args.xss_payloads:
        with open(args.xss_payloads, "r") as f:
            payload = f.readline().strip("\n").strip() # Only payloads that takes one line
            r = random.randint(0,4096)
            cntr = 0
            while redis_conn.get("crawler/payloads/"+str(r)) and cntr < 4096:
                r = random.randint(0,4096)
                cntr += 1
            if cntr >= 4096:
                print "Could not add payload. Payload limit has been reached"
            
            redis_conn.set("crawler/payloads/"+str(r), payload)

    if args.var_list:
        with open(args.var_list, "r") as f:
            for var in f.read().split(","):
                var = var.strip("\n").strip()
                redis_conn.set("crawler/variables/"+var, "")

    if args.urls:
        with open(args.var_list, "r") as f:
            for line in f:
                url = line.strip("\n").strip()
                domain = urlparse(url).netloc

                if domain not in domains:
                    domains.add(domain)
                    redis_conn.set("crawler/domains/"+domain, "")
            
                task_params = dict()
                task_params["worker"] = "Noname"
                task_params["crawler"] = crawler # inherit crawler
                task_params["extract_js"] = extractor # and js extractor parameters
                task_params["params"] = ""
                task_params = json.dumps(task_params)

                tasks[url] = task_params

        for url in tasks:
            redis_conn.set("crawler/queue/"+url, tasks[url])
   
    if args.url:
        url = args.url.strip("\n").strip()
        domain = urlparse(url).netloc
        if domain not in domains:
            domains.add(domain)
            redis_conn.set("crawler/domains/"+domain, "")
        
        task_params = dict()
        task_params["worker"] = "Noname"
        task_params["crawler"] = crawler # inherit crawler
        task_params["extract_js"] = extractor # and js extractor parameters
        task_params["params"] = ""
        task_params = json.dumps(task_params)  
        redis_conn.set("crawler/queue/"+url, task_params)

if __name__=="__main__":
    main()