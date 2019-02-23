import os
import argparse
import settings

from aux import *
from settings import infologger

if __name__=="__main__":
    parser = argparse.ArgumentParser(description='Add task to the scanner')
    parser.add_argument('--payloads', type=str, default=None)
    parser.add_argument('--variables', type=str, default=None)
    parser.add_argument('--extractjs', help='extract variable name from js-scripts', action='store_true')
    parser.add_argument('--crawler', help='extract urls from page and scan throug them', action='store_true')
    parser.add_argument('--urls', type=str, default=None)
    parser.add_argument('--url', type=str, default=None)
    args = parser.parse_args()

    conn = redis.StrictRedis(host=settings.redis_host, port=settings.redis_port, db=settings.redis_db)

    if args.payloads:
        if not os.path.isfile(args.payloads):
            infologger.info("No such file (payloads) {}".format(args.payloads))
        else:
            with open(args.payloads, "r") as f:
                payloads = f.read().split("\n")
            redis_add_values(conn, settings.payloads_queue, payloads)

    if args.variables:
        if not os.path.isfile(args.variables):
            infologger.info("No such file (variables) {}".format(args.variables))
        else:
            with open(args.variables, "r") as f:
                variables = f.read().split("\n")
            redis_add_values(conn, settings.variables_queue, variables)

    if args.urls:
        if not os.path.isfile(args.urls):
            infologger.info("No such file (urls) {}".format(args.urls))
        else:
            with open(args.urls, "r") as f:
                urls = f.read().split("\n")
            redis_add_tasks(conn, urls, args.crawler, args.extractjs)
    
    if args.url:
        redis_add_tasks(conn, [url], args.crawler, args.extractjs)