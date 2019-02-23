import json
import settings
import binascii
import smtplib

from email.header import Header
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from operator import xor

# Notification functions
def send_report(user_email, password, mail_to, subject, data, server_name):
    server = smtplib.SMTP_SSL(server_name)
    server.login(user_email, password)

    mail_from = user_email
    msg = MIMEMultipart()

    msg["Subject"] = Header(subject,"utf-8")
    msg["From"] = mail_from
    msg["To"] = mail_to

    msg_text = MIMEText(data.encode("utf-8"), "plain", "utf-8")
    msg.attach(msg_text)
    
    server.sendmail(mail_from , mail_to, msg.as_string())
    server.quit()

def notify(message, subject):
    credfile = settings.credfile
    
    with open(credfile, "r") as f:
        tmp = f.readline().split(":")
        tmp = [t.strip(" \n") for t in tmp]
            
        user_email = tmp[0]
        password = tmp[1]
        notified_emails = tmp[2:]

        for mail in notified_emails:
            send_report(user_email, password, mail,\
                            "XSS Scanner report",\
                            message, settings.smtp_server)

def redis_get_values(conn, queue, encoding='utf-8'):
    values = set()
    if encoding:
        for key in conn.scan_iter("{}*".format(queue)):
            values.add(conn.get(key).decode(encoding))
    else:
        for key in conn.scan_iter("{}*".format(queue)):
            values.add(conn.get(key))
    
    return values

def redis_get_hashes(conn, queue):
    hashes = set()
    for key in conn.scan_iter('{}*'.format(queue)):
        value_hash = key.decode('utf-8').split('/')[-1]
        hashes.add(value_hash)

    return hashes

def redis_add_values(conn, queue, values):
    existed_hashes = redis_get_hashes(conn, queue)

    for value in values:
        value_hash = binascii.crc32(value.encode('utf-8')) % (1 << 32) # Unsigned CRC32
        value_hash = str(value_hash)
        
        if value_hash not in existed_hashes:
            conn.set("".join((queue, str(value_hash))), value)

def redis_del(conn, queue, hashes):
    for hash_value in hashes:
        key = "".join((queue, str(hash_value)))
        conn.delete(key)

def redis_add_tasks(conn, urls, use_crawler=False, use_extractor=False, methods=['get', 'post']):
    existing_tasks = set()
    existing_tasks.update(redis_get_hashes(conn, settings.task_queue))
    #existing_tasks.update(redis_get_hashes(conn, settings.processing_queue))
    existing_tasks.update(redis_get_hashes(conn, settings.done_queue))

    for url in urls:
        task = dict()
        task_id = binascii.crc32(url.encode('utf-8')) % (1 << 32) # Unsigned CRC32
        task_id = str(task_id)

        if task_id not in existing_tasks:
            task['url'] = url
            task['params'] = pack_params(use_crawler, use_extractor, methods)
            task['id'] = task_id

            dump = json.dumps(task)
            conn.set("".join((settings.task_queue, str(task_id))), dump)

def pack_params(use_crawler=False, use_extractor=False, methods=['get', 'post']):
    result = 0
    if use_crawler:
        result = xor(result, settings.const_use_crawler)
    if use_extractor:
        result = xor(result, settings.const_use_extractor)
    if 'post' in methods:
        result = xor(result, settings.const_use_post)
    if 'get' in methods:
        result = xor(result, settings.const_use_get)

    return result