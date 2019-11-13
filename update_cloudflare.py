import json
import logging.handlers
import re
import time

import ConfigParser
import requests

config = ConfigParser.SafeConfigParser()
config.read('conf/update_cloudflare.props')

logfile = config.get('log', 'logfile')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
fh = logging.handlers.TimedRotatingFileHandler(logfile, when='midnight', interval=1, backupCount=5)
fh.setLevel(logging.DEBUG)
fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
fh.setFormatter(fmt)
logger.addHandler(fh)

v4url = config.get('update', 'v4url')
dns_record_host = config.get('update', 'dns_record_host')
dns_record_type = 'A'
dns_record_id = None
new_ip_url = config.get('update', 'new_ip_url')

x_auth_email = config.get('update', 'X-Auth-Email')
x_auth_key = config.get('update', 'X-Auth-Key')

sleep_period = float(config.get('update', 'sleep_period'))

logger.info('X-Auth: email:{e} key:{k}'.format(e=x_auth_email, k=x_auth_key))
zone_id = None
current_ip = None
new_ip = None
headers = {'Content-Type': 'application/json', 'X-Auth-Email': x_auth_email, 'X-Auth-Key': x_auth_key}
url = '{}/zones'.format(v4url)
try:
    r = requests.get(url, headers=headers)
except requests.exceptions.ConnectionError as err:
    logger.error(err)
    r = None
if r is None or r.status_code != 200:
    if r is not None:
        logger.error('Failed to get zones: error{}'.format(r.text))
    #exit(1)
else:
    # print(r.json())
    packet = r.json()
    # print (packet['result'])
    result = packet['result']
    for zone in result:
        # print(zone)
        # print('Zone: name {} id {}'.format(zone['name'], zone['id']))
        if zone['name'] == dns_record_host:
            zone_id = zone['id']
            break
    logger.info('ZoneID: {}'.format(zone_id))
if zone_id is not None:
    url = '{}/zones/{}/dns_records'.format(v4url, zone_id)
    try:
        r = requests.get(url, headers=headers)
    except requests.exceptions.ConnectionError as err:
        logger.error(err)
        r = None
    if r is not None and r.status_code == 200:
        packet = r.json()
        for dns in packet['result']:
            if dns['name'] == dns_record_host and dns['type'] == dns_record_type:
                # print (json.dumps(dns, indent=1))
                current_ip = dns['content']
                dns_record_id = dns['id']
                logger.info('DNSID: {}  current IP: {}'.format(dns_record_id, current_ip))

        if current_ip is not None:
            new_ip = None
            try:
                r = requests.get(new_ip_url)
            except requests.exceptions.ConnectionError as err:
                logger.error(err)
                r = None
            if r is not None and r.status_code == 200:
                if r is not None:
                    m = re.search('\d+[.]\d+[.]\d+[.]\d+', r.text)
                    if m is not None:
                        new_ip = m.group()
            if new_ip is not None and new_ip == current_ip:
                logger.info('IP unchanged - do nothing')
            else:
                data = {"type": dns_record_type, "name": dns_record_host, "content": new_ip}
                url = '{}/zones/{}/dns_records/{}'.format(v4url, zone_id, dns_record_id)
                try:
                    r = requests.put(url, json.dumps(data), headers=headers)
                except requests.exceptions.ConnectionError as err:
                    logger.error(err)
                    r = None
                if r is not None and r.status_code == 200:
                    logger.info('IP updated to {}'.format(new_ip))
                elif r is not None:
                    logger.error('Failed to update IP - error {}'.format(r.text))

