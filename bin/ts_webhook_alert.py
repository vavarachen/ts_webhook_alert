"""
Author : vavarachen@gmail.com
Date : Apr 14, 2020
Version : 1.2
Description : This script can be used to send indicators from Splunk to ThreatStream.
How the indicator is interpreted is dictated by indicator mappings.

Notes : The splunk query triggering the alert must contain at least one column named "value"
the values of which should contain the indicator to be exported to ThreatStream.

You can choose to override the tag and indicator type specified in the alert by
adding columns "itype" and "tags" to the splunk query output.  The values of these
columns will override the alert defaults for the corresponding indicator.

Sample csv output:

value,itype,tags
attacker1@gmail.com,phish_email,malicious_campaign
http://attacker1.site.tld,phish_url,malicious_campaign
attacker2@yahoo.com,,
http://attacker2.site.tld,,

For the above sample, the alert default itype, tags (configured during alert creation)
will only be applied to attacker2 email and url.  The first two indicators should override
the alert defaults with specified itype and tags.
"""
import os
import requests
import sys
import json
import gzip
import datetime
import time
import splunk.entity as entity
import csv
import logging
from logging.handlers import RotatingFileHandler


logger = logging.getLogger('ts_webhook_alert')
logger.setLevel(logging.DEBUG)
try:
    fh = RotatingFileHandler('%s/var/log/splunk/ts_webhook.log' % os.environ['SPLUNK_HOME'], backupCount=3)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    fh.level = logging.DEBUG
    logger.addHandler(fh)
except Exception:
    pass


def gunzip(gzfile):
    """
    Uncompress the results file and sanitize it for import.
    Splunk results file by default contains columns which don't play nice with TS import
    """

    logger.info("Processing results file %s" % gzfile)
    if gzfile.endswith(".gz"):
        results_file = gzip.open(gzfile, 'rb')
    else:
        results_file = open(gzfile, 'r')

    reader = csv.DictReader(results_file)
    header = [r for r in reader.fieldnames if not r.startswith('__mv_')]

    sanitized_results_file = os.path.join(os.path.dirname(gzfile), 'sanitized_results.csv')
    with open(sanitized_results_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
        writer.writeheader()
        for row in reader:
            for k in row.keys():
                if k.startswith('__mv_'):
                    row.pop(k)
            writer.writerow(row)
    logger.info("Wrote export file %s" % sanitized_results_file)
    return open(sanitized_results_file)


def get_future_date(days):
    """ Indicator expiration date """
    return '%sT00:00:00' % (datetime.datetime.now().date() + datetime.timedelta(int(days)))


def get_credentials(session_key):
    """ Retrieve Anomali Threatstream username and API key """
    my_app = 'ts_webhook_alert'
    try:
        # list all credentials
        entities = entity.getEntities(['admin', 'passwords'], namespace=my_app, owner='nobody', sessionKey=session_key)
    except Exception as err:
        raise Exception("Could not get %s credentials from Splunk. Error: %s" % (my_app, str(err)))
    else:
        # return first set of credentials
        for k, v in entities.items():
            if v['eai:acl']['app'] == my_app:
                return v['username'], v['clear_password']

    raise Exception("No credentials have been found")


def send_observables(settings):
    """
    This is the workhorse of the app.
    1) Get credentials for API
    2) Initialize variables and defaults for the import
    3) Post data
    """
    session_key = settings['session_key']
    if len(session_key) == 0:
        logger.error("Session Key missing. Please enable passAuth in inputs.conf.\n")
        logger.debug("ERROR sessionKey: %s\n" % session_key)
        exit(2)
    ts_username, ts_key = get_credentials(session_key)
    
    config = settings['configuration']
    results_file = settings['results_file']
    search_name = settings['search_name']
    ts_url = config['ts_import_url']
    r_params = dict({
        'username': ts_username,
        'api_key': ts_key
    })
    r_data = dict({
        "notes": config['ts_tags'],
        "trusted_circles": config['ts_trusted_circles'],
        "source_confidence_weight": config['ts_source_confidence'],
        "confidence": config['ts_confidence'],
        "severity": config['ts_severity'],
        "expiration_ts": get_future_date(config['ts_expiration']),
        "classification": config['ts_classification'],
        "md5_mapping": config['ts_mapping_md5'],
        "ip_mapping": config['ts_mapping_ip'],
        "domain_mapping": config['ts_mapping_domain'],
        "url_mapping": config['ts_mapping_url'],
        "email_mapping": config['ts_mapping_email']
    })

    try:
        # By default the filename is 'results.csv.gz' which is not very helpful.
        # For easier correlation, filename is based on saved search name and timestamp
        r_file = {'file': ("%s-%d" % (search_name, int(time.time())),
                           gunzip(results_file).read(), 'application/octet-stream')}
        res = requests.post(ts_url, params=r_params,  data=r_data, files=r_file, verify=True)

        if res.ok:
            logger.info("Receiver endpoint responded with HTTP status=%d, reason=%s\n" % (res.status_code, res.reason))
            return True
        else:
            try:
                logger.error("Receiver endpoint responded with HTTP status=%d, reason=%s.  Payload: %s\n" %
                             (res.status_code, res.reason, json.dumps(res.json())))
            except Exception:
                logger.warning("Non JSON response received from %s" % ts_url)
                logger.error("Receiver endpoint responded with HTTP status=%d, reason=%s.  Payload: %s\n" %
                             (res.status_code, res.reason, res.text))
            return False
    except Exception:
        raise


if __name__ == '__main__':
    # Uncomment below for troubleshooting.
    # See, tail -f /opt/splunk/var/log/splunk/splunkd.log | grep sendmodalert
    # sys.stderr.write("DEBUG settings: %s\n" % json.dumps(settings, indent=2))
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        settings = json.loads(sys.stdin.read())

        try:
            resp = send_observables(settings)
        except Exception as err:
            logger.error(str(err))
            sys.stderr.write("ERROR Unable to export indicators to TS endpoint\n")
            sys.exit(-1)
        else:
            logger.info("TS export successful.")
            sys.stderr.write("INFO TS endpoint responded with OK status\n")

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
