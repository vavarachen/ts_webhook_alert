"""
Author : vavarachen@gmail.com
Date : Dec 27, 2017
Version : 1.0
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
import requests
import sys
import json
import gzip
import datetime
import time
import splunk.entity as entity

def gunzip(gzfile):
    if gzfile.endswith(".gz"):
        return gzip.open(gzfile, 'r')
    else:
        return open(gzfile,'r')

def get_future_date(days):
    return '%sT00:00:00' % (datetime.datetime.now().date() + datetime.timedelta(int(days)))

def getCredentials(sessionKey):
    """ Retrieve Anomali Threatstream username and API key """
    myapp = 'ts-webhook-alert'
    try:
        # list all credentials
        entities = entity.getEntities(['admin', 'passwords'], namespace=myapp,
                                    owner='nobody', sessionKey=sessionKey)
    except Exception, e:
        raise Exception("Could not get %s credentials from splunk. Error: %s"
                      % (myapp, str(e)))

    # return first set of credentials
    for i, c in entities.items():
        return c['username'], c['clear_password']

    raise Exception("No credentials have been found")  


def send_observables(settings):
    sessionKey = settings['session_key']
    if len(sessionKey) == 0:
        sys.stderr.write("Session Key missing. Please enable passAuth in inputs.conf.\n")
        sys.stderr.write("sessionKey: %s\n" % sessionKey)
        exit(2)
    ts_username, ts_key = getCredentials(sessionKey)
    
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
        r_file = {'file': ("%s-%d" % (search_name, int(time.time())), gunzip(results_file).read(), 'application/octet-stream')}
        res = requests.post(ts_url, params=r_params,  data=r_data, files=r_file)
        if 200 <= res.status_code < 300:
            sys.stderr.write("DEBUG receiver endpoint responded with HTTP status=%d\n" % res.status_code)
            return True
        else:
            sys.stderr.write("ERROR receiver endpoint responded with HTTP status=%d\n" % res.status_code)
            return False
    except Exception, e:
        sys.stderr.write("ERROR Error %s\n" % e)
        return False


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        settings = json.loads(sys.stdin.read())

        if not send_observables(settings):
            # Uncomment below for troubleshooting. See, tail -f /opt/splunk/var/log/splunk/splunkd.log | grep sendmodalert
            #sys.stderr.write("DEBUG settings: %s\n" % json.dumps(settings, indent=2))
            sys.stderr.write("ERROR Unable to contact TS endpoint\n")
            sys.exit(2)
        else:
            sys.stderr.write("DEBUG TS endpoint responded with OK status\n")

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
