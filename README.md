# ts_webhook_alert
Splunk alert action app for exporting indicators from Splunk to Anomali ThreatStream.


# Installation

```console
git clone https://github.com/vavarachen/ts_webhook_alert.git

tar -czf ts_webhook_alert.tar.gz ts_webhook_alert
```

Upload the tar.gz file to Splunk Search Head (Apps > Manage Apps > Install app from file)


# Configuration
Find app ("Anomali Threatstream Indicator Export") and click "Set up"
![Setup](https://github.com/vavarachen/ts_webhook_alert/blob/master/resources/ts_webhook_setup.png)


# Example
Create a Splunk search which outputs indicators.  Fields like 'tag', 'itype' are optional.

![Splunk Search](https://github.com/vavarachen/ts_webhook_alert/blob/master/resources/alert_step1.png)

Create an alert from the search.
![Create Alert](https://github.com/vavarachen/ts_webhook_alert/blob/master/resources/alert_step2.png)

Configure ts_webhook as 'Action'.
![Configure Action](https://github.com/vavarachen/ts_webhook_alert/blob/master/resources/alert_step3.png)