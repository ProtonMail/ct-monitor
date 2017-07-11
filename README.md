ct-monitor
===========
# A monitoring tool for certificate transparency. #

## Overview ##

The tool monitors and logs new changes on certificate transparency for domains. It then notifies the user whenever a new certificate has been logged on the certificate transparency framework. In case an unauthorized signed SSL certificate for a domain is created, it will be immediately logged and notified.


## Usage ##

Let's say a company owns `example1.com`, `example2.com`, `example3.com`, etc...
To monitor the certificate transparency logs for these domains.

### First ###
```
python ct-monitor.py --domains "example1.com,example2.com,example3.com" --db /var/logs/ct_monitor.db --initial-scan
```

### Second ###
After running an initial scan on all domains, run the following:

```
python ct-monitor.py --domains "example1.com,example2.com,example3.com" --db /var/logs/ct_monitor.db

```

#### Now, whenever a certificate is issued that holds one of the specified domains, a notification will be sent. ####

# Note #
Within the ct-monitor.py script, there is a function called `notification_handler`. It's set to print the notification on screen by default. You would need to customize it based on your needs to integrate the tool with your preferred notification channel.


## Requirements ##
* Python2 or Python3
* requests


## Compatibility ##
The project currently supports all platforms that run Python. The project is compatible with both Python 2 and Python 3.


## References on Certificate Transparency ##
* https://www.certificate-transparency.org/what-is-ct
* https://en.wikipedia.org/wiki/Certificate_Transparency
