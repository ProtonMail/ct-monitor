#!/usr/bin/env python3
# coding=utf-8
# *******************************************************************
# *** ct-monitor ***
# * Description:
#   A monitoring tool for certificate transparency.
# * Version:
#   v0.2
# * Author:
#   Mazin Ahmed <Mazin AT ProtonMail DOT com>
# *******************************************************************

# Modules
import argparse
import calendar
import json
import requests
import sqlite3
import time
try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus


def notification_handler(notification_message):
    """
    This function should be customized based off the user needs
    for notification channel.
    """

    print(notification_message)
    return(0)


def notify(ctr_hash=None,
           domain=None,
           cert_data=None,
           zero_results=False,
           scan_finished=False):
    """
    This function notifies users about results of scans,
    and when a scan finishes.
    Edit the TEMPLATE variable to customize notification messages.
    """

    if zero_results is True:
        # Message informing that there is no certificates identified.
        TEMPLATE = "No new certificates were identified for %s." % (domain)
    elif scan_finished is True:
        # Message informing that a scan is finished for a domain.
        TEMPLATE = "Scan finished for %s." % (domain)
    else:
        current_date = calendar.timegm(time.gmtime())
        # Message informing a user with new identified certificate.
        TEMPLATE = """The following certificate has been identified:
* CTR_Hash: %s
* Domain: %s
* Date Discovered: %s
* dnsNames: %s
* validFrom: %s
* validTo: %s
* serialNumber: %s
* subject: %s
* signatureAlgorithm: %s
* issuer: %s
    """ % (ctr_hash,
           domain,
           format_date(current_date),
           cert_data["dnsNames"],
           format_date(cert_data["validFrom"], certificate_date=True),
           format_date(cert_data["validTo"], certificate_date=True),
           cert_data["serialNumber"],
           cert_data["subject"],
           cert_data["signatureAlgorithm"],
           cert_data["issuer"])

    notification_handler(TEMPLATE)
    return(0)


def format_date(epoch, certificate_date=False):
    if certificate_date:
        return time.strftime('%d-%B-%Y %H:%M:%S UTC', time.gmtime((int(epoch / 1000))))
    else:
        return time.strftime('%d-%B-%Y %H:%M:%S UTC', time.gmtime(epoch))


class GoogleCTR_API(object):
    def __init__(self):
        """
        self.timeout: The request's timeout.
        self.user_agent: The request's HTTP User-Agent.
        self.headers: The requests HTTP headers.
        """

        self.timeout = 4
        self.user_agent = "ct-monitor (https://github.com/ProtonMail/ct-monitor)"
        self.headers = {"User-Agent": self.user_agent, 'Accept': '*/*'}

    def certificates_of_domain_query_parser(self, response):
        """
        Parses the first step response, and returns the output as dict.
        Input:
        response: the response of the request.
        Output:
        output: A dict:
        hashes: A list of CTR hashes.
        nextPageToken: The token of next page.
        """

        output = {"hashes": [], "nextPageToken": ""}
        if response[0][0] == str("er"):
            output["nextPageToken"] = None
            return(output)

        try:
            output["nextPageToken"] = str(response[0][-1][1])
        except KeyError:
            output["nextPageToken"] = None  # Reached last page.

        for i in range(len(response[0][1])):
            ctr_hash = response[0][1][i][5]
            output["hashes"].append(ctr_hash)

        return(output)

    def get_certificates_of_domain(self, domain):
        """
        Gets a list of CTR hashes associated with the domain.
        Input:
        domain: the domain to scan.
        Output:
        a list of CTR hashes associated with the domain.
        """

        output = []
        token = ""

        while token is not None:

            if token == "":
                url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain={0}".format(quote_plus(domain))
            else:
                url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?include_expired=true&include_subdomains=true&domain={0}&p={1}".format(quote_plus(domain), quote_plus(token))
            resp = requests.get(url, headers=self.headers, timeout=self.timeout)

            if resp.status_code == 503:
                return(output)

            resp = json.loads(resp.text.split("\n\n")[1])

            if (resp[0][1] is not None) and (len(resp[0][1]) == 0):
                return(output)

            parsed_response = self.certificates_of_domain_query_parser(resp)

            token = parsed_response["nextPageToken"]
            output.extend(parsed_response["hashes"])
        return(output)

    def get_certificate_details(self, ctr_hash):
        """
        Returns certificate details of a certificate.
        Input:
        ctr_hash: CTR Hash for the certificate.
        Output:
        a dict that holds:
        dnsNames: dnsNames entry.
        validFrom: validFrom entry.
        validTo: validTo entry.
        serialNumber: serialNumber entry.
        subject: subject entry.
        signatureAlgorithm: signatureAlgorithm entry.
        issuer: issuer entry.
        """

        output = {}
        url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certbyhash?hash={0}".format(quote_plus(ctr_hash))
        resp = requests.get(url, headers=self.headers, timeout=self.timeout)
        if resp.status_code == 503:
            output = {"dnsNames": "NA",
                      "validFrom": "NA",
                      "validTo": "NA",
                      "serialNumber": "NA",
                      "subject": "NA",
                      "signatureAlgorithm": "NA",
                      "certificateType": "NA",
                      "issuer": "NA"}
            return(output)
        resp = json.loads(resp.text.split("\n\n")[1])

        output.update({"serialNumber": resp[0][1][0]})
        output.update({"subject": resp[0][1][1]})
        output.update({"issuer": resp[0][1][2]})
        output.update({"validFrom": resp[0][1][3]})
        output.update({"validTo": resp[0][1][4]})
        output.update({"signatureAlgorithm": resp[0][1][6]})
        if resp[0][1][7] == "":
            output.update({"dnsNames": "NA"})
        else:
            output.update({"dnsNames": ", ".join(resp[0][1][7])})

        return(output)


class DBHandler(object):
    def __init__(self, db):
        self.conn = sqlite3.connect(db)
        self.c = self.conn.cursor()
        self.db_initialize()

    def db_initialize(self):
        """
        Initialize the DB.
        Input: None
        Output:
        return: 0: if no errors occurred.
        """

        self.c.execute("""CREATE TABLE IF NOT EXISTS "Data" ("CTR_Hash" TEXT, "Domain" TEXT, "Date_Added" NUMERIC, "dnsNames" TEXT, "validFrom" TEXT, "validTo" TEXT, "serialNumber" TEXT, "subject" TEXT, "signatureAlgorithm" TEXT, "issuer" TEXT);""")
        self.c.execute("""CREATE TABLE IF NOT EXISTS "Logs" ("Date" NUMERIC, "Scan_Type" TEXT, "New_Identified_Certs_Count" INTEGER);""")
        self.conn.commit()
        return(0)

    def check_if_certifacte_in_db(self, ctr_hash):
        """
        Checks if the certificate exists in the DB.
        Input:-
        ctr_hash: CTR Hash for the certificate.
        Output:-
        returns: True: if the certificate is the DB.
        returns: False: if the certificate is not the DB.
        """

        self.c.execute("""SELECT  COUNT("CTR_Hash") FROM "Data" WHERE CTR_Hash = ?""", (ctr_hash,))
        i = self.c.fetchall()[0][0]
        if i > 0:
            return(True)
        else:
            return(False)

    def add_certifacte_to_db(self, ctr_hash, domain, cert_data):
        """
        Adds certificate entry to the DB.
        Input:-
        ctr_hash: CTR Hash for the certificate.
        domain: Domain name.
        cert_data: the output of get_certificates_of_domain function
        Output:-
        return: 0: if no errors occurred.
        """

        current_date = calendar.timegm(time.gmtime())
        self.c.execute("""INSERT INTO "Data" VALUES(? ,? , ?, ?, ?, ?, ?, ?, ?, ?) """, (ctr_hash, domain, current_date, cert_data["dnsNames"], cert_data["validFrom"], cert_data["validTo"], cert_data["serialNumber"], cert_data["subject"], cert_data["signatureAlgorithm"], cert_data["issuer"],))
        self.conn.commit()

        return(0)

    def add_to_scans_log(self, scan_type, new_identified_Certs_count):
        """
        Adds log entry for scans.
        Input:-
        scan_type: The scan type.
        new_identified_Certs_count: The sum of new identified certificates.
        Output:-
        return: 0: if no errors occurred.
        """

        current_date = calendar.timegm(time.gmtime())
        self.c.execute("""INSERT INTO "Logs" VALUES(?,?,?)""", (current_date, scan_type, new_identified_Certs_count,))
        self.conn.commit()

        return(0)


def run(domain, initial_scan=False, db=None):
    """
    The responsible function for the scan.
    Input:-
    domain: The domain for the scan.
    Optional Input:
    initialize_scan: if set to True, notification will not occur.
                     default: False.
    Output:-
    return: 0: if no errors occurred.
    """

    new_identified_Certs_counter = 0
    ctr_hashes = GoogleCTR_API().get_certificates_of_domain(domain)
    for ctr_hash in ctr_hashes:
        if DBHandler(db).check_if_certifacte_in_db(ctr_hash) is False:
            new_identified_Certs_counter += 1
            cert_data = GoogleCTR_API().get_certificate_details(ctr_hash)
            DBHandler(db).add_certifacte_to_db(ctr_hash, domain, cert_data)
            if initial_scan is False:
                notify(ctr_hash=ctr_hash,
                       domain=domain,
                       cert_data=cert_data)
    if new_identified_Certs_counter == 0:
        notify(domain=domain, zero_results=True)
    if initial_scan is True:
        scan_type = "initial_scan"
    else:
        scan_type = "update"
    DBHandler(db).add_to_scans_log(scan_type, new_identified_Certs_counter)
    notify(domain=domain, scan_finished=True)

    return(0)


def main():

    parser = argparse.ArgumentParser(description="ct-monitor:" +
                                                 " A monitoring tool for" +
                                                 " certificate transparency")
    parser.add_argument("-d", "--domains",
                        dest="domains",
                        help="A list of domains to monitor," +
                             " separated by commas.",
                        action='store',
                        required=True)
    parser.add_argument("--db",
                        dest="db",
                        help="The SQLITE database to save results.\
                              If not existed, it will be automatically\
                              created.",
                        action='store',
                        required=True)
    parser.add_argument("--initial-scan",
                        dest="initial_scan",
                        help="Initial scan to set the database and initial\
                             entries",
                        action='store_true')
    args = parser.parse_args()

    domains = args.domains.replace(" ", "").split(",") if args.domains else []
    db = args.db if args.db else None
    initial_scan = args.initial_scan if args.initial_scan else False

    if db is None:
        print("Error: --db is not specified.")
        exit(1)
    if len(domains) == 0:
        print("Error: --domains is not specified")
        exit(1)

    for domain in domains:
        run(domain, db=db, initial_scan=initial_scan)

    print("Done.")

if (__name__ == "__main__"):
    try:
        main()
    except KeyboardInterrupt:
        exit(1)
    except Exception as e:
        print(e)
        exit(2)
