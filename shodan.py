#! /usr/bin/python3
# vim: et:ts=4:sts=4:sw=4:fileencoding=utf-8
r"""

    Usage: {script} [-t] COMPONENT COUNTRY [PRODUCT]

e.g.,

    {script} -t coinhive CA mikrotik

"""

from urllib import request, parse
from urllib.error import HTTPError, URLError
import ssl
import json
from pprint import pformat
from ipaddress import ip_address
import struct, socket, sys, os
import smtplib
from email.mime.text import MIMEText


ANICHOST = "whois.arin.net"


class Usage(SystemExit):
    def __init__(self):
        super(Usage, self).__init__(__doc__.format(script=os.path.basename(__file__)))


def info_shodan(**kwargs):
    with open(os.path.expanduser("~/.shodan")) as f:
        shodan_key = f.read().strip()

    sys.stderr.write("Inquiring shodan.io on API usage limits...\n")

    handler = request.HTTPSHandler(debuglevel=kwargs.get("debuglevel", 0))
    opener = request.build_opener(handler)

    with opener.open(request.Request("https://api.shodan.io/api-info",
        parse.urlencode((
                ("key", shodan_key),
            )).encode("ascii"))) as response:
        if response.getcode() != 200:
            raise ValueError("Unexpected HTTP response code {code}".format(code=response.getcode()))
        shodan_results = json.loads(response.read().decode("utf-8"))
    return shodan_results


def search_shodan(page, **kwargs):
    with open(os.path.expanduser("~/.shodan")) as f:
        shodan_key = f.read().strip()

    query = "http.component:{component} country:{country}".format(**kwargs)
    sys.stderr.write("Inquiring shodan.io with \"%s\" (page %d)...\n" % (query, page,))

    handler = request.HTTPSHandler(debuglevel=kwargs.get("debuglevel", 0))
    opener = request.build_opener(handler)

    with opener.open(request.Request("https://api.shodan.io/shodan/host/search",
        parse.urlencode((
                ("key", shodan_key),
                ("query", query),
                ("page", page),
            )).encode("ascii"))) as response:
        if response.getcode() != 200:
            raise ValueError("Unexpected HTTP response code {code}".format(code=response.getcode()))
        shodan_results = json.loads(response.read().decode("utf-8"))
    return shodan_results


def whoseip(ip, prop):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((ANICHOST, 43))
    s.send(("n + %s\r\n" % (ip,)).encode("utf-8"))
    r = []
    while True:
        d = s.recv(4096)
        if not d:
            break
        r.append(d)
    s.close()
    resp = b"".join(r).decode("utf-8")
    propheader = "%s:" % (prop,)
    propvalues = []
    for line in resp.splitlines():
        if line.startswith(propheader):
            propvalue = line.split(None, 1)[1].strip()
            propvalues.append(propvalue)
    return propvalues


def read_sent_emails(sent_name):
    sent_emails = {}
    with open(os.path.expanduser(sent_name)) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            email, iptext = line.split(None, 1)
            if email.endswith(":"):
                email = email[:-1]
            ips = []
            for ipstr in iptext.split():
                if ipstr.endswith(","):
                    ipstr = ipstr[:-1]
                ips.append(ip_address(ipstr))
            sent_emails[email] = ips
    return sent_emails


def write_sent_emails(sent_name, sent_emails):
    with open(os.path.expanduser(sent_name), "w") as f:
        for e in sorted(sent_emails.keys()):
            ehosts = sent_emails[e]
            ehosts.sort()
            f.write("%s: %s\n" % (e, ", ".join(str(ehost) for ehost in ehosts)))


def filter_hosts(infected_hosts, prodfilter, component, testing, myaddr, ready_emails, all_emails, debuglevel=0):
    ssl_handler = request.HTTPSHandler(debuglevel=debuglevel, context=ssl._create_unverified_context(), check_hostname=False)
    ssl_opener = request.build_opener(ssl_handler)

    plain_handler = request.HTTPHandler(debuglevel=debuglevel)
    plain_opener = request.build_opener(plain_handler)

    componentfilter = component.lower()

    page_emails = {}

    for (ip, product, port, is_ssl) in infected_hosts:
        sys.stderr.write("%s\n" % (ip,))
        if prodfilter:
            if prodfilter not in product.lower():
                sys.stderr.write("  *** %s\n" % (product,))
                continue
        if is_ssl:
            opener = ssl_opener
            url = "https://%s:%s/" % (ip, port)
        else:
            opener = plain_opener
            url = "http://%s:%s/" % (ip, port)

        try:
            with opener.open(url, timeout=5) as response:
                html = response.read().decode("utf-8", errors="replace")
                if componentfilter not in html.lower():
                    sys.stderr.write(" *** HTML %r... at %s does not show \"%s\"\n" % (html[:20],
                        url, componentfilter))
                    continue
        except HTTPError as e:
            html = e.read().decode("utf-8", errors="replace")
            if componentfilter not in html.lower():
                sys.stderr.write(" *** HTML %r... at %s does not show \"%s\" and responds with code %s\n" % (html[:20],
                    url, componentfilter, e.code))
                continue
        except URLError as e:
            sys.stderr.write(" *** Timed out on \"%s\"\n" % (url,))
            continue

        for e in whoseip(ip, "OrgAbuseEmail"):
            sys.stderr.write("  %s\n" % (e,))
            page_ehosts = page_emails.get(e, [])
            ready_ehosts = ready_emails.get(e, [])
            all_ehosts = all_emails.get(e, [])
            if ip not in all_ehosts:
                page_ehosts.append(ip)
                ready_ehosts.append(ip)
                all_ehosts.append(ip)
                page_emails[e] = page_ehosts
                ready_emails[e] = ready_ehosts
                all_emails[e] = all_ehosts

    sys.stderr.write("\n")
    for e in sorted(page_emails.keys()):
        page_ehosts = page_emails[e]
        page_ehosts.sort()
        sys.stderr.write("%s: %s\n" % (e, ", ".join(str(page_ehost) for page_ehost in page_ehosts)))


def send_mail(ready_emails):
    sys.stderr.write("\n")
    prodname = prodfilter if prodfilter else "internet thing"
    for e in sorted(ready_emails.keys()):
        sys.stderr.write("Sending email to %s...\n" % (e,))
        ehosts = ready_emails[e]
        msg = MIMEText("""
Hello %s,

Your %s at the following address(es) showed as infected with "%s":

  %s

Best regards,

A community cleanup initiative
https://github.com/ilatypov/community-cleanup
""" % (e, prodname, component, "\n  ".join(str(ehost) for ehost in ehosts)))

        recipients = [myaddr]
        if not testing:
            recipients.append(e)
        msg["Subject"] = "Community cleanup: your %s needs attention" % (prodname,)
        msg["From"] = myaddr
        msg["To"] = e
        s = smtplib.SMTP("localhost")
        s.sendmail(myaddr, recipients, msg.as_string())
        s.quit()


def main(argv):
    if len(argv) < 2:
        raise Usage()
    i = 1
    if argv[i] == "-d":
        debuglevel = 1
        i += 1
    else:
        debuglevel = 0
    if argv[i] == "-t":
        testing = True
        i += 1
    else:
        testing = False
    if len(argv) < i + 2:
        raise Usage()
    (component, country) = argv[i:i + 2]
    if len(argv) == i + 3:
        prodfilter = argv[i + 2].lower()
    elif len(argv) < i + 3:
        prodfilter = None
    else:
        raise Usage()

    myaddr = "{USER}@{HOSTNAME}".format(USER=os.environ["USER"], HOSTNAME=socket.gethostname())
    sent_name = "email-hosts.txt"
    all_emails = read_sent_emails(sent_name)
    ready_emails = {}
    page = 1
    while True:
        shodan_limits = info_shodan(debuglevel=debuglevel)
        sys.stderr.write("Shodan limits:\n%s\n" % (pformat(shodan_limits),))

        shodan_results = search_shodan(page, component=component, country=country, prodfilter=prodfilter, debuglevel=debuglevel)
        numhosts = len(shodan_results["matches"])
        sys.stderr.write("Found matches: {numhosts}\n".format(numhosts=numhosts))
        if numhosts == 0:
            break
        infected_hosts = tuple((ip_address(match["ip"]), match["product"], match["port"], not not match.get("ssl")) for match in shodan_results["matches"])
        filter_hosts(infected_hosts, prodfilter, component, testing, myaddr, ready_emails, all_emails)
        page += 1

    send_mail(ready_emails)
    write_sent_emails(sent_name, all_emails)

if __name__ == "__main__":
    import sys
    # Wrapping parameter parsing into a function call prevents from spilling
    # them into the global namespace and accidentally using them in the other
    # functions.
    main(sys.argv)

