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


SEND_PAGES = 3


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


def whoseip(ip, whoserole, debuglevel=0):
    r"""
    Obtain email addresses of a given role for the given IP address.

    >>> whoseip('71.17.138.152', 'abuse')
    ['abuse@sasktel.net']

    >>> whoseip('109.87.56.48', 'abuse')
    ['noc@triolan.com']

    >>> whoseip('76.67.127.81', 'abuse')
    ['abuse@sympatico.ca', 'abuse@bell.ca']
    """

    def get_roles_addresses(entities):
        er = [(e.get("roles", []), 
                dict([(k, v) for (k, obj, kind, v) in e.get("vcardArray", [None, []])[1]]))
            for e in entities]
        for e in entities:
            if "entities" in e:
                er.extend(get_roles_addresses(e["entities"]))
        return er

    handler = request.HTTPSHandler(debuglevel=debuglevel)
    opener = request.build_opener(handler)

    emails = []
    with opener.open(request.Request("https://rdap.arin.net/bootstrap/ip/%s" % (ip,))) as response:
        r = json.loads(response.read().decode("utf-8"))
        try:
            entroles = get_roles_addresses(r["entities"])
        except (KeyError, IndexError) as e:
            sys.stderr.write("  *** %s %s in %s\n" % (e.__class__.__name__, 
                    e, pformat(r)))
            return emails
        for roles, addr in entroles:
            if whoserole in roles:
                if "email" in addr:
                    emails.append(addr["email"])
    return emails


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
            f.write("%s: %s\n" % (e, ", ".join(str(ehost) for ehost in ehosts)))


def filter_hosts(infected_hosts, prodfilter, component, ready_emails, all_emails, debuglevel=0):
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
            sys.stderr.write(" *** HTTP timed out on \"%s\"\n" % (url,))
            continue
        except socket.timeout as e:
            sys.stderr.write(" *** TCP timed out on \"%s\"\n" % (url,))
            continue

        for e in whoseip(ip, "abuse"):
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

    for e in sorted(ready_emails.keys()):
        ready_ehosts = ready_emails[e]
        ready_ehosts.sort()

    for e in sorted(all_emails.keys()):
        all_ehosts = all_emails[e]
        all_ehosts.sort()


def send_mail(ready_emails, testing, myaddr, component, prodfilter):
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
    unittesting = False
    debuglevel = 0
    testing = False
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "-d":
            debuglevel = 1
        elif arg == "-t":
            testing = True
        elif arg == "-u":
            unittesting = True
        elif arg.startswith("-"):
            raise Usage()
        else:
            break
        i += 1
    if unittesting:
        import doctest
        (failures, tests) = doctest.testmod(verbose=(not not debuglevel))
        raise SystemExit(0 if failures == 0 else 1 + (failures % 127))
    if len(argv) < i + 2:
        raise Usage()
    (component, country) = argv[i:i + 2]
    i += 2
    if len(argv) < i + 1:
        prodfilter = None
    else:
        prodfilter = argv[i].lower()
        i += 1
        if len(argv) >= i + 1:
            raise Usage()

    myaddr = "{USER}@{HOSTNAME}".format(USER=os.environ["USER"], HOSTNAME=socket.gethostname())
    sent_name = "email-hosts.txt"
    all_emails = read_sent_emails(sent_name)
    ready_emails = {}
    page = 1
    page_sender_count = 0
    while True:
        shodan_limits = info_shodan(debuglevel=debuglevel)
        sys.stderr.write("Shodan limits:\n%s\n" % (pformat(shodan_limits),))

        shodan_results = search_shodan(page, component=component, country=country, prodfilter=prodfilter, debuglevel=debuglevel)
        numhosts = len(shodan_results["matches"])
        sys.stderr.write("Found matches: {numhosts}\n".format(numhosts=numhosts))
        if numhosts == 0:
            break
        infected_hosts = tuple((ip_address(match["ip"]), match["product"], match["port"], not not match.get("ssl")) for match in shodan_results["matches"])
        filter_hosts(infected_hosts, prodfilter, component, ready_emails, all_emails)
        page += 1
        page_sender_count += 1
        if page_sender_count == SEND_PAGES:
            send_mail(ready_emails, testing, myaddr, component, prodfilter)
            write_sent_emails(sent_name, all_emails)
            ready_emails = {}
            page_sender_count = 0

    send_mail(ready_emails, testing, myaddr, component, prodfilter)
    write_sent_emails(sent_name, all_emails)

if __name__ == "__main__":
    import sys
    # Wrapping parameter parsing into a function call prevents from spilling
    # them into the global namespace and accidentally using them in the other
    # functions.
    main(sys.argv)

