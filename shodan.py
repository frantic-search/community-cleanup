#! /usr/bin/python3
# vim: et:ts=4:sts=4:sw=4:fileencoding=utf-8
r"""
Usage:

    python3 {script} [-t] [--to-myself-only] \
            [--product PRODUCT] \
            [--country COUNTRY] \
            [--component COMPONENT] \
            [--macro MACRO] \
            [--url httpX://HOST:PORT]
            [--rerun (EMAIL|REGEX)]

e.g.,

    python3 {script} -t --product MikroTik --country CA \
            --component coinhive --macro {CHECK_COINHIVE}

    python3 {script} -t --query "country:CA avtech" \
            --macro {WEAK_AVTECH}

    python3 {script} -t --macro {WEAK_AVTECH} --url http://SUSPECT:PORT

    python3 {script} --to-myself-only --rerun abuse@telus.com

    python3 {script} --to-myself-only --rerun '.*\.ca$'

Using --to-myself-only will limit recipients to oneself.

Using -t will spare from using Shodan when testing code changes.  This will
also limit email recipients to oneself.
{message}
"""

import os
if os.name == "nt":
    # Check if executing the Windows build of Python from a Cygwin shell.
    if "TZ" in os.environ:
        # The Windows build of Python (as opposed to the Cygwin one) appears
        # confused with the TZ variable set by the Cygwin shell.  The former
        # sets time.timezone to 0, time.altzone to -3600 (-1 hr) in the
        # presence of TZ="America/New_York", which turns the local time zone to
        # UTC.
        del os.environ["TZ"]
import time

from urllib import request, parse
from urllib.error import HTTPError, URLError
from http.client import BadStatusLine, CannotSendRequest
import ssl
import json
import base64
from pprint import pformat
from ipaddress import ip_address, IPv4Address, IPv6Address
import struct, socket, sys
import smtplib
from email.mime.text import MIMEText
import re


SEND_PAGES = 3
IPS_LIMIT = 4
TEST_IPS = ("23.16.26.111", "216.232.223.192", "174.94.137.145")
CHECK_COINHIVE = "check_coinhive"
WEAK_AVTECH = "weak_avtech"
MACROS = (CHECK_COINHIVE, WEAK_AVTECH)

SHODAN_TIMEOUT = 15
SHODAN_LARGE_TIMEOUT = 45
URL_TIMEOUT = 5
REPEAT_SLEEP = 5
NETWORK_ERRORS = (socket.timeout, socket.error, socket.herror, socket.gaierror,
        OSError,
        BadStatusLine, CannotSendRequest,
        ConnectionRefusedError, ConnectionResetError, 
        URLError)


class Usage(SystemExit):
    def __init__(self, message=None):
        super(Usage, self).__init__(__doc__.format(script=os.path.basename(__file__),
            CHECK_COINHIVE=CHECK_COINHIVE,
            WEAK_AVTECH=WEAK_AVTECH,
            message=("\nError: %s\n" % (message,) if message else "")))


def local_timestamp(s_since_epoch=None):
    if s_since_epoch is not None:
        if s_since_epoch < 0:
            return "infinity"
        elif s_since_epoch == 0:
            return "olden times"
    t = time.localtime(s_since_epoch)
    is_dst = time.daylight and t.tm_isdst
    zone = time.altzone if is_dst else time.timezone
    strtime = time.strftime("%Y-%m-%d %H:%M:%S", t)
    utcoff = -zone
    if utcoff > 0:
        utcsign = "+"
    else:
        utcsign = "-"
        utcoff = -utcoff
    strtime += ("%s%02d%02d" % (utcsign, utcoff // 3600, (utcoff % 3600) // 60))
    return strtime


def process_http_error(e, quiet=False):
    code = e.getcode()
    try:
        body = e.read().decode("utf-8", errors="replace")
    except (HTTPError,) + NETWORK_ERRORS as e2:
        body = ""
        sys.stderr.write("  *** Error reading HTTP response to {url}: original code {code}, body unavailable due to {classname}\n".format(url=e.geturl(),
                code=e.getcode(), classname=e2.__class__.__name__))
        code = 0
    else:
        if ((code < 200) or (code >= 400)) and not quiet:
            sys.stderr.write("  *** HTTP response to {url}: code {code}, body {body!r}...\n".format(url=e.geturl(),
                    code=e.getcode(), body=body[:20]))
    return (code, body)


process_http_response = process_http_error


def log_network_error(e, url):
    sys.stderr.write("  *** Network {classname} with {url}\n".format(classname=e.__class__.__name__,
        url=url))


def sleep_with_banner(repeatsleep):
    sys.stderr.write("  *** Repeating in {repeatsleep}s...\n".format(repeatsleep=repeatsleep))
    time.sleep(repeatsleep)


def resilient_send(req, timeout=URL_TIMEOUT, repeatsleep=REPEAT_SLEEP, debuglevel=0):
    url = req.full_url
    if url.startswith("https:"):
        handlerclass = request.HTTPSHandler
    else:
        handlerclass = request.HTTPHandler
    handler = handlerclass(debuglevel=debuglevel)
    opener = request.build_opener(handler)

    while True:
        try:
            with opener.open(req, timeout=timeout) as response:
                (code, body) = process_http_response(response, True)
                break
        except HTTPError as e:
            (code, body) = process_http_error(e, True)
            backendmsg = str(body)
            if "timed out" in backendmsg:
                # A backend timed out.  Rinse, repeat.
                sys.stderr.write("  *** Backend time out\n")
                pass
            else:
                break
        except NETWORK_ERRORS as e:
            log_network_error(e, url)
        sleep_with_banner(repeatsleep)

    return (code, json.loads(body))


def myip_shodan(testing, **kwargs):
    url = "https://api.shodan.io/tools/myip"
    sys.stderr.write("Inquiring shodan.io on my IP address...\n")
    if testing:
        return (200, "45.56.111.4")

    with open(os.path.expanduser("~/.shodan")) as f:
        shodan_key = f.read().strip()

    return resilient_send(request.Request(url,
                parse.urlencode((
                        ("key", shodan_key),
                    )).encode("ascii")),
                timeout=kwargs.get("timeout", SHODAN_TIMEOUT),
                repeatsleep=kwargs.get("repeatsleep", REPEAT_SLEEP),
                debuglevel=kwargs.get("debuglevel", 0))


def info_shodan(testing, **kwargs):
    url = "https://api.shodan.io/api-info"
    sys.stderr.write("Inquiring shodan.io on API usage limits...\n")
    if testing:
        return (200, {"https": False,
             "monitored_ips": 8586,
             "plan": "dev",
             "query_credits": 10,
             "scan_credits": 100,
             "telnet": False,
             "unlocked": True,
             "unlocked_left": 10,
             "usage_limits": {"monitored_ips": 16,
                              "query_credits": 100,
                              "scan_credits": 100}})

    with open(os.path.expanduser("~/.shodan")) as f:
        shodan_key = f.read().strip()

    return resilient_send(request.Request(url,
                parse.urlencode((
                        ("key", shodan_key),
                    )).encode("ascii")),
                timeout=kwargs.get("timeout", SHODAN_TIMEOUT),
                repeatsleep=kwargs.get("repeatsleep", REPEAT_SLEEP),
                debuglevel=kwargs.get("debuglevel", 0))


def search_shodan(testing, page, **kwargs):
    url = "https://api.shodan.io/shodan/host/search"
    argsmap = (
            ("product", "product"),
            ("component", "http.component"),
            ("country", "country"),
            ("ip", "ip"),
        )
    querypieces = []
    query = kwargs.get("query")
    if query is not None:
        querypieces.append(query)
    for (funcarg, shodanarg) in argsmap:
        funcval = kwargs.get(funcarg)
        if funcval is not None:
            querypieces.append("{key}:{value}".format(key=shodanarg, value=funcval))
    queryargvalue = " ".join(querypieces)
    sys.stderr.write("Inquiring shodan.io with \"%s\" (page %d)...\n" % (queryargvalue, page,))

    if testing:
        if page > 1:
            return (200, {"matches": []})

        qlow =  queryargvalue.lower()
        if "mikrotik" in qlow:
            return (200, {"matches": [{
                        "product": "MikroTik http proxy",
                        "ip": 2917626385,
                        "port": 8080
                        }, {
                        "product": "MikroTik http proxy",
                        "ip": 3494743649,
                        "port": 8080
                        }]})
        elif "avtech" in qlow:
            return (200, {"matches": [{
                    "product": "Avtech AVN801 network camera",
                    "ip": 1805602870,
                    "port": 88
                }, {
                    "product": "Avtech AVN801 network camera",
                    "ip": 412990438,
                    "port": 8888
                }, {
                    "product": "Avtech AVN801 network camera",
                    "ip": 2264972081,
                    "port": 88
                    }]})
        elif "ip:" in qlow:
            return (200, {
                  "matches": [
                    {
                      "ip": 386931311,
                      "port": 9090,
                      "product": "Avtech AVN801 network camera",
                      "http": {
                      },
                    },
                    {
                      "ip": 3639140288,
                      "port": 8443,
                      "ssl": {
                      },
                      "http": {
                      },
                    },
                    {
                      "ip": 3639140288,
                      "port": 1723,
                    },
                    {
                      "product": "MikroTik http proxy",
                      "ip": 2925431185,
                      "port": 8080,
                      "http": {
                      },
                    },
                  ],
                  "total": 4
                })
        else:
            raise Usage("Only MikroTik and AVTech products, as well as IP lookups, are mocked as Shodan results")

    with open(os.path.expanduser("~/.shodan")) as f:
        shodan_key = f.read().strip()

    return resilient_send(request.Request("%s?%s" % (url,
                parse.urlencode((
                        ("key", shodan_key),
                        ("query", queryargvalue),
                        ("page", page),
                    ))),
                    method="GET"),
                timeout=kwargs.get("timeout", SHODAN_TIMEOUT),
                repeatsleep=kwargs.get("repeatsleep", REPEAT_SLEEP),
                debuglevel=kwargs.get("debuglevel", 0))


def whoseip(ip, whoserole, debuglevel=0):
    r"""
    Obtain email addresses of a given role for the given IP address.

    >>> whoseip('71.17.138.152', 'abuse')
    ['abuse@sasktel.net']

    >>> whoseip('109.87.56.48', 'abuse')
    ['abuse@triolan.com.ua']

    >>> whoseip('76.67.127.81', 'abuse')
    ['abuse@sympatico.ca', 'abuse@bell.ca']

    >>> whoseip('24.84.44.189', 'abuse')
    ['internet.abuse@sjrb.ca']
    """

    def get_roles_addresses(entities):
        er = [(e.get("roles", []),
                dict([(k, v) for (k, obj, kind, v) in e.get("vcardArray", [None, []])[1]]))
            for e in entities]
        for e in entities:
            if "entities" in e:
                er.extend(get_roles_addresses(e["entities"]))
        return er

    emails = []
    url = "https://rdap.arin.net/bootstrap/ip/%s" % (ip,)
    (code, whoseobj) = resilient_send(request.Request(url), debuglevel=debuglevel)

    try:
        entroles = get_roles_addresses(whoseobj["entities"])
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
    if os.path.exists(sent_name):
        with open(os.path.expanduser(sent_name)) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                (email, iptext) = line.split(None, 1)
                if email.endswith(":"):
                    email = email[:-1]
                ips = []
                for ipstr in iptext.split():
                    if ipstr.endswith(","):
                        ipstr = ipstr[:-1]
                    ips.append(ip_address(ipstr))
                sent_emails[email] = ips
    return sent_emails


def write_sent_emails(testing, to_myself_only, sent_name, sent_emails):
    if testing or to_myself_only:
        return
    with open(os.path.expanduser(sent_name), "w") as f:
        for e in sorted(sent_emails.keys()):
            ehosts = sent_emails[e]
            f.write("%s: %s\n" % (e, ", ".join(str(ehost) for ehost in ehosts)))


def build_httpfilter(macro):
    httpfilter = []
    if macro is None:
        pass
    elif macro == CHECK_COINHIVE:
        httpfilter.append(("/", (), "coinhive"))
    elif macro == WEAK_AVTECH:
        avtech_path = "/cgi-bin/nobody/Machine.cgi?action=get_capability"
        avtech_headers = ((b"Authorization", b"Basic %s" % (base64.b64encode(b"admin:admin"),)),)
        avtech_bodysearch = "Firmware.Version"
        httpfilter.append((avtech_path, (), avtech_bodysearch))
        httpfilter.append((avtech_path, avtech_headers, avtech_bodysearch))
    else:
        raise Usage("Unknown macro \"%s\"" % (macro,))
    return httpfilter


def check(httpfilter, baseurl, opener, findings=None):
    if len(httpfilter) == 0:
        # Assume the host vulnerable in the absence of HTTP checks
        return True

    for (path_info, headers, bodysearch) in httpfilter:
        body = ""
        url = baseurl + path_info
        try:
            req = request.Request(url)
            for (name, value) in headers:
                req.add_header(name, value)
            with opener.open(req, timeout=URL_TIMEOUT) as response:
                (code, body) = process_http_response(response, True)
        except HTTPError as e:
            (code, body) = process_http_error(e, True)
        except NETWORK_ERRORS as e:
            log_network_error(e, url)
            return False

        if bodysearch.lower() in body.lower():
            finding = "Got {bodysearch!r} in {url}{headersinfo}".format(bodysearch=bodysearch,
                url=url,
                headersinfo=(" with default %s" % (headers[0][0].decode("ascii"),) if len(headers) > 0 else ""))
            if findings is None:
                sys.stderr.write("  %s\n" % (finding,))
            else:
                findings.append(finding)
            return True

    sys.stderr.write("  *** The product appears protected at %s\n" % (baseurl,))
    return False


def log_hosts(testing, hosts, openers, httpfilters, debuglevel=0):
    logs = []
    for hostrec in hosts:
        host = ip_address(hostrec["ip"])
        port = hostrec["port"]
        is_ssl = "ssl" in hostrec
        url = "http%s://%s:%s" % ("s" if is_ssl else "", host, port)
        sys.stderr.write("  %s\n" % (url,))

        product = hostrec.get("product", "").lower()
        if "avtech" in product:
            macro = WEAK_AVTECH
            vuln = "Weak AVTech"
        elif "mikrotik" in product:
            macro = CHECK_COINHIVE
            vuln = "Infected MikroTik"
        else:
            sys.stderr.write("    %s\n" % ("No product" if product is None
                else "Unexpected product %s" % (product,)))
            continue
        httpfilter = httpfilters[macro]
        findings = []
        ts = local_timestamp()
        if check(httpfilter, url, openers[is_ssl], findings):
            if isinstance(host, (IPv4Address, IPv6Address)):
                ip = host
            else:
                # isinstance(host, str)
                # Convert both 'xx.xx.xx.xx' and 'HOSTNAME' to
                # ipaddress.IPvXAddress for soring.
                ipstr = socket.gethostbyname(str(host))
                ip = ip_address(ipstr)
            logrec = "{ip!s:>15} {ts} {vuln:<17} {finds}".format(ip=ip,
                    ts=ts,
                    vuln=vuln,
                    finds=", ".join(findings))
            logs.append((ip, logrec))
            sys.stderr.write("    %s\n" % (logrec,))
    return logs


def record_hosts(testing, hosts, openers, httpfilter, ready_emails, all_emails, debuglevel=0):
    page_emails = {}

    for (host, port, is_ssl) in hosts:
        sys.stderr.write("%s\n" % (host,))
        url = "http%s://%s:%s" % ("s" if is_ssl else "", host, port)

        if check(httpfilter, url, openers[is_ssl]):
            found_emails = False
            if isinstance(host, (IPv4Address, IPv6Address)):
                ip = host
            else:
                # isinstance(host, str)
                # Convert both 'xx.xx.xx.xx' and 'HOSTNAME' to
                # ipaddress.IPvXAddress for soring.
                ipstr = socket.gethostbyname(str(host))
                ip = ip_address(ipstr)
            for e in whoseip(ip, "abuse"):
                found_emails = True
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

            if not found_emails:
                sys.stderr.write("  *** No abuse notification emails found\n")

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


def extract_thing(shodanquery):
    if shodanquery:
        pieces = shodanquery.split()
        thing_pieces = []
        for piece in pieces:
            if ":" not in piece:
                thing_pieces.append(piece)
        return " ".join(thing_pieces)
    else:
        return ""


def send_logs_mail(testing,
        myaddr, to_myself_only, myipaddr,
        rerun, logs):
    if len(logs) == 0:
        if to_myself_only:
            sys.stderr.write("Nothing to send by email for %s (to myself).\n" % (rerun,))
        return
    if testing:
        sys.stderr.write("Testing email for %s by sending it just to myself...\n" % (rerun,))
    else:
        sys.stderr.write("Sending email for %s%s...\n" % (rerun, 
                " to myself" if to_myself_only else ""))
    msg = MIMEText("""
Hello {rerun},

The following address(es) appeared vulnerable to abuse and botnets, according
to the requests shown below.  This initiative sent the requests from the IP
address {myipaddr}.

  {logstr}

Legend:

    Weak AVTech: attackers may discover (or already discovered) a chance to
    take control of the device due to a weakness in the firmware or leaving
    the default password unchanged.

        https://seclists.org/bugtraq/2016/Oct/26

        https://www.exploit-db.com/exploits/40500

    Infected MikroTik: attackers already discovered a weakness in the device by
    taking control of it and setting up Coinhive in its HTML code.  This
    finding is not exhaustive.  There may be other vulnerable routers or
    routers that were infected but whose attackers did not set up Coinhive.

        https://www.zdnet.com/article/mikrotik-routers-enslaved-in-massive-coinhive-cryptojacking-campaign/

        https://www.securityweek.com/remotely-exploitable-vulnerability-discovered-mikrotiks-routeros

    None of these findings imply that the owners of the devices were
    responsible for malicious activities.  Instead, they became or may become
    victims of remote attacks.  Once successful, the attackers take control of
    the device and use it for other activities.

Best regards,

A community cleanup initiative
https://github.com/frantic-search/community-cleanup
""".format(rerun=rerun,
    myipaddr=myipaddr,
    logstr="\n  ".join(logrec for (ip, logrec) in sorted(logs))))

    recipients = [myaddr]
    if not testing and not to_myself_only:
        recipients.append(rerun)
    msg["Subject"] = "%sCommunity cleanup checking back" % ("TESTING: " if testing else "",)
    msg["From"] = myaddr
    msg["To"] = rerun
    s = smtplib.SMTP("localhost")
    s.sendmail(myaddr, recipients, msg.as_string())
    s.quit()


def send_mail(testing,
        ready_emails, myaddr, to_myself_only,
        shodanquery, product, component, macro):
    if len(ready_emails) == 0:
        sys.stderr.write("Nothing to send by email from the last few pages of the results.\n")
        return
    if macro == WEAK_AVTECH:
        prodname = "AVTech"
    elif product:
        prodname = product
    else:
        prodname = extract_thing(shodanquery) or "internet thing"

    if macro == CHECK_COINHIVE:
        vulnerability = "showing Coinhive"
    elif macro == WEAK_AVTECH:
        vulnerability = "exhibiting known exploits or factory-defined authentication"
    elif component:
        vulnerability = "running \"%s\"" % (component,)
    else:
        vulnerability = None
    for e in sorted(ready_emails.keys()):
        if testing:
            sys.stderr.write("Testing email for %s by sending it just to myself...\n" % (e,))
        else:
            sys.stderr.write("Sending an email for %s%s...\n" % (e,
                    " to myself" if to_myself_only else ""))
        ehosts = ready_emails[e]
        msg = MIMEText("""
Hello %s,

Your %s at the following address(es) appeared vulnerable to abuse and botnets%s:

  %s

Best regards,

A community cleanup initiative
https://github.com/frantic-search/community-cleanup
""" % (e, prodname,
    "" if vulnerability is None else "\nbecause of %s" % (vulnerability,),
    "\n  ".join(str(ehost) for ehost in ehosts)))

        recipients = [myaddr]
        if not testing and not to_myself_only:
            recipients.append(e)
        msg["Subject"] = "%sCommunity cleanup: your %s needs attention" % ("TESTING: " if testing else "",
                prodname,)
        msg["From"] = myaddr
        msg["To"] = e
        s = smtplib.SMTP("localhost")
        s.sendmail(myaddr, recipients, msg.as_string())
        s.quit()


def chunks(seq, n):
    """
    Yield successive n-sized chunks from seq.

    >>> tuple(chunks(range(14), 3))
    ((0, 1, 2), (3, 4, 5), (6, 7, 8), (9, 10, 11), (12, 13))

    >>> tuple(chunks(range(12), 3))
    ((0, 1, 2), (3, 4, 5), (6, 7, 8), (9, 10, 11))
    """
    it = iter(seq)
    while True:
        chunk = []
        for i in range(n):
            try:
                chunk.append(next(it))
            except StopIteration:
                if i > 0:
                    yield tuple(chunk)
                return
        yield tuple(chunk)


def recheck(testing, rerun, ips,
        myaddr, myipaddr, to_myself_only,
        openers, httpfilters,
        debuglevel):
    if testing:
        ips = tuple(ip_address(ip) for ip in TEST_IPS)
    logs = []
    continue_chunks = True
    for ips_chunk in chunks(ips, IPS_LIMIT):
        ips_chunk_str = ",".join(str(ip) for ip in ips_chunk)
        page = 1
        while True:
            (shodan_code, shodan_results) = search_shodan(testing, page,
                    ip=ips_chunk_str,
                    debuglevel=debuglevel,
                    timeout=SHODAN_LARGE_TIMEOUT)
            if shodan_code != 200:
                sys.stderr.write("Unexpected Shodan code %d, response:\n%s\n" % (shodan_code, pformat(shodan_results),))
                continue_chunks = False
                break
            nummatches = len(shodan_results["matches"])
            if nummatches == 0:
                sys.stderr.write("  No more matches\n")
                break
            # sys.stderr.write("  Found matches: {nummatches}\n".format(nummatches=nummatches))
            hosts = tuple(match for match in shodan_results["matches"]
                        if "http" in match)
            numhosts = len(hosts)
            sys.stderr.write("  Found HTTP(S) services: {numhosts}"
                    " (out of {nummatches} matches)\n".format(numhosts=numhosts,
                        nummatches=nummatches))
            logs.extend(log_hosts(testing, hosts, openers, httpfilters, debuglevel=debuglevel))
            page += 1
        if not continue_chunks:
            break
    send_logs_mail(testing, myaddr, to_myself_only, myipaddr, rerun, logs)


def search_and_mail(testing, checkurl,
        shodanquery, product, country, component, macro, 
        all_emails, sent_name, myaddr, to_myself_only,
        httpfilter, openers, 
        debuglevel):
    ready_emails = {}
    if checkurl is None:
        page = 1
        page_sender_count = 0
        while True:
            (shodan_code, shodan_limits) = info_shodan(testing, debuglevel=debuglevel)
            sys.stderr.write("Shodan code %d, limits:\n%s\n" % (shodan_code, pformat(shodan_limits),))
            if shodan_code != 200:
                break

            (shodan_code, shodan_results) = search_shodan(testing, page,
                    query=shodanquery,
                    product=product, country=country, component=component,
                    debuglevel=debuglevel)
            if shodan_code != 200:
                sys.stderr.write("Unexpected Shodan code %d, response:\n%s\n" % (shodan_code, pformat(shodan_results),))
                break

            nummatches = len(shodan_results["matches"])
            if nummatches == 0:
                sys.stderr.write("  No more matches\n")
                break
            # sys.stderr.write("  Found matches in page {page}: {nummatches}\n".format(page=page, 
            #         nummatches=nummatches))
            hosts = tuple((ip_address(match["ip"]), match["port"], "ssl" in match)
                    for match in shodan_results["matches"]
                        if "http" in match)
            numhosts = len(hosts)
            sys.stderr.write("  Found HTTP(S) services: {numhosts}"
                    " (out of {nummatches} matches)\n".format(numhosts=numhosts,
                        nummatches=nummatches))

            record_hosts(testing, hosts, openers, httpfilter, ready_emails, all_emails, debuglevel=debuglevel)
            page += 1
            page_sender_count += 1
            if page_sender_count == SEND_PAGES:
                send_mail(testing, ready_emails, myaddr, to_myself_only,
                        shodanquery, product, component, macro)
                write_sent_emails(testing, to_myself_only, sent_name, all_emails)
                ready_emails = {}
                page_sender_count = 0
    else:
        urlobj = parse.urlparse(checkurl)
        record_hosts(testing,
                ((urlobj.hostname, urlobj.port, urlobj.scheme == "https"),),
                openers,
                httpfilter,
                ready_emails, all_emails, debuglevel=debuglevel)

    send_mail(testing, ready_emails, myaddr, to_myself_only,
            shodanquery, product, component, macro)
    write_sent_emails(testing, to_myself_only, sent_name, all_emails)


class AutoFlush:
    def __init__(self, out):
        self._out = out

    def write(self, s):
        self._out.write(s)
        self._out.flush()

    def __getattr__(self, attrname):
        return getattr(self._out, attrname)


def wrap_once(o, cls):
    if isinstance(o, cls):
        return o
    else:
        return cls(o)


def next_arg(argv, i):
    i += 1
    if i >= len(argv):
        raise Usage()
    return (i, argv[i])


def main(argv):
    sys.stdout = wrap_once(sys.stdout, AutoFlush)
    sys.stderr = wrap_once(sys.stderr, AutoFlush)

    unittesting = False
    debuglevel = 0
    testing = False
    to_myself_only = False
    shodanquery = None
    product = None
    country = None
    component = None
    macro = None
    checkurl = None
    rerun = None
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "-d":
            debuglevel = 1
        elif arg == "-t":
            testing = True
        elif arg == "--to-myself-only":
            to_myself_only = True
        elif arg == "-u":
            unittesting = True
        elif arg == "--query":
            (i, shodanquery) = next_arg(argv, i)
        elif arg == "--product":
            (i, product) = next_arg(argv, i)
        elif arg == "--country":
            (i, country) = next_arg(argv, i)
        elif arg == "--component":
            (i, component) = next_arg(argv, i)
        elif arg == "--macro":
            (i, macro) = next_arg(argv, i)
        elif arg == "--url":
            (i, checkurl) = next_arg(argv, i)
        elif arg == "--rerun":
            (i, rerun) = next_arg(argv, i)
        elif arg.startswith("-"):
            raise Usage()
        else:
            break
        i += 1

    if unittesting:
        import doctest
        (failures, tests) = doctest.testmod(verbose=(not not debuglevel))
        raise SystemExit(0 if failures == 0 else 1 + (failures % 127))

    if not (rerun or shodanquery or product or country or component or macro):
        raise Usage()

    if rerun:
        if shodanquery or product or country or component or macro:
            raise Usage("The --rerun argument overrides Shodan search")
    else:
        if checkurl:
            if shodanquery or product or country or component:
                raise Usage("The --url argument overrides Shodan search")
        else:
            if not (shodanquery or product or country or component):
                raise Usage("The search will benefit from using a condition")

    myaddr = "\"Community Cleanup Initiative\" <community_cleanup@yahoo.com>"
    sent_name = "email-hosts.txt"
    all_emails = read_sent_emails(sent_name)

    httpfilters = {}
    for m in (None,) + MACROS:
        httpfilters[m] = build_httpfilter(m)
    httpfilter = httpfilters[macro]

    openers = {}
    for is_ssl in (False, True):
        if is_ssl:
            handler = request.HTTPSHandler(debuglevel=debuglevel, context=ssl._create_unverified_context(), check_hostname=False)
        else:
            handler = request.HTTPHandler(debuglevel=debuglevel)
        openers[is_ssl] = request.build_opener(handler)

    if rerun:
        (shodan_code, shodan_limits) = info_shodan(testing, debuglevel=debuglevel)
        sys.stderr.write("Shodan code %d, limits:\n%s\n" % (shodan_code, pformat(shodan_limits),))
        if shodan_code == 200:
            (shodan_code, myip) = myip_shodan(testing, debuglevel=debuglevel)
            if shodan_code == 200:
                sys.stderr.write("My IP: %s\n" % (myip,))
                myipaddr = ip_address(myip)
                if rerun in all_emails:
                    recheck(testing, rerun, all_emails[rerun],
                            myaddr, myipaddr, to_myself_only,
                            openers, httpfilters, debuglevel)
                else:
                    emailpat = re.compile(rerun)
                    for e in sorted(all_emails.keys()):
                        if emailpat.match(e):
                            recheck(testing, e, all_emails[e],
                                    myaddr, myipaddr, to_myself_only,
                                    openers, httpfilters, debuglevel)
    else:
        search_and_mail(testing, checkurl,
                shodanquery, product, country, component, macro, 
                all_emails, sent_name, myaddr, to_myself_only,
                httpfilter, openers,
                debuglevel)


if __name__ == "__main__":
    import sys
    # Wrapping parameter parsing into a function call prevents from spilling
    # them into the global namespace and accidentally using them in the other
    # functions.
    main(sys.argv)

