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

    python3 {script} -t --query "http.status:200 country:CA" \
            --component jenkins --macro {WEAK_JENKINS}

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

from collections import namedtuple
from urllib import request, parse
from urllib.error import HTTPError, URLError
from http.client import BadStatusLine, CannotSendRequest
from http import HTTPStatus
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
WEAK_JENKINS = "weak_jenkins"
MACROS = (CHECK_COINHIVE, WEAK_AVTECH, WEAK_JENKINS)
MACRO_VULNS = {
        CHECK_COINHIVE: "Infected MikroTik",
        WEAK_AVTECH: "Weak AVTech",
        WEAK_JENKINS: "Weak Jenkins"
    }
MACRO_SMELLS = {
        CHECK_COINHIVE: "showing Coinhive",
        WEAK_AVTECH: "exhibiting known exploits or factory-defined authentication",
        WEAK_JENKINS: "showing Jenkins jobs"
    }
MACRO_PRODUCTS = {
        CHECK_COINHIVE: "MikroTik",
        WEAK_AVTECH: "AVTech",
        WEAK_JENKINS: "Jenkins"
    }
MACRO_FIXTURES = {
        CHECK_COINHIVE: [{
                "ip": 2917626385,
                "port": 8080,
                "http": {},
                "product": "MikroTik http proxy",
            }, {
                "ip": 3494743649,
                "port": 8080,
                "http": {},
                "product": "MikroTik http proxy",
            }],
        WEAK_AVTECH: [{
                "ip": 1805602870,
                "port": 88,
                "product": "Avtech AVN801 network camera",
            }, {
                "ip": 412990438,
                "port": 8888,
                "http": {},
                "product": "Avtech AVN801 network camera",
            }, {
                "ip": 2264972081,
                "port": 88,
                "http": {},
                "product": "Avtech AVN801 network camera",
                }],
        WEAK_JENKINS: [{
                "ip": "35.183.208.63",
                "port": 8080,
                "http": {},
                "product": "Jenkins",
            }]
    }
IP_SEARCH_FIXTURES = [
        {
            "ip": 386931311,
            "port": 9090,
            "http": {},
            "product": "Avtech AVN801 network camera",
        },
        {
            "ip": 3639140288,
            "port": 8443,
            "http": {},
            "ssl": {},
        },
        {
            "ip": 3639140288,
            "port": 1723,
        },
        {
            "ip": 2925431185,
            "port": 8080,
            "http": {},
            "product": "MikroTik http proxy",
        },
        {
            "ip": "35.183.208.63",
            "port": 8080,
            "http": {},
            "product": "Jetty",
        }
    ]
MACRO_LEGENDS = {
        CHECK_COINHIVE: """Adversaries discovered a weakness in the device by
    taking control of it and setting up Coinhive in its HTML code.  This
    finding is not exhaustive.  There may be other vulnerable routers or
    routers that were infected but whose attackers did not set up Coinhive.

        https://www.zdnet.com/article/mikrotik-routers-enslaved-in-massive-coinhive-cryptojacking-campaign/

        https://www.securityweek.com/remotely-exploitable-vulnerability-discovered-mikrotiks-routeros""",

        WEAK_AVTECH: """Adversaries may discover (or already discovered) a
    chance to take control of the device due to a weakness in the firmware
    or leaving the default password unchanged.

        https://seclists.org/bugtraq/2016/Oct/26

        https://www.exploit-db.com/exploits/40500""",

        WEAK_JENKINS: """Jenkins servers left without a password protection
    allow downloading source code, configuration files and build results.
    The server software and its plugins may have vulnerabilities of varying
    severities.

        https://www.jenkins.io/security/advisories/"""
    }
RESERVATION = """None of these findings imply that the owners of the devices or machines
    were responsible for malicious activities.  Instead, they became or may
    become victims of remote attacks.  Once successful, the attackers take
    control of the device and use it for other activities."""


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
            WEAK_JENKINS=WEAK_JENKINS,
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
        if ((code < HTTPStatus.OK) or (code >= HTTPStatus.BAD_REQUEST)) and not quiet:
            sys.stderr.write("  *** HTTP response to {url}: code {code}, body {body!r}...\n".format(url=e.geturl(),
                    code=e.getcode(), body=body[:20]))
    return (code, body)


process_http_response = process_http_error


def log_network_error(e, url):
    sys.stderr.write("  *** Network {classname} in {url}\n".format(classname=e.__class__.__name__,
        url=url))


def log_error(e, url):
    sys.stderr.write("  *** {classname} in {url}\n".format(classname=e.__class__.__name__,
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
    # Verify SSL certificates and host names
    handler = handlerclass(debuglevel=debuglevel)
    opener = request.build_opener(handler)
    # rdap.org does not like Python agents
    opener.addheaders = [(header, value)
                     for header, value in opener.addheaders
                     if header.lower() != 'user-agent'] 

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
            elif "Request rate limit reached" in backendmsg:
                sys.stderr.write("  *** Rate limit reached\n")
                pass
            else:
                break
        except NETWORK_ERRORS as e:
            log_network_error(e, url)
        sleep_with_banner(repeatsleep)

    try:
        return (code, json.loads(body))
    except json.decoder.JSONDecodeError as e:
        # log_error(e, url + " with response " + body)
        return (code, {"body": body})


# https://blog.cloudflare.com/rfc8482-saying-goodbye-to-any/
def getipaddr(host, port=None):
    if isinstance(host, (IPv4Address, IPv6Address)):
        return host
    # isinstance(host, str)
    # Convert both 'xx.xx.xx.xx' and 'HOSTNAME' to
    # ipaddress.IPvXAddress for sorting.
    for tryfamily in (socket.AddressFamily.AF_INET, socket.AddressFamily.AF_INET6):
        try:
            for (fam, typ, proto, cname, sockaddr) in socket.getaddrinfo(host, port, tryfamily, socket.SocketKind.SOCK_STREAM):
                (addr, port) = sockaddr[:2]
                return ip_address(addr)
        except socket.gaierror as e:
            log_network_error(e, host)
            continue
    return host


def myip_shodan(testing, **kwargs):
    url = "https://api.shodan.io/tools/myip"
    sys.stderr.write("Inquiring shodan.io on my IP address...\n")
    if testing:
        return (HTTPStatus.OK, "45.56.111.4")

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
        return (HTTPStatus.OK, {"https": False,
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
    def shodan_jenkins_fixup(kw):
        if kw.get("component") == "jenkins":
            del kw["component"]
            q = kw.get("query")
            if q is None:
                q = "x-jenkins"
            else:
                q = "%s %s" % (q, "x-jenkins")
            kw["query"] = q

    shodan_fixups = (shodan_jenkins_fixup,)
    # Avoid changing the caller's dictionary
    kw = dict(kwargs)
    for shodan_fixup in shodan_fixups:
        shodan_fixup(kw)
    querypieces = []
    query = kw.get("query")
    if query is not None:
        querypieces.append(query)
    for (funcarg, shodanarg) in argsmap:
        funcval = kw.get(funcarg)
        if funcval is not None:
            querypieces.append("{key}:{value}".format(key=shodanarg, value=funcval))
    queryargvalue = " ".join(querypieces)
    sys.stderr.write("Inquiring shodan.io with \"%s\" (page %d)...\n" % (queryargvalue, page,))

    if testing:
        if page > 1:
            return (HTTPStatus.OK, {"matches": []})
        qlow = queryargvalue.lower()
        for macro in MACROS:
            macrolow = MACRO_PRODUCTS[macro].lower()
            if macrolow in qlow:
                return (HTTPStatus.OK, {"matches": MACRO_FIXTURES[macro]})
        if "ip:" in qlow:
            return (HTTPStatus.OK, {
              "matches": IP_SEARCH_FIXTURES,
              "total": len(IP_SEARCH_FIXTURES)
            })
        else:
            raise Usage("Only products {products}, as well as IP lookups, are mocked as Shodan results"
                    .format(products=", ".join(sorted(MACRO_PRODUCTS.keys()))))

    with open(os.path.expanduser("~/.shodan")) as f:
        shodan_key = f.read().strip()

    return resilient_send(request.Request("%s?%s" % (url,
                parse.urlencode((
                        ("key", shodan_key),
                        ("query", queryargvalue),
                        ("page", page),
                    ))),
                    method="GET"),
                timeout=kw.get("timeout", SHODAN_TIMEOUT),
                repeatsleep=kw.get("repeatsleep", REPEAT_SLEEP),
                debuglevel=kw.get("debuglevel", 0))



# https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8
IPV4SEG  = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
IPV4ADDR = r'(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')'
IPV6SEG  = r'(?:(?:[0-9a-fA-F]){1,4})'
IPV6GROUPS = (
    r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,                  # 1:2:3:4:5:6:7:8
    r'(?:' + IPV6SEG + r':){1,7}:',                           # 1::                                 1:2:3:4:5:6:7::
    r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,                 # 1::8               1:2:3:4:5:6::8   1:2:3:4:5:6::8
    r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',  # 1::7:8             1:2:3:4:5::7:8   1:2:3:4:5::8
    r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',  # 1::6:7:8           1:2:3:4::6:7:8   1:2:3:4::8
    r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',  # 1::5:6:7:8         1:2:3::5:6:7:8   1:2:3::8
    r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',  # 1::4:5:6:7:8       1:2::4:5:6:7:8   1:2::8
    IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',             # 1::3:4:5:6:7:8     1::3:4:5:6:7:8   1::8
    r':(?:(?::' + IPV6SEG + r'){1,7}|:)',                     # ::2:3:4:5:6:7:8    ::2:3:4:5:6:7:8  ::8       ::
    r'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',       # fe80::7:8%eth0     fe80::7:8%1  (link-local IPv6 addresses with zone index)
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,     # ::255.255.255.255  ::ffff:255.255.255.255  ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r'(?:' + IPV6SEG + r':){1,4}:[^\s:]' + IPV4ADDR,          # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
)
IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])  # Reverse rows for greedy match

IPV4ADDR_COMPILED = re.compile(IPV4ADDR)
IPV6ADDR_COMPILED = re.compile(IPV6ADDR)

RDAP_BOOTSTRAP = "https://rdap.org"

def whoseip(ip, whoserole, debuglevel=0):
    r"""
    Obtain email addresses of a given role for the given IP address.

    >>> print('#'); whoseip('71.17.138.152', 'abuse', debuglevel)
    #
    ...['sasktel.wanec@sasktel.com']

    >>> whoseip('109.87.56.48', 'abuse')
    ['abuse@triolan.com.ua']

    >>> whoseip('76.67.127.81', 'abuse')
    ['abuse@sympatico.ca', 'abuse@bell.ca']

    >>> whoseip('24.84.44.189', 'abuse')
    ['ipadmin@sjrb.ca']

    >>> whoseip('199.19.213.77', 'abuse')
    ['mnaser@vexxhost.com']

    >>> whoseip('build.automotivelinux.org', 'abuse')
    ['abuse@enom.com']

    >>> whoseip('104.31.68.51', 'abuse')
    ['abuse@cloudflare.com']

    >>> whoseip('68.183.197.228', 'abuse')
    ['abuse@digitalocean.com']

    >>> whoseip('ci.jwfh.ca', 'abuse')
    []
    """

    def get_roles_addresses(entities):
        er = [(e.get("roles", []), e.get("remarks", []),
                dict([(k, v) for (k, obj, kind, v) in e.get("vcardArray", [None, []])[1]]))
            for e in entities]
        for e in entities:
            if "entities" in e:
                er.extend(get_roles_addresses(e["entities"]))
        return er

    if IPV4ADDR_COMPILED.match(ip) or IPV6ADDR_COMPILED.match(ip):     
        url = "%s/ip/%s" % (RDAP_BOOTSTRAP, ip,)
        (code, whoseobj) = resilient_send(request.Request(url), debuglevel=debuglevel)
        if code != HTTPStatus.OK:
            return []
    else:
        splits = ip.split(".")
        while True:
            if len(splits) < 2:
                return []
            domain = ".".join(splits)
            url = "%s/domain/%s" % (RDAP_BOOTSTRAP, domain,)
            (code, whoseobj) = resilient_send(request.Request(url), debuglevel=debuglevel)
            if code != HTTPStatus.OK:
                del splits[0]
            else:
                break

    try:
        entroles = get_roles_addresses(whoseobj["entities"])
    except (KeyError, IndexError) as e:
        sys.stderr.write("  *** whoseip(%r, %r) %s %s in %s\n" % (ip, whoserole,
                e.__class__.__name__,
                e, pformat(whoseobj)))
        return []
    roleemails = {}
    for roles, remarks, addr in entroles:
        if "email" in addr:
            for remark in remarks:
                if "Unvalidated" in remark["title"]:
                    break
            else:
                email = addr["email"]
                if "@" not in email:
                    # Empty or "EMAIL REDACTED FOR PRIVACY"
                    # sys.stderr.write("  *** whoseip(%r, %r) got an invalid email %r in roles %r\n" % (ip, whoserole,
                    #     email, roles))
                    continue
                for role in roles:
                    if role in roleemails:
                        if email not in roleemails[role]:
                            roleemails[role].append(email)
                    else:
                        roleemails[role] = [email]
    for tryrole in (whoserole, "technical", "administrative"):
        if tryrole in roleemails:
            return roleemails[tryrole]
    return []


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


class HTTPChecker(namedtuple("HTTPChecker", 
        ("path", "headers", "bodysearch", "host_hint_extractor"),
        defaults=(None,))):
    pass


def jenkins_host_extractor(json):
    if "primaryView" in json:
        p = json["primaryView"]
        if "url" in p:
            u = p["url"]
            urlobj = parse.urlparse(u)
            return urlobj.hostname
    return None


def build_httpchecker(macro):
    httpchecker = []
    if macro is None:
        pass
    elif macro == CHECK_COINHIVE:
        httpchecker.append(HTTPChecker(path="/", headers=(), bodysearch="coinhive"))
    elif macro == WEAK_AVTECH:
        avtech_path = "/cgi-bin/nobody/Machine.cgi?action=get_capability"
        avtech_headers = ((b"Authorization", b"Basic %s" % (base64.b64encode(b"admin:admin"),)),)
        avtech_bodysearch = "Firmware.Version"
        httpchecker.append(HTTPChecker(path=avtech_path, headers=(), bodysearch=avtech_bodysearch))
        httpchecker.append(HTTPChecker(path=avtech_path, headers=avtech_headers, bodysearch=avtech_bodysearch))
    elif macro == WEAK_JENKINS:
        jenkins_path = "/api/json"
        jenkins_bodysearch = "\"jobs\""
        httpchecker.append(HTTPChecker(path=jenkins_path, headers=(), bodysearch=jenkins_bodysearch,
            host_hint_extractor=jenkins_host_extractor))
    else:
        raise Usage("Unknown macro \"%s\"" % (macro,))
    return httpchecker


def check(macro, httpchecker, baseurl, opener, findings=None, host_hints=None):
    if len(httpchecker) == 0:
        # Assume the host vulnerable in the absence of HTTP checks
        return True

    for checker in httpchecker:
        body = ""
        url = baseurl + checker.path
        try:
            req = request.Request(url)
            for (name, value) in checker.headers:
                req.add_header(name, value)
            with opener.open(req, timeout=URL_TIMEOUT) as response:
                (code, body) = process_http_response(response, True)
        except HTTPError as e:
            (code, body) = process_http_error(e, True)
        except NETWORK_ERRORS as e:
            log_network_error(e, url)
            return False

        if checker.bodysearch.lower() in body.lower():
            finding = "Got {bodysearch!r} in {url}{headersinfo}".format(bodysearch=checker.bodysearch,
                url=url,
                headersinfo=(" with default %s" % (checker.headers[0][0].decode("ascii"),)
                    if len(checker.headers) > 0 else ""))
            if findings is not None:
                findings.append(finding)
            if ((host_hints is not None) and (len(host_hints) == 0) and
                    (checker.host_hint_extractor is not None)):
                try:
                    body_json = json.loads(body)
                except json.decoder.JSONDecodeError as e:
                    body_json = {}
                    log_error(e, url)
                host_hint = checker.host_hint_extractor(body_json)
                if host_hint is not None:
                    host_hints.append(host_hint)
            sys.stderr.write("  %s\n" % (finding,))
            return True

    sys.stderr.write("  *** The product appears protected against %s at %s\n" % (macro, baseurl,))
    return False


# https://stackoverflow.com/questions/390250/elegant-ways-to-support-equivalence-equality-in-python-classes
class HostLog(namedtuple("HostLog", ("ip", "ts", "vuln", "findings"))):
    # https://docs.python.org/3/library/collections.html#collections.namedtuple
    __slots__ = ()
    def __str__(self):
        return "{ip!s:>15} {ts} {vuln:<17} {finds}".format(finds = ", ".join(self.findings),
                **self._asdict())


def log_hosts(testing, macro, hosts, openers, httpcheckers, debuglevel=0):
    logs = []
    found_macros = {}
    for hostrec in hosts:
        host = ip_address(hostrec["ip"])
        port = hostrec["port"]
        is_ssl = "ssl" in hostrec
        url = "http%s://%s:%s" % ("s" if is_ssl else "", host, port)
        sys.stderr.write("  %s\n" % (url,))

        product = hostrec.get("product", "").lower()
        guessed = False
        if macro is None:
            check_macros = MACROS
        else:
            check_macros = [macro]
        for check_macro in check_macros:
            product_guess = MACRO_PRODUCTS[check_macro].lower()
            if (macro is not None) or (product_guess in product) or (len(product.strip()) == 0):
                guessed = True
                vuln = MACRO_VULNS[check_macro]
            else:
                continue
            httpchecker = httpcheckers[check_macro]
            findings = []
            ts = local_timestamp()
            if check(check_macro, httpchecker, url, openers[is_ssl], findings):
                found_macros[check_macro] = 1
                ip = getipaddr(host, port)
                # Not looking up owners of the host name "host" here as this
                # method "log_hosts" is only used to "recheck" IP addresses
                # already nested by their owner email addresses.
                hostlog = HostLog(ip, ts, vuln, findings)
                logs.append(hostlog)
                sys.stderr.write("    %s\n" % (hostlog,))
        if not guessed:
            sys.stderr.write("    %s\n" % ("No product" if product is None
                else "Unexpected product %s" % (product,)))
    return found_macros, logs


def record_hosts(testing, hosts, macro, openers, httpchecker, ready_emaillogs, all_emails, debuglevel=0):
    page_emails = {}

    for (host, port, is_ssl) in hosts:
        sys.stderr.write("%s\n" % (host,))
        url = "http%s://%s%s" % ("s" if is_ssl else "", host, "" if port is None else (":%s" % (port,)))
        findings = []
        host_hints = []
        ts = local_timestamp()

        if check(macro, httpchecker, url, openers[is_ssl], findings, host_hints):
            hosts_to_report = [host]
            if len(host_hints) > 0:
                hosts_to_report.append(host_hints[0])
            found_emails = False
            for rephost in hosts_to_report:
                lookup_name = str(rephost)
                ip = getipaddr(rephost, port)
                for e in whoseip(lookup_name, "abuse", debuglevel):
                    found_emails = True
                    sys.stderr.write("  %s\n" % (e,))
                    page_ehosts = page_emails.get(e, [])
                    ready_ehostlogs = ready_emaillogs.get(e, [])
                    all_ehosts = all_emails.get(e, [])
                    if ip not in all_ehosts:
                        page_ehosts.append(ip)
                        ready_ehostlogs.append(HostLog(ip, ts, MACRO_VULNS[macro], findings))
                        all_ehosts.append(ip)
                        page_emails[e] = page_ehosts
                        ready_emaillogs[e] = ready_ehostlogs
                        all_emails[e] = all_ehosts

            if not found_emails:
                sys.stderr.write("  *** No abuse notification emails found for %s\n" % (host,))

    sys.stderr.write("\n")
    for e in sorted(page_emails.keys()):
        page_ehosts = page_emails[e]
        page_ehosts.sort()
        sys.stderr.write("%s: %s\n" % (e, ", ".join(str(page_ehost) for page_ehost in page_ehosts)))

    for e in sorted(ready_emaillogs.keys()):
        ready_ehostlogs = ready_emaillogs[e]
        ready_ehostlogs.sort()

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
        rerun, matched_macros, logs):
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
    {legend}

Reservation:
    {reservation}

Best regards,

A community cleanup initiative
https://github.com/frantic-search/community-cleanup
""".format(rerun=rerun,
    myipaddr=myipaddr,
    logstr="\n  ".join(str(hostlog) for hostlog in sorted(logs)),
    legend="\n\n".join(("%s: %s" % (MACRO_VULNS[m], MACRO_LEGENDS[m])) for m in matched_macros),
    reservation=RESERVATION))

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
        ready_emaillogs, myaddr, to_myself_only,
        shodanquery, product, component, macro):
    if len(ready_emaillogs) == 0:
        sys.stderr.write("Nothing to send by email from the last few pages of the results.\n")
        return
    if macro in MACRO_PRODUCTS:
        prodname = MACRO_PRODUCTS[macro]
    elif product:
        prodname = product
    else:
        prodname = extract_thing(shodanquery) or "internet thing"

    if macro in MACRO_SMELLS:
        smell = MACRO_SMELLS[macro]
    elif component:
        smell = "running \"%s\"" % (component,)
    else:
        smell = None
    for e in sorted(ready_emaillogs.keys()):
        if testing:
            sys.stderr.write("Testing email for %s by sending it just to myself...\n" % (e,))
        else:
            sys.stderr.write("Sending an email for %s%s...\n" % (e,
                    " to myself" if to_myself_only else ""))
        ehostlogs = ready_emaillogs[e]
        msg = MIMEText("""
Hello {email},

Your {product} at the following address(es) appeared vulnerable to abuse and botnets{because}:

    {logstr}

{legendpiece}Reservation:
    {reservation}

Best regards,

A community cleanup initiative
https://github.com/frantic-search/community-cleanup
""".format(email=e, product=prodname,
    because=("" if smell is None else "\nbecause of %s" % (smell,)),
    logstr="\n    ".join(str(ehostlog) for ehostlog in ehostlogs),
    legendpiece=("Legend:\n    %s\n\n" % (MACRO_LEGENDS[macro],) if macro in MACRO_LEGENDS else ""),
    reservation=RESERVATION))

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


def recheck(testing, macro, rerun, ips,
        myaddr, myipaddr, to_myself_only,
        openers, httpcheckers,
        debuglevel):
    if testing:
        ips = tuple(ip_address(ip) for ip in TEST_IPS)
    logs = []
    matched_macros = {}
    continue_chunks = True
    for ips_chunk in chunks(ips, IPS_LIMIT):
        ips_chunk_str = ",".join(str(ip) for ip in ips_chunk)
        page = 1
        while True:
            (shodan_code, shodan_results) = search_shodan(testing, page,
                    ip=ips_chunk_str,
                    debuglevel=debuglevel,
                    timeout=SHODAN_LARGE_TIMEOUT)
            if shodan_code != HTTPStatus.OK:
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
            matched_chunk_macros, matched_chunk_logs = log_hosts(testing, macro, 
                    hosts, openers, httpcheckers, debuglevel=debuglevel)
            matched_macros.update(matched_chunk_macros)
            logs.extend(matched_chunk_logs)
            page += 1
        if not continue_chunks:
            break
    matched_macros = tuple([m for m in sorted(matched_macros.keys())])
    send_logs_mail(testing, myaddr, to_myself_only, myipaddr, rerun, matched_macros, logs)


def search_and_mail(testing, checkurl,
        shodanquery, product, country, component, macro, 
        all_emails, sent_name, myaddr, to_myself_only,
        httpchecker, openers, 
        debuglevel):
    ready_emaillogs = {}
    if checkurl is None:
        page = 1
        page_sender_count = 0
        while True:
            (shodan_code, shodan_limits) = info_shodan(testing, debuglevel=debuglevel)
            sys.stderr.write("Shodan code %d, limits:\n%s\n" % (shodan_code, pformat(shodan_limits),))
            if shodan_code != HTTPStatus.OK:
                break

            (shodan_code, shodan_results) = search_shodan(testing, page,
                    query=shodanquery,
                    product=product, country=country, component=component,
                    debuglevel=debuglevel)
            if shodan_code != HTTPStatus.OK:
                sys.stderr.write("Unexpected Shodan code %d, response:\n%s\n" % (shodan_code, pformat(shodan_results),))
                break

            nummatches = len(shodan_results["matches"])
            if nummatches == 0:
                sys.stderr.write("  No more matches\n")
                break
            # sys.stderr.write("  Found matches in page {page}: {nummatches}\n".format(page=page, 
            #         nummatches=nummatches))
            # TODO: take the host name from http.host
            # TODO: extract an additional host name hint from http.html (link .. href="..")
            hosts = tuple((ip_address(match["ip"]), match["port"], "ssl" in match)
                    for match in shodan_results["matches"]
                        if "http" in match)
            numhosts = len(hosts)
            sys.stderr.write("  Found HTTP(S) services: {numhosts}"
                    " (out of {nummatches} matches)\n".format(numhosts=numhosts,
                        nummatches=nummatches))

            record_hosts(testing, hosts, macro, openers, httpchecker, ready_emaillogs, all_emails, debuglevel=debuglevel)
            page += 1
            page_sender_count += 1
            if page_sender_count == SEND_PAGES:
                send_mail(testing, ready_emaillogs, myaddr, to_myself_only,
                        shodanquery, product, component, macro)
                write_sent_emails(testing, to_myself_only, sent_name, all_emails)
                ready_emaillogs = {}
                page_sender_count = 0
    else:
        urlobj = parse.urlparse(checkurl)
        record_hosts(testing,
                ((urlobj.hostname, urlobj.port, urlobj.scheme == "https"),),
                macro,
                openers,
                httpchecker,
                ready_emaillogs, all_emails, debuglevel=debuglevel)

    send_mail(testing, ready_emaillogs, myaddr, to_myself_only,
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
        (failures, tests) = doctest.testmod(verbose=(not not debuglevel),
                extraglobs=(('debuglevel', debuglevel),),
                optionflags=doctest.ELLIPSIS)
        raise SystemExit(0 if failures == 0 else 1 + (failures % 127))

    if not (rerun or shodanquery or product or country or component or macro):
        raise Usage()

    if rerun:
        if shodanquery or product or country or component:
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

    httpcheckers = {}
    for m in (None,) + MACROS:
        httpcheckers[m] = build_httpchecker(m)
    httpchecker = httpcheckers[macro]

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
        if shodan_code == HTTPStatus.OK:
            (shodan_code, myip) = myip_shodan(testing, debuglevel=debuglevel)
            if shodan_code == HTTPStatus.OK:
                sys.stderr.write("My IP: %s\n" % (myip,))
                myipaddr = ip_address(myip)
                if rerun in all_emails:
                    recheck(testing, macro, rerun, all_emails[rerun],
                            myaddr, myipaddr, to_myself_only,
                            openers, httpcheckers, debuglevel)
                else:
                    emailpat = re.compile(rerun)
                    for e in sorted(all_emails.keys()):
                        if emailpat.match(e):
                            recheck(testing, macro, e, all_emails[e],
                                    myaddr, myipaddr, to_myself_only,
                                    openers, httpcheckers, debuglevel)
    else:
        search_and_mail(testing, checkurl,
                shodanquery, product, country, component, macro, 
                all_emails, sent_name, myaddr, to_myself_only,
                httpchecker, openers,
                debuglevel)


if __name__ == "__main__":
    import sys
    # Wrapping parameter parsing into a function call prevents from spilling
    # them into the global namespace and accidentally using them in the other
    # functions.
    main(sys.argv)

