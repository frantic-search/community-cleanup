#! /bin/bash

function usage() {
    echo "Usage: $0 [-t] COMPONENT COUNTRY [PRODUCT]" >&2
    exit 1
}

function error() {
    echo "Error: $*" >&2
    exit 2
}

testing="$1"
if [[ "${testing}" == "-t" ]] ; then
    shift
else
    testing=""
fi
myaddr="${USER}@${HOSTNAME}"
component="$1"; shift || usage
country="$1"; shift || usage
if (( $# == 1 )) ; then
    product="$1"
elif (( $# == 0 )) ; then
    product=""
else
    usage
fi

tmproot="${TMPDIR:-/tmp}"
tmproot="${tmproot%/}"
tmp="${tmproot}/shodan"
rm -rf "${tmp}"
mkdir -p "${tmp}"

key=$(< ~/.shodan)
echo "Requesting component ${component} in country ${country}..."
c=$(curl -isS -o "${tmp}/search.txt" --write-out "%{http_code}" \
    "https://api.shodan.io/shodan/host/search" \
    -d "key=${key}" \
    -d "query=http.component:${component} country:${country}" \
)
[[ "${c}" == "200" ]] || error "HTTP code ${c} in ${tmp}/search.txt"
searchbody=$(sed -e '1,/^[[:space:]]*$/d' "${tmp}/search.txt")
numhosts=$(jq ".matches | length" <<< "${searchbody}")
echo "Found hosts: ${numhosts}"
jq -r ".matches[] | ((.ip|tostring) + \" \" + .product)" <<< "${searchbody}" > "${tmp}/hosts-num.txt"
python -c '
import struct, socket, sys
import smtplib
from email.mime.text import MIMEText

testing = sys.argv[1]
if testing == "-t":
    del sys.argv[1]
else:
    testing = ""
(myaddr, component, country) = sys.argv[1:4]
if len(sys.argv) == 5:
    prodfilter = sys.argv[4].lower()
else:
    prodfilter = None
emails = {}
anichost = "whois.arin.net"

for line in iter(sys.stdin.readline, ""):
    hostinfo = line.strip().split(None, 1)
    if len(hostinfo) == 2:
        ip, product = hostinfo
    else:
        ip = hostinfo[0]
        product = ""
    h = socket.inet_ntoa(struct.pack("!I", int(ip)))
    sys.stderr.write("%s\n" % (h,))
    if prodfilter:
        if prodfilter not in product.lower():
            sys.stderr.write("  *** %s\n" % (product,))
            continue
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((anichost, 43))
    s.send(bytearray(u"n + %s\r\n" % h, "utf-8"))
    r = []
    while True:
        d = s.recv(4096)
        if not d:
            break
        r.append(d)
    s.close()
    resp = "".join(r)
    for line in resp.splitlines():
        # print "=== %s ====" % (line,)
        if line.startswith("OrgAbuseEmail:"):
            e = line.split()[1].strip()
            sys.stderr.write("  %s\n" % (e,))
            if e in emails:
                eaddrs = emails[e]
            else:
                eaddrs = []
                emails[e] = eaddrs
            eaddrs.append(h)
sys.stderr.write("\n")
for e in emails:
    print "%s: %s\n" % (e, ", ".join(emails[e]))

prodname = prodfilter if prodfilter else "internet thing"
for e in emails:
    sys.stderr.write("Sending email to %s...\n" % (e,))
    msg = MIMEText("""
Hello %s,

Your %s at the following address(es) may be infected 
with "%s":

  %s

Best regards,

A community cleanup initiative
https://github.com/ilatypov/community-cleanup
""" % (e, prodname, component, "\n  ".join(emails[e])))

    me = myaddr
    if testing:
        you = myaddr
    else:
        you = e
    msg["Subject"] = "Community cleanup: your %s needs attention" % (prodname,)
    msg["From"] = me
    msg["To"] = you
    s = smtplib.SMTP("localhost")
    s.sendmail(me, [you], msg.as_string())
    s.quit()

' ${testing} "${myaddr}" "${component}" "${country}" "${product}" < "${tmp}/hosts-num.txt" > "${tmp}/hosts-emails.txt"
cat "${tmp}/hosts-emails.txt"

