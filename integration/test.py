import hashlib
import http.cookiejar
from html.parser import HTMLParser
import json, os, socket, subprocess, tempfile, time
from pathlib import Path
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.parse import urlencode
from urllib.error import HTTPError
REPO=Path(__file__).resolve().parents[1]
SHARED=REPO/"integration/privacy-lib"
paths={"node":os.environ.get("NODE_BINARY","node"),"node22":os.environ.get("NODE_BINARY","node")}
sources=[SHARED/"gdpr-router.cjs",*sorted((SHARED/"gdpr").glob("*.rego"))]
hashes=lambda:[hashlib.sha256(file.read_bytes()).hexdigest() for file in sources]
before=hashes()
checks=[]
def check(name, condition):
    assert condition,name
    checks.append({"name":name,"passed":True})
    print("PASS",name,flush=True)
def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0));return s.getsockname()[1]
class Form(HTMLParser):
    token=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=="input" and a.get("name")=="_csrf":self.token=a["value"]
def client():return build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
with tempfile.TemporaryDirectory(prefix="gdpr-todos-") as temp:
    opa_port,app_port=port(),port()
    flags=getattr(subprocess,"CREATE_NO_WINDOW",0)
    opa=subprocess.Popen([os.environ.get("OPA_BINARY","opa"),"run","--server","--addr",f"127.0.0.1:{opa_port}",str(SHARED/"gdpr")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=flags)
    app=subprocess.Popen([paths["node22"],str(REPO/"bin/www")],cwd=temp,
        env=dict(os.environ,PORT=str(app_port),GDPR_ADMIN_USER_IDS="1",OPA_QUERY_URL=f"http://127.0.0.1:{opa_port}/v1/query"),
        stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,creationflags=flags)
    base=f"http://127.0.0.1:{app_port}"
    alice=client()
    def html(c,url):
        with c.open(base+url,timeout=10) as r:return r.read().decode()
    def csrf(c):
        parser=Form();parser.feed(html(c,"/login"));assert parser.token;return parser.token
    def login(c,username="alice",password="letmein",signup=False):
        body=urlencode({"username":username,"password":password,"_csrf":csrf(c)}).encode()
        with c.open(Request(base+("/signup" if signup else "/login/password"),data=body),timeout=10) as r:
            text=r.read().decode()
        assert f'<li class="user">{username}</li>' in text
    def request(c,policy,body=None,method="POST",token=True):
        headers={"Content-Type":"application/json"}
        if token:headers["X-CSRF-Token"]=csrf(c)
        try:
            with c.open(Request(base+"/gdpr/"+policy,data=json.dumps(body or {}).encode(),headers=headers,method=method),timeout=10) as r:
                return r.status,json.loads(r.read())
        except HTTPError as e:
            raw=e.read()
            try:payload=json.loads(raw)
            except ValueError:payload=raw.decode()
            return e.code,payload
    try:
        for _ in range(150):
            if app.poll() is not None:raise RuntimeError(app.stderr.read().decode())
            try:csrf(alice);break
            except OSError:time.sleep(.1)
        else:raise RuntimeError("App startup timeout")
        for _ in range(100):
            try:
                from urllib.request import urlopen
                with urlopen(f"http://127.0.0.1:{opa_port}/health",timeout=1):break
            except OSError:time.sleep(.1)
        check("Unauthenticated evaluation denied",request(alice,"consent")[0]==401)
        login(alice)
        check("Original login and session work",True)
        check("Authenticated privacy test page renders", "Privacy checks" in html(alice,"/gdpr"))
        check("CSRF required on GDPR requests",request(alice,"consent",token=False)[0]==403)
        check("Missing consent denies processing",request(alice,"consent")== (200,False))
        check("Consent stored in SQLite",request(alice,"consent",{"value":"yes","withdrawn":False},"PATCH")== (200,{"value":"yes","withdrawn":False}))
        for policy in ["consent","lawful"]:
            check(policy+" accepts",request(alice,policy)==(200,True))
        status,data=request(alice,"information");check("Information report",status==200 and data["consent_valid"] is True)
        status,data=request(alice,"access");download=json.loads(data["download"]["content"])
        check("Access scoped to real username/todos",status==200 and download["user_id"]=="1" and sorted(x["field"] for x in download["data_collected_from_user"])==["todos","username"])
        check("Access excludes credentials","hashed_password" not in json.dumps(data) and '"salt"' not in json.dumps(data))
        status,data=request(alice,"rectification",{"updates":{"username":"UpdatedAlice"}})
        check("Rectification plan",status==200 and data["request"]["validated"] and data["db_update_plan"][0]["field"]=="username")
        status,data=request(alice,"erasure",{"fields":["username"]});check("Retention blocks username erasure",status==200 and data["decision"]=="reject")
        status,data=request(alice,"restriction");check("Restriction plan",status==200 and data["decision"]=="accept")
        with alice.open(Request(base+"/",data=urlencode({"title":"Alice private integration todo","_csrf":csrf(alice)}).encode()),timeout=10) as response:
            check("Original todo creation works after integration",response.status==200)
        status,data=request(alice,"portability")
        check("Portability returns JSON and CSV",status==200 and data["decision"]=="accept" and len(data["actions"]["downloads"])==2 and "alice" in json.dumps(data["actions"]["downloads"]))
        check("Portability excludes credentials","hashed_password" not in json.dumps(data) and '"salt"' not in json.dumps(data))
        check("Portability includes real owned todo title","Alice private integration todo" in json.dumps(data))
        status,data=request(alice,"objection",{"reason":"marketing"});check("Objection plan",status==200 and data["decision"]=="accept")
        status,data=request(alice,"complaint",{"authority_id":"cy-0000","description":"Integration test, do not send"});check("Complaint plan",status==200 and data["decision"]=="accept")
        status,data=request(alice,"breach",{"incident_id":"test-incident"});check("Configured demo administrator breach assessment",status==200 and data["decision"]=="notify_users")
        bob=client();login(bob,"bob","Integration456",True)
        check("Independent real user signup/session",True)
        check("Second user has no inherited consent",request(bob,"consent")==(200,False))
        with bob.open(Request(base+"/",data=urlencode({"title":"Bob private integration todo","_csrf":csrf(bob)}).encode()),timeout=10) as response:
            assert response.status==200
        assert request(bob,"consent",{"value":"yes","withdrawn":False},"PATCH")[0]==200
        status,other=request(bob,"portability")
        check("Portability isolates real todo ownership",status==200 and "Bob private integration todo" in json.dumps(other) and "Alice private integration todo" not in json.dumps(other))
        status,own=request(alice,"portability")
        check("Alice export excludes Bob todo","Alice private integration todo" in json.dumps(own) and "Bob private integration todo" not in json.dumps(own))

        check("Nonadministrator cannot assess breach",request(bob,"breach",{"incident_id":"x"})[0]==403)
        status,data=request(bob,"access");check("Second user isolated",json.loads(data["download"]["content"])["user_id"]!="1")
        check("Cannot select another subject",request(bob,"access",{"user_id":"1"})[0]==400)
        check("Invalid consent value rejected",request(alice,"consent",{"value":"yes","withdrawn":"false"},"PATCH")[0]==400)
        check("Withdraw consent",request(alice,"consent",{"value":"yes","withdrawn":True},"PATCH")[0]==200)
        for policy in ["consent","lawful","portability"]:
            status,data=request(alice,policy);check(policy+" denies after withdrawal",status==200 and (data["decision"]=="reject" if isinstance(data,dict) else data is False))
        status,data=request(alice,"access");check("Access remains available",status==200 and data["request"]["validated"])
        status,data=request(alice,"erasure",{"fields":["todos"],"reason":"withdrawn_consent"});check("Eligible erasure plan",status==200 and data["decision"]=="accept")
        check("Unknown operation rejected",request(alice,"unknown")[0]==400)
        opa.terminate();opa.wait(timeout=10)
        check("OPA failure returns 502",request(alice,"consent")[0]==502)
        check("Router/policies unchanged",hashes()==before)
        result={"repository":"passport/todos-express-password","commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=REPO,text=True).strip(),
            "timestamp":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "passed":len(checks),"checks":checks,"policies":["consent","lawful","information","access","rectification","erasure","restriction","portability","objection","complaint","breach"],
            "limitations":["Decision plans only; no side effects executed","Access returns metadata only","Synthetic controller/purpose metadata","Alice is explicitly configured as demo administrator; upstream has no roles"]}
        subprocess.run([paths["node"],str(REPO/"integration/test-support.cjs"),"record"],input=json.dumps(result),text=True,check=True)
        print("Integration result:",len(checks),"/",len(checks),"passed",flush=True)
    finally:
        app.terminate();app.wait(timeout=10);app.stderr.close()
        if opa.poll() is None:opa.terminate();opa.wait(timeout=10)
