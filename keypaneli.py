#!/usr/bin/env python3
"""Keypaneli - tek dosya, ek kurulum yok. Çalıştır: python keypaneli.py  ->  http://localhost:8000"""
import sqlite3, json, os, secrets, hashlib, time, re
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = os.environ.get("DB", "keypaneli.db")
UNIT = {"hour": 3600, "day": 86400, "week": 604800, "unlimited": 0}
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
tries = {}
fails = {}


def now(): return int(time.time())
def hp(p, s):
    try: return hashlib.scrypt(p.encode(), salt=s.encode(), n=2**14, r=8, p=1).hex()
    except (AttributeError, ValueError):  # bazı telefon Python'larında scrypt yok
        return hashlib.pbkdf2_hmac("sha256", p.encode(), s.encode(), 200000).hex()


def q(sql, a=(), one=False):
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    cur = c.execute(sql, a)
    r = cur.fetchone() if one else cur.fetchall()
    c.commit(); lid = cur.lastrowid; c.close()
    return r if sql.lstrip().lower().startswith("select") else lid


def init():
    c = sqlite3.connect(DB)
    c.executescript("""
    create table if not exists users(id integer primary key,username text unique,pw text,salt text,role text,created int);
    create table if not exists keys(id integer primary key,k text unique,owner int,kind text,dur int,maxdev int,created int,act int,exp int,banned int default 0);
    create table if not exists devs(kid int,dev text,seen int,unique(kid,dev));
    create table if not exists sess(t text primary key,uid int);
    create table if not exists meta(k text primary key,v text);""")
    if not c.execute("select 1 from users").fetchone():
        u = os.environ.get("ADMIN_USER", "admin")
        p = os.environ.get("ADMIN_PASS") or secrets.token_urlsafe(8)
        r = os.environ.get("ADMIN_REF") or "Wroxbaba31"
        s = secrets.token_hex(8)
        c.execute("insert into users values(null,?,?,?,?,?)", (u, hp(p, s), s, "admin", now()))
        c.execute("insert or replace into meta values('ref',?)", (r,))
        print(f"\n=== ILK KURULUM ===\nAdmin kullanıcı: {u}\nAdmin şifre    : {p}\nAdmin referans : {r}\n(Bunları kaydet, tekrar gösterilmez)\n")
    if not c.execute("select 1 from meta where k='ref2'").fetchone():  # eski veritabanında da referans = Wroxbaba31 olsun
        c.execute("insert or replace into meta values('ref',?)", (os.environ.get("ADMIN_REF") or "Wroxbaba31",))
        c.execute("insert into meta values('ref2','1')")
    c.commit(); c.close()


def status(r):
    if r["banned"]: return "engelli"
    if r["act"] is None: return "bekliyor"
    if r["exp"] and now() > r["exp"]: return "doldu"
    return "aktif"


def info(r, ok, msg, dc, exp):
    t = now()
    return {"ok": ok, "active": ok, "msg": msg, "kind": r["kind"], "devices": dc, "maxdev": r["maxdev"],
            "exp": exp, "remaining": (max(0, exp - t) if exp else None), "unlimited": r["kind"] == "unlimited"}


def verify(k, dev, reg=True):
    r = q("select * from keys where k=?", (k,), True)
    if not r: return {"ok": False, "active": False, "msg": "Geçersiz key"}
    dc = q("select count(*) c from devs where kid=?", (r["id"],), True)["c"]
    if r["banned"]: return info(r, False, "Key engellendi", dc, r["exp"])
    t, exp = now(), r["exp"]
    if r["act"] is None:
        if not reg: return info(r, True, "Key henüz başlamadı (ilk kullanımda başlar)", dc, 0)
        exp = t + r["dur"] if r["dur"] else 0
        q("update keys set act=?,exp=? where id=?", (t, exp, r["id"]))
    elif exp and t > exp:
        return info(r, False, "Key süresi doldu (otomatik kapandı)", dc, exp)
    if not q("select 1 from devs where kid=? and dev=?", (r["id"], dev), True):
        if dc >= r["maxdev"]: return info(r, False, f"Cihaz limiti doldu ({dc}/{r['maxdev']})", dc, exp)
        if reg: q("insert into devs values(?,?,?)", (r["id"], dev, t)); dc += 1
    return info(r, True, "Giriş başarılı", dc, exp)


def rand_key(): return "KP-" + "-".join("".join(secrets.choice(ALPHA) for _ in range(5)) for _ in range(3))


def api(m, path, b, u, ip):
    P = path.split("/")
    if path in ("verify", "check") and m == "POST":
        return verify(str(b.get("key", "")).strip(), str(b.get("device", ""))[:100] or "?", path == "verify"), None
    if path in ("login", "register"):
        if tries.get(ip, (0, 0))[0] >= 10 and now() - tries[ip][1] < 300:
            return {"err": "Çok fazla deneme, 5 dk bekle"}, None
        tries[ip] = (tries.get(ip, (0, 0))[0] + 1, now())
        un, pw = str(b.get("username", "")).strip(), str(b.get("password", ""))
        if path == "register":
            if b.get("ref", "").strip() != q("select v from meta where k='ref'", (), True)["v"]:
                return {"err": "Geçersiz referans kodu"}, None
            if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", un) or len(pw) < 6:
                return {"err": "Kullanıcı adı 3-20 harf/rakam, şifre en az 6 karakter"}, None
            if q("select 1 from users where username=?", (un,), True): return {"err": "Bu kullanıcı adı alınmış"}, None
            s = secrets.token_hex(8)
            uid = q("insert into users values(null,?,?,?,?,?)", (un, hp(pw, s), s, "user", now()))
        else:
            r = q("select * from users where username=?", (un,), True)
            if not r or not secrets.compare_digest(r["pw"], hp(pw, r["salt"])): return {"err": "Hatalı giriş"}, None
            uid = r["id"]
        tries.pop(ip, None)
        t = secrets.token_urlsafe(32); q("insert into sess values(?,?)", (t, uid))
        return {"ok": True}, t
    if path == "logout": return {"ok": True}, "-"
    if not u: return {"err": "Giriş gerekli", "auth": True}, None
    adm = u["role"] == "admin"
    if path == "me":
        return {"username": u["username"], "admin": adm, "ref": q("select v from meta where k='ref'", (), True)["v"] if adm else None}, None
    if path == "keys" and m == "GET":
        rows = q("select k.*,(select count(*) from devs where kid=k.id) dc,u.username own from keys k left join users u on u.id=k.owner"
                 + ("" if adm else " where k.owner=%d" % u["id"]) + " order by k.id desc")
        return {"keys": [dict(id=r["id"], key=r["k"], kind=r["kind"], dur=r["dur"], maxdev=r["maxdev"], dc=r["dc"], st=status(r),
                              exp=r["exp"], own=r["own"]) for r in rows]}, None
    if path == "keys" and m == "POST":
        kind = b.get("kind")
        if kind not in UNIT: return {"err": "Geçersiz tür"}, None
        try: cnt, md, qty = max(1, int(b.get("count", 1))), max(1, int(b.get("maxdev", 1))), min(100, max(1, int(b.get("qty", 1))))
        except Exception: return {"err": "Geçersiz sayı"}, None
        dur = UNIT[kind] * cnt if UNIT[kind] else 0
        out = []
        for _ in range(1 if b.get("mode") == "custom" else qty):
            k = str(b.get("custom", "")).strip() if b.get("mode") == "custom" else rand_key()
            if b.get("mode") == "custom" and not re.fullmatch(r"[A-Za-z0-9_-]{4,40}", k):
                return {"err": "Özel key 4-40 karakter (harf, rakam, - _)"}, None
            if q("select 1 from keys where k=?", (k,), True): return {"err": "Bu key zaten var"}, None
            q("insert into keys values(null,?,?,?,?,?,?,null,0,0)", (k, u["id"], kind, dur, md, now())); out.append(k)
        return {"ok": True, "made": out}, None
    if P[0] == "keys" and len(P) >= 2:
        r = q("select * from keys where id=?", (P[1],), True)
        if not r or (not adm and r["owner"] != u["id"]): return {"err": "Bulunamadı"}, None
        if m == "DELETE":
            q("delete from devs where kid=?", (r["id"],)); q("delete from keys where id=?", (r["id"],))
        elif P[2:] == ["reset"]: q("delete from devs where kid=?", (r["id"],))
        elif P[2:] == ["ban"]: q("update keys set banned=? where id=?", (0 if r["banned"] else 1, r["id"]))
        return {"ok": True}, None
    if adm and path == "users" and m == "GET":
        return {"users": [dict(id=r["id"], username=r["username"], role=r["role"], keys=r["n"]) for r in
                          q("select u.*,(select count(*) from keys where owner=u.id) n from users u")]}, None
    if adm and P[0] == "users" and m == "DELETE":
        q("delete from users where id=? and role!='admin'", (P[1],)); return {"ok": True}, None
    if adm and path == "ref" and m == "POST":
        r = re.sub(r"\s", "", str(b.get("ref", "")))
        if len(r) < 4: return {"err": "Referans en az 4 karakter"}, None
        q("insert or replace into meta values('ref',?)", (r,)); return {"ok": True}, None
    return {"err": "Bulunamadı"}, None


class H(BaseHTTPRequestHandler):
    def user(self):
        t = next((c.split("=", 1)[1] for c in self.headers.get("Cookie", "").split("; ") if c.startswith("kp=")), None)
        r = q("select u.* from sess s join users u on u.id=s.uid where s.t=?", (t,), True) if t else None
        return r

    def go(self, m):
        path = self.path.split("?")[0]
        if m == "GET" and path == "/":
            d = PAGE.encode(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(d))); self.end_headers(); self.wfile.write(d); return
        n = int(self.headers.get("Content-Length") or 0)
        try: b = json.loads(self.rfile.read(n) or b"{}")
        except Exception: b = {}
        if path.rstrip("/") == "/connect":  # oyun/program buraya bağlanır: /connect?key=KEY&device=ID
            qs = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0]
            key = str(b.get("key") or qs.get("key") or "").strip()
            dev = str(b.get("device") or qs.get("device") or "?")[:100]
            f = fails.get(ip, (0, 0))
            if f[0] >= 30 and now() - f[1] < 300: res = {"ok": False, "active": False, "msg": "Çok fazla hatalı deneme, 5 dk bekle"}
            else:
                try: res = verify(key, dev, not (b.get("check") or qs.get("check")))
                except Exception as e: res = {"ok": False, "active": False, "msg": f"Sunucu hatası: {e}"}
                if not res.get("ok"): fails[ip] = (f[0] + 1, now())
            d = json.dumps(res, ensure_ascii=False).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store"); self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(d))); self.end_headers(); self.wfile.write(d); return
        if not path.startswith("/api/"): self.send_error(404); return
        ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0]
        try: res, tok = api(m, path[5:], b, self.user(), ip)
        except Exception as e: res, tok = {"err": f"Sunucu hatası: {e}"}, None
        d = json.dumps(res).encode(); self.send_response(200)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(d)))
        if tok == "-": self.send_header("Set-Cookie", "kp=; Max-Age=0; Path=/")
        elif tok: self.send_header("Set-Cookie", f"kp={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000")
        self.end_headers(); self.wfile.write(d)

    do_GET = lambda s: s.go("GET")
    do_POST = lambda s: s.go("POST")
    do_DELETE = lambda s: s.go("DELETE")
    def log_message(self, *a): pass


PAGE = """<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Keypaneli</title><style>
:root{--bg:#f4f5f8;--cd:#fff;--tx:#161922;--mu:#6b7285;--ac:#4f6bff;--bd:#dfe2ea;--ok:#12a066;--bad:#e5384c;--wr:#c98a00}
@media(prefers-color-scheme:dark){:root{--bg:#0e1015;--cd:#171a22;--tx:#e8eaf0;--mu:#8b91a3;--ac:#7690ff;--bd:#2a2f3a;--ok:#35c27a;--bad:#ff6b7a;--wr:#f0b429}}
*{box-sizing:border-box}body{margin:0;font:15px system-ui,sans-serif;background:var(--bg);color:var(--tx)}
.w{max-width:900px;margin:0 auto;padding:16px}h1{margin:0;font-size:22px}h1 b{color:var(--ac)}
.c{background:var(--cd);border:1px solid var(--bd);border-radius:12px;padding:14px;margin:12px 0}
input,select,button{font:inherit;padding:10px;border-radius:8px;border:1px solid var(--bd);background:var(--bg);color:var(--tx);width:100%;margin:4px 0}
button{background:var(--ac);color:#fff;border:0;cursor:pointer;font-weight:600}button.g{background:var(--bd);color:var(--tx);width:auto;padding:6px 10px;font-size:13px}
button.r{background:var(--bad);width:auto;padding:6px 10px;font-size:13px}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px}.top{display:flex;justify-content:space-between;align-items:center}
.k{border-top:1px solid var(--bd);padding:10px 0}.k code{font-size:14px;word-break:break-all;cursor:pointer}.m{color:var(--mu);font-size:13px;margin:4px 0}
.s{padding:2px 8px;border-radius:99px;font-size:12px;font-weight:700;border:1px solid}.aktif{color:var(--ok)}.doldu,.engelli{color:var(--bad)}.bekliyor{color:var(--wr)}
.tabs{display:flex;gap:8px}.tabs button{background:var(--bd);color:var(--tx)}.tabs button.on{background:var(--ac);color:#fff}.err{color:var(--bad);min-height:20px}.hide{display:none}


:root{--bg:#000;--cd:#0c0c0d;--tx:#f2f2f2;--mu:#8a8a92;--ac:#fff;--bd:#232327;--ok:#3ddc84;--bad:#ff5a5f;--wr:#e0a800}
body{background:#000;min-height:100vh}
.w{max-width:760px}
.hero{text-align:center;margin:40px 0 18px}
.logo{font-size:clamp(54px,17vw,108px);font-weight:900;letter-spacing:.2em;margin-right:-.2em;line-height:1;color:#fff;font-family:Inter,"Helvetica Neue",Arial,sans-serif;animation:logo 1s cubic-bezier(.2,.8,.2,1) both}
@keyframes logo{from{opacity:0;letter-spacing:.6em;filter:blur(8px)}}
.sub{letter-spacing:.55em;margin-right:-.55em;color:var(--mu);font-size:11px;font-weight:600;margin-top:10px;animation:up .8s .4s both}
@keyframes up{from{opacity:0;transform:translateY(14px)}}
.c{background:var(--cd);border:1px solid var(--bd);border-radius:10px;box-shadow:none;animation:up .6s both}
#auth{max-width:380px;margin:20px auto;animation-delay:.5s;transition:opacity .4s,transform .4s}#auth.out{opacity:0;transform:translateY(-14px)}
#app>.c:nth-child(2){animation-delay:.08s}#app>.c:nth-child(3){animation-delay:.16s}#app>.c:nth-child(4){animation-delay:.24s}
input,select{background:#000;border:1px solid var(--bd);border-radius:8px}input:focus,select:focus{outline:0;border-color:#fff}
button{background:#fff;color:#000;border-radius:8px;transition:transform .12s,opacity .2s}button:hover{opacity:.88}button:active{transform:scale(.97)}
button.g{background:#1a1a1d;color:#f2f2f2;border:1px solid var(--bd)}button.r{background:transparent;color:var(--bad);border:1px solid var(--bad)}
.tabs button{background:#1a1a1d;color:#aaa}.tabs button.on{background:#fff;color:#000}
.s{box-shadow:none}.k{border-color:var(--bd)}h1,b{color:#fff}.hide{display:none!important}
#snow{position:fixed;inset:0;z-index:-1;pointer-events:none}.c{background:rgba(10,10,11,.82)}
</style></head><body><div class="w">
<canvas id="snow"></canvas><div class="hero"><div class="logo">WROX</div><div class="sub">KEY PANELİ</div></div><div class="top"><span></span><div id="who"></div></div>
<div id="auth" class="c hide"><div class="tabs"><button id="t1" class="on" onclick="tab(1)">Giriş</button><button id="t2" onclick="tab(2)">Kayıt ol</button></div>
<input id="u" placeholder="Kullanıcı adı" autocomplete="username"><input id="p" type="password" placeholder="Şifre" autocomplete="current-password">
<input id="rf" class="hide" placeholder="Referans kodu (zorunlu)"><button onclick="auth()" id="ab">Giriş yap</button><div class="err" id="ae"></div></div>
<div id="app" class="hide">
<div class="c"><b>Key oluştur</b><div class="row">
<select id="kind"><option value="hour">Saatlik</option><option value="day" selected>Günlük</option><option value="week">Haftalık</option><option value="unlimited">Sınırsız</option></select>
<input id="cnt" type="number" min="1" value="1" placeholder="Süre adedi"><input id="md" type="number" min="1" value="1" placeholder="Cihaz limiti">
<select id="mode" onchange="cu.classList.toggle('hide',mode.value!='custom');qt.classList.toggle('hide',mode.value=='custom')"><option value="random">Rastgele</option><option value="custom">Kendim yazacağım</option></select>
<input id="qt" type="number" min="1" max="100" value="1" placeholder="Adet"><input id="cu" class="hide" placeholder="Özel key"></div>
<button onclick="mk()">Oluştur</button><div class="err" id="ke"></div></div>
<div class="c"><div class="top"><b>Keylerim</b><button class="g" onclick="ld()">Yenile</button></div><div id="kl"></div></div>
<div class="c"><b>Key doğrula (test)</b><div class="m">Yazılımın bu uç noktayı çağırır: POST /api/verify {"key","device"}</div>
<input id="vk" placeholder="Key"><input id="vd" placeholder="Cihaz ID"><button onclick="vf()">Doğrula</button><div id="vr" class="m"></div></div>
<div id="adm" class="c hide"><b>Admin</b><div class="m">Referans kodu (kayıt için gerekli):</div><div class="row"><input id="ref"><button onclick="sr()">Kaydet</button></div><div id="ul"></div></div>
</div></div><script>
const $=s=>document.getElementById(s),E=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const A=async(p,m='GET',b)=>{try{return await(await fetch('/api/'+p,{method:m,headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined})).json()}catch(e){return{err:'Sunucuya ulaşılamadı: '+e}}};
const F=t=>t?new Date(t*1000).toLocaleString('tr-TR'):'—',KN={hour:'Saatlik',day:'Günlük',week:'Haftalık',unlimited:'Sınırsız'};let reg=0,me;
$('vd').value=localStorage.kpd=localStorage.kpd||'dev-'+Math.random().toString(36).slice(2,10);
function tab(n){reg=n==2;$('t1').className=reg?'':'on';$('t2').className=reg?'on':'';$('rf').classList.toggle('hide',!reg);$('ab').textContent=reg?'Kayıt ol':'Giriş yap'}
async function auth(){const r=await A(reg?'register':'login','POST',{username:$('u').value,password:$('p').value,ref:$('rf').value});$('ae').textContent=r.err||'';if(r.ok){$('auth').classList.add('out');setTimeout(()=>{$('auth').classList.remove('out');init()},650)}}
async function init(){me=await A('me');if(me.err){$('auth').classList.remove('hide');$('app').classList.add('hide');$('who').innerHTML='';return}
$('auth').classList.add('hide');$('app').classList.remove('hide');$('who').innerHTML=E(me.username)+' <button class="g" onclick="A(\\'logout\\',\\'POST\\').then(init)">Çıkış</button>';
$('adm').classList.toggle('hide',!me.admin);if(me.admin){$('ref').value=me.ref;ul()}ld()}
async function ld(){const r=await A('keys');$('kl').innerHTML=r.keys.length?r.keys.map(k=>`<div class="k"><code onclick="navigator.clipboard&&navigator.clipboard.writeText('${E(k.key)}')">${E(k.key)}</code> <span class="s ${k.st}">${k.st}</span>
<div class="m">${KN[k.kind]}${k.dur&&k.kind!='unlimited'?' × '+k.dur/{hour:3600,day:86400,week:604800}[k.kind]:''} · Cihaz ${k.dc}/${k.maxdev} · Bitiş: ${k.kind=='unlimited'?(k.st=='bekliyor'?'ilk kullanımda başlar':'sınırsız'):k.st=='bekliyor'?'ilk kullanımda başlar':F(k.exp)}${k.own&&me.admin?' · '+E(k.own):''}</div>
<button class="g" onclick="ac(${k.id},'reset')">Cihazları sıfırla</button> <button class="g" onclick="ac(${k.id},'ban')">Engelle/Aç</button> <button class="r" onclick="confirm('Silinsin mi?')&&A('keys/${k.id}','DELETE').then(ld)">Sil</button></div>`).join(''):'<div class="m">Henüz key yok.</div>'}
const ac=(i,a)=>A('keys/'+i+'/'+a,'POST').then(ld);
async function mk(){const r=await A('keys','POST',{kind:$('kind').value,count:$('cnt').value,maxdev:$('md').value,mode:$('mode').value,custom:$('cu').value,qty:$('qt').value});$('ke').textContent=r.err||'';if(r.ok)ld()}
async function vf(){const r=await A('verify','POST',{key:$('vk').value,device:$('vd').value});$('vr').textContent=(r.ok?'✅ ':'❌ ')+r.msg+(r.devices!=null?` · cihaz ${r.devices}/${r.maxdev}`:'')+(r.ok&&r.exp?' · bitiş '+F(r.exp):'');ld()}
async function sr(){const r=await A('ref','POST',{ref:$('ref').value});alert(r.err||'Referans güncellendi')}
async function ul(){const r=await A('users');$('ul').innerHTML=r.users.map(u=>`<div class="k">${E(u.username)} <span class="m">${u.role} · ${u.keys} key</span> ${u.role!='admin'?`<button class="r" onclick="confirm('Kullanıcı silinsin mi?')&&A('users/${u.id}','DELETE').then(ul)">Sil</button>`:''}</div>`).join('')}

(()=>{const cv=$('snow'),x=cv.getContext('2d'),M=['kar','top','yıldız','elmas','yağmur'];let W,Hh,t=0,mode='kar',P=[];
const rs=()=>{W=cv.width=innerWidth;Hh=cv.height=innerHeight};rs();addEventListener('resize',rs);
const mk=y=>({x:Math.random()*W,y:y==null?-30:y,r:1+Math.random()*3.5,v:.6+Math.random()*1.8,d:Math.random()*6.28,s:mode,a:.35+Math.random()*.6});
for(let i=0;i<150;i++)P.push(mk(Math.random()*Hh));
setInterval(()=>{let n;do{n=M[Math.floor(Math.random()*M.length)]}while(n==mode);mode=n},10000);
(function f(){t+=.01;x.clearRect(0,0,W,Hh);const wind=Math.sin(t*.6)*1.3;x.fillStyle=x.strokeStyle='#fff';
for(const p of P){const k=p.s=='yağmur'?5:p.s=='top'?1.3:1;p.y+=p.v*k;p.x+=(p.s=='yağmur'?.4:1)*(Math.sin(p.d+t*2)*.5+wind);
if(p.y>Hh+40||p.x>W+40||p.x<-40)Object.assign(p,mk());
x.globalAlpha=p.a;x.lineWidth=1;x.beginPath();
if(p.s=='kar'){x.arc(p.x,p.y,p.r,0,6.28);x.fill()}
else if(p.s=='top'){const R=p.r*3+3;x.globalAlpha=p.a*.35;x.arc(p.x,p.y,R,0,6.28);x.fill();x.globalAlpha=p.a;x.lineWidth=1.5;x.beginPath();x.arc(p.x,p.y,R,0,6.28);x.stroke()}
else if(p.s=='yıldız'){const R=p.r*2.4+2;x.save();x.translate(p.x,p.y);x.rotate(t*2+p.d);for(let i=0;i<10;i++){const rr=i%2?R*.45:R,a=i*Math.PI/5;x.lineTo(Math.sin(a)*rr,-Math.cos(a)*rr)}x.closePath();x.fill();x.restore()}
else if(p.s=='elmas'){const R=p.r*2+3;x.save();x.translate(p.x,p.y);x.rotate(t*1.5+p.d);x.strokeRect(-R/2,-R/2,R,R);x.restore()}
else{x.moveTo(p.x,p.y);x.lineTo(p.x-wind*3,p.y+p.r*6+6);x.stroke()}}
x.globalAlpha=1;requestAnimationFrame(f)})()})();
init();setInterval(()=>{me&&!me.err&&ld()},30000);
</script></body></html>"""

if __name__ == "__main__":
    init()
    port = int(os.environ.get("PORT", 8000))
    print(f"Keypaneli çalışıyor: http://localhost:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
