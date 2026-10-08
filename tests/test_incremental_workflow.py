import io, json, zipfile
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from app.db import conn, init_db, reset_test_data, set_setting
from app.main import app
from app.security import encrypt_secret

@pytest.fixture(autouse=True)
def clean_db():
    init_db(); reset_test_data(); yield

def login(c):
    assert c.post("/login",data={"admin_password":"test-admin-password"},follow_redirects=False).status_code==303

def master(n):
    rows=["computer_number,source_email,target_email,first_name,middle_name,last_name"]
    rows += [f"{10000+i},user{i:04d}@rack.example,user{i:04d}@jcf.gov.jm,Test,,User{i:04d}" for i in range(1,n+1)]
    return ("\n".join(rows)+"\n").encode()

def profile(env="TEST",limit=100,stop=0):
    with conn() as db:
        cur=db.execute("""INSERT INTO environment_profiles(
        name,environment_type,is_active,writes_enabled,emergency_stop,production_max_batch,
        ad_host,ad_port,ad_use_ssl,ad_base_dn,ad_bind_username,ad_bind_password_enc,
        ad_target_ou,ad_license_group_dn,ad_computer_number_attribute,ad_upn_suffix,
        ad_default_password_enc,ad_force_password_change,ad_allow_user_creation,ad_allow_group_changes,
        graph_tenant_id,graph_client_id,graph_client_secret_enc,graph_required_sku,
        sync_agent_url,sync_agent_token_enc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("TEST" if env=="TEST" else "PROD",env,1,1,stop,limit,"dc",636,1,"DC=t,DC=local","svc",encrypt_secret("bindpass123!"),
         "OU=M365,DC=t,DC=local","CN=E3,DC=t,DC=local","extensionAttribute7","jcf.gov.jm",
         encrypt_secret("TempPass123!"),1,1,1,"tenant","client",encrypt_secret("graphsecret"),"SPE_E3","https://sync",encrypt_secret("synctoken")))
        return cur.lastrowid

class AD:
    def __init__(self): self.created=[]; self.members=set(); self.adds=[]
    def identity_decision(self,**kw):
        i=int(kw["target_email"].split("@")[0].replace("user",""))
        dn=f"CN=User{i},DC=t,DC=local"
        cand={"dn":dn,"object_guid":f"g{i}","upn":kw["target_email"],"mail":kw["target_email"],"first_name":"Test","last_name":f"User{i:04d}","computer_number":str(10000+i),"enabled":True,"proxy_addresses":[],"email_match":True,"computer_number_match":True,"name_match":True}
        if i==1:
            cand["computer_number"]="99999"; cand["computer_number_match"]=False
            return {"status":"manual_review","reason":"Computer Number mismatch","candidates":[cand]}
        if i<=10: return {"status":"confirmed","reason":"match","candidates":[cand],"selected":cand}
        return {"status":"not_found","reason":"not found","candidates":[]}
    def is_group_member(self,dn): return dn in self.members
    def add_to_license_group(self,dn): self.members.add(dn); self.adds.append(dn)
    def create_user(self,**kw):
        dn=f"CN={kw['first_name']} {kw['last_name']},OU=M365,DC=t,DC=local"
        self.created.append(kw); self.members.add(dn)
        return {"ok":True,"created":True,"dn":dn,"object_guid":"new-"+kw["computer_number"]}

class Graph:
    async def get_user(self,upn): return {"id":"e-"+upn,"accountEnabled":True,"userPrincipalName":upn}
    async def license_ready(self,oid): return True,["SPE_E3"]
    async def mailbox_ready(self,oid): return True,"ready"
    async def test_connection(self): return {"ok":True}

class Sync:
    def __init__(self): self.calls=0
    async def trigger_delta_sync(self): self.calls+=1; return {"ok":True}
    async def test_connection(self): return {"ok":True}

class Cloud:
    def __init__(self): self.next=1000; self.users={}; self.started=[]; self.creds=[]
    async def create_mail_batch(self,name): return {"id":88001,"name":name}
    async def mail_batches(self): return []
    async def verify_mail_user(self,email):
        for oid,u in self.users.items():
            if u["sourceEmail"]==email:return {"id":oid}
        return {}
    async def create_mail_user(self,p): self.next+=1; self.users[self.next]=dict(p); return {"id":self.next}
    async def get_mail_user(self,oid): return self.users[oid]
    async def get_self_service_token(self,oid): return str(oid)
    async def register_source_credentials(self,t,u,p): self.creds.append((u,p)); return {}
    async def add_mail_batch_members(self,b,o): return {}
    async def start_migration(self,o): self.started.append(list(o)); return {}
    async def progress(self,oid,since_minutes): return {"status":"Completed","percentage":100}

def fakes(monkeypatch):
    from app import provisioning,service
    ad,gr,sy,cl=AD(),Graph(),Sync(),Cloud()
    monkeypatch.setattr(provisioning,"ad_client_for_profile",lambda p:ad)
    monkeypatch.setattr(provisioning,"graph_client_for_profile",lambda p:gr)
    monkeypatch.setattr(provisioning,"sync_client_for_profile",lambda p:sy)
    async def ready(): return cl
    monkeypatch.setattr(service,"_cloudiway_client_ready",ready)
    set_setting("cloudiway_token",encrypt_secret("tok"),True); set_setting("cloudiway_source_pool_id","4"); set_setting("cloudiway_target_pool_id","3")
    return ad,sy,cl

def test_1000_stage_no_passwords():
    profile()
    with TestClient(app) as c:
        login(c); r=c.post("/upload",files={"file":("u.csv",master(1000),"text/csv")},data={"workflow_mode":"manual_bulk"},follow_redirects=False); assert r.status_code==303
    with conn() as db:
        assert db.execute("SELECT imported_rows FROM upload_batches").fetchone()["imported_rows"]==1000
        assert db.execute("SELECT COUNT(*) c FROM users WHERE generated_password_enc IS NOT NULL").fetchone()["c"]==0

def test_template_download():
    with TestClient(app) as c:
        login(c); r=c.get("/upload/template.xlsx"); assert r.status_code==200
        df=pd.read_excel(io.BytesIO(r.content),sheet_name="Users Template")
        assert list(df.columns)==["computer_number","source_email","target_email","first_name","middle_name","last_name"]

def test_full_20_user_end_to_end(monkeypatch):
    profile(); ad,sy,cl=fakes(monkeypatch)
    with TestClient(app) as c:
        login(c)
        c.post("/upload",files={"file":("master.csv",master(1000),"text/csv")},data={"workflow_mode":"manual_bulk"},follow_redirects=False)
        with conn() as db: up=db.execute("SELECT id FROM upload_batches").fetchone()["id"]
        assert c.post(f"/workflow/{up}/generate",data={"quantity":"20","auto_start":"1"},follow_redirects=False).status_code==303
        with conn() as db:
            mb=db.execute("SELECT * FROM migration_batches").fetchone(); mid=mb["id"]
            assert mb["selected_count"]==20 and mb["cloudiway_batch_id"]
            assert db.execute("SELECT COUNT(*) c FROM users WHERE generated_password_enc IS NOT NULL").fetchone()["c"]==0
            conflict=db.execute("SELECT * FROM users WHERE target_email='user0001@jcf.gov.jm'").fetchone()
            cand=json.loads(conflict["ad_candidate_json"])[0]
        c.post(f"/migration-batch/{mid}/provision",follow_redirects=False)
        with conn() as db:
            assert db.execute("""SELECT COUNT(*) c FROM migration_batch_members m JOIN users u ON u.id=m.user_id WHERE m.migration_batch_id=? AND u.provisioning_status='sync_pending'""",(mid,)).fetchone()["c"]==19
        c.post(f"/provisioning/user/{conflict['id']}/resolve",data={"candidate_dn":cand["dn"],"resolution_note":"Verified manually"},follow_redirects=False)
        assert sy.calls==1
        c.post(f"/migration-batch/{mid}/refresh-m365",follow_redirects=False)
        with conn() as db:
            assert db.execute("SELECT workflow_status FROM migration_batches WHERE id=?",(mid,)).fetchone()["workflow_status"]=="m365_ready"
        pack=c.post(f"/migration-batch/{mid}/rackspace-package"); assert pack.status_code==200
        z=zipfile.ZipFile(io.BytesIO(pack.content)); csvn=next(x for x in z.namelist() if x.endswith("rackspace-password-update.csv")); data=z.read(csvn)
        assert len(pd.read_csv(io.BytesIO(data)))==20
        conf=c.post(f"/migration-batch/{mid}/confirm",files={"file":("confirm.csv",data,"text/csv")},follow_redirects=False); assert conf.status_code==303
        with conn() as db: assert db.execute("SELECT workflow_status FROM migration_batches WHERE id=?",(mid,)).fetchone()["workflow_status"]=="migrating"
        assert len(cl.creds)==20 and len(cl.started)==1
        assert c.post("/status/refresh").status_code==200
        with conn() as db:
            assert db.execute("""SELECT COUNT(*) c FROM migration_batch_members m JOIN users u ON u.id=m.user_id WHERE m.migration_batch_id=? AND u.migration_status='completed'""",(mid,)).fetchone()["c"]==20
            assert db.execute("""SELECT COUNT(*) c FROM upload_batch_members u WHERE u.upload_batch_id=? AND NOT EXISTS(SELECT 1 FROM migration_batch_members m JOIN migration_batches b ON b.id=m.migration_batch_id WHERE b.upload_batch_id=? AND m.user_id=u.user_id)""",(up,up)).fetchone()["c"]==980
    assert len(ad.created)==10
    assert {x["temporary_password"] for x in ad.created}=={"TempPass123!"}
    assert all(x["force_change_at_logon"] for x in ad.created)

def test_production_batch_limit(monkeypatch):
    profile("PRODUCTION",10); fakes(monkeypatch)
    with TestClient(app) as c:
        login(c); c.post("/upload",files={"file":("u.csv",master(20),"text/csv")},data={"workflow_mode":"manual_bulk"},follow_redirects=False)
        with conn() as db: up=db.execute("SELECT id FROM upload_batches").fetchone()["id"]
        c.post(f"/workflow/{up}/generate",data={"quantity":"20"},follow_redirects=False)
    with conn() as db: assert db.execute("SELECT COUNT(*) c FROM migration_batches").fetchone()["c"]==0

def test_emergency_stop_blocks_writes(monkeypatch):
    profile(stop=1); fakes(monkeypatch)
    with TestClient(app) as c:
        login(c); c.post("/upload",files={"file":("u.csv",master(5),"text/csv")},data={"workflow_mode":"manual_bulk"},follow_redirects=False)
        with conn() as db: up=db.execute("SELECT id FROM upload_batches").fetchone()["id"]
        c.post(f"/workflow/{up}/generate",data={"quantity":"5"},follow_redirects=False)
        with conn() as db: mid=db.execute("SELECT id FROM migration_batches").fetchone()["id"]
        c.post(f"/migration-batch/{mid}/provision",follow_redirects=False)
    with conn() as db:
        assert db.execute("SELECT COUNT(*) c FROM users WHERE ad_group_status='member'").fetchone()["c"]==0
