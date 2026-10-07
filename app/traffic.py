import os,time,json,random,urllib.request,urllib.error
SERVICE_URL=os.environ.get("CUSTOMER_URL","http://customer-service:8080/process")
ids=["784512345678","784512345679","784512345680","784512345681","784512345682"]
def send(nid):
    body=json.dumps({"national_id":nid}).encode()
    req=urllib.request.Request(SERVICE_URL,data=body,headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req,timeout=12) as r:
            print(f"traffic result status={r.status} national_id={nid}",flush=True)
    except Exception as e:
        print(f"traffic error national_id={nid} error={e}",flush=True)
while True:
    send(random.choice(ids))
    time.sleep(2)
