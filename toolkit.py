#!/usr/bin/env python3
import argparse, datetime as dt, json, os, platform, pwd, grp, re, stat, subprocess
from pathlib import Path

VERSION='1.0.0'
HIGH_RISK={'awk','find','perl','python','python3','ruby','vim','vi','nmap','env','less','more','tar','cp','bash','sh'}
CANDIDATE_CVES={
 'CVE-2022-0847':'Dirty Pipe; candidate reference only. Verify affected versions with the distribution vendor.',
 'CVE-2016-5195':'Dirty COW; historical candidate reference. Verify affected versions with the distribution vendor.',
 'CVE-2023-0386':'OverlayFS privilege-escalation vulnerability; verify affected versions with the distribution vendor.'}

class UI:
 def __init__(self,color=True): self.color=color
 def c(self,s,c): return f'{c}{s}\033[0m' if self.color else s
 def banner(self):
  C='\033[96m'; B='\033[1m'; R='\033[0m'
  print(self.c('╔══════════════════════════════════════════════════════════════╗',C))
  print(self.c('║     LINUX PRIVILEGE ESCALATION AUTOMATION TOOLKIT          ║',C+B))
  print(self.c('║              SECURITY AUDIT / DETECTION ONLY               ║',C))
  print(self.c('╚══════════════════════════════════════════════════════════════╝',C)); print()
 def section(self,n,t): print(self.c(f'[{n}] {t}', '\033[1;94m')); print('─'*62)
 def ok(self,s): print(self.c('[+] '+s,'\033[92m'))
 def warn(self,s): print(self.c('[!] '+s,'\033[93m'))
 def err(self,s): print(self.c('[-] '+s,'\033[91m'))
 def info(self,s): print('    '+s)

def run(cmd,timeout=20):
 try:
  p=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,timeout=timeout)
  return p.returncode,p.stdout.strip(),p.stderr.strip()
 except Exception as e: return 127,'',str(e)

def finding(lst,severity,category,title,evidence,mitigation):
 lst.append({'severity':severity,'category':category,'title':title,'evidence':evidence,'mitigation':mitigation})

def scan(ui):
 data={}; findings=[]
 # 1 system
 ui.section(1,'System Information Collection')
 uid,euid=os.getuid(),os.geteuid(); user=pwd.getpwuid(uid).pw_name
 groups=set()
 try: groups.add(grp.getgrgid(os.getgid()).gr_name)
 except: pass
 for g in grp.getgrall():
  if user in g.gr_mem: groups.add(g.gr_name)
 osname='Unknown'
 try:
  txt=Path('/etc/os-release').read_text(errors='ignore'); m=re.search(r'^PRETTY_NAME="?(.*?)"?$',txt,re.M); osname=m.group(1) if m else osname
 except: pass
 data['system']={'user':user,'uid':uid,'euid':euid,'groups':sorted(groups),'kernel':platform.release(),'os':osname,'hostname':platform.node(),'privilege':'root' if euid==0 else 'limited/user'}
 ui.ok(f'User: {user} | UID/EUID: {uid}/{euid} | Privilege: {data["system"]["privilege"]}')
 ui.info(f'OS: {osname}'); ui.info(f'Kernel: {platform.release()}'); ui.info('Groups: '+(', '.join(sorted(groups)) or 'none'))
 # 2 suid/sgid
 ui.section(2,'SUID / SGID Binary Discovery')
 suid=[]; rc,out,_=run(['find','/','-xdev','-type','f','-perm','/6000','-printf','%m %u %g %p\\n'],45)
 if rc==0:
  for line in out.splitlines():
   p=line.split(' ',3)
   if len(p)==4: suid.append({'mode':p[0],'owner':p[1],'group':p[2],'path':p[3]})
 data['suid_sgid']=suid; ui.ok(f'Discovered {len(suid)} SUID/SGID file(s).')
 for x in suid:
  name=Path(x['path']).name
  if name in HIGH_RISK:
   finding(findings,'HIGH','SUID/SGID',f'Potentially sensitive SUID/SGID binary: {name}',f"{x['path']} | mode={x['mode']} owner={x['owner']}",'Review necessity, package ownership and privilege-bit configuration; remove unnecessary SUID/SGID.')
 # 3 permissions
 ui.section(3,'Weak File & Directory Permissions')
 sensitive=[]
 for f in ['/etc/passwd','/etc/shadow']:
  try:
   s=os.stat(f); mode=stat.S_IMODE(s.st_mode); sensitive.append({'path':f,'mode':oct(mode),'owner_uid':s.st_uid})
   if mode & (stat.S_IWGRP|stat.S_IWOTH): finding(findings,'HIGH','Permissions',f'Sensitive file is group/world writable: {f}',oct(mode),'Restore restrictive ownership and permissions and investigate changes.')
  except OSError as e: sensitive.append({'path':f,'error':str(e)})
 data['sensitive_permissions']=sensitive
 world=[]; rc,out,_=run(['find','/','-xdev','-type','f','-perm','-0002','-not','-path','/proc/*','-not','-path','/sys/*','-not','-path','/dev/*','-printf','%m %u %g %p\\n'],45)
 if rc==0:
  for line in out.splitlines()[:5000]:
   p=line.split(' ',3)
   if len(p)==4: world.append({'mode':p[0],'owner':p[1],'group':p[2],'path':p[3]})
 data['world_writable_files']=world; ui.ok(f'World-writable regular files: {len(world)}')
 for x in world[:100]: finding(findings,'HIGH' if x['owner']=='root' else 'MEDIUM','Permissions',f'World-writable file: {x["path"]}',f"mode={x['mode']} owner={x['owner']}",'Remove unnecessary write permission and verify ownership.')
 homes=[]
 if Path('/home').is_dir():
  for p in Path('/home').iterdir():
   try: s=p.stat(); homes.append({'path':str(p),'mode':oct(stat.S_IMODE(s.st_mode)),'owner_uid':s.st_uid})
   except: pass
 data['home_directories']=homes
 # 4 services
 ui.section(4,'Misconfigured Services')
 services=[]; rc,out,_=run(['systemctl','list-unit-files','--type=service','--no-pager','--no-legend'],25)
 if rc==0:
  for line in out.splitlines():
   parts=line.split();
   if not parts or not parts[0].endswith('.service'): continue
   name=parts[0]; rc2,cat,_=run(['systemctl','cat',name,'--no-pager'],10); text=cat if rc2==0 else ''
   userm=re.findall(r'^\s*User=(.+)$',text,re.M); execs=re.findall(r'^\s*Exec(?:Start|StartPre|StartPost)=(.+)$',text,re.M); writable=[]
   for ex in execs:
    m=re.search(r'(?<!\S)(/[^\s;]+)',ex)
    if m:
     q=m.group(1).strip('"')
     try:
      s=os.stat(q)
      if os.access(q,os.W_OK) or s.st_uid!=0: writable.append({'path':q,'owner_uid':s.st_uid,'writable':os.access(q,os.W_OK)})
     except: pass
   services.append({'name':name,'user':userm[0].strip() if userm else 'root(default)','exec':execs,'writable_targets':writable})
   if writable: finding(findings,'HIGH','Services',f'Privileged service references writable/non-root-owned target: {name}',json.dumps(writable),'Make service executable/configuration files root-owned and not writable by untrusted users.')
 data['services']=services; ui.ok(f'Systemd services reviewed: {len(services)}') if rc==0 else ui.warn('systemd unavailable/inactive; service review limited.')
 # 5 sudo
 ui.section(5,'Sudo Configuration Review')
 rc,out,err=run(['sudo','-n','-l'],10); data['sudo']={'returncode':rc,'output':out or err}
 if rc==0:
  lines=[x for x in out.splitlines() if 'NOPASSWD' in x.upper()]
  ui.ok('Non-interactive sudo policy collected.')
  if lines: finding(findings,'HIGH','Sudo','NOPASSWD rule detected','\n'.join(lines[:20]),'Review necessity and restrict passwordless commands according to least privilege.')
 else: ui.warn('sudo listing unavailable without prompting; no password was requested.')
 # 6 cron
 ui.section(6,'Cron Vulnerability Review')
 cron=[]
 for base in ['/etc/crontab','/etc/cron.d','/etc/cron.daily','/etc/cron.hourly','/etc/cron.weekly','/etc/cron.monthly']:
  p=Path(base); candidates=[p] if p.is_file() else list(p.glob('*')) if p.is_dir() else []
  for f in candidates:
   if not f.is_file(): continue
   try:
    txt=f.read_text(errors='ignore'); cron.append({'path':str(f),'content':txt[:12000]})
    for ref in re.findall(r'(?<!\S)(/[A-Za-z0-9_./-]+)',txt):
     if os.path.exists(ref):
      try:
       s=os.stat(ref)
       if os.access(ref,os.W_OK) or s.st_uid!=0: finding(findings,'HIGH','Cron',f'Root-scheduled target may be writable: {ref}',f'referenced by {f}; owner_uid={s.st_uid}; writable={os.access(ref,"W_OK")}', 'Make scheduled scripts root-owned and non-writable by untrusted users.')
      except: pass
   except: pass
 rc,out,_=run(['crontab','-l'],10)
 if rc==0: cron.append({'path':'user crontab','content':out})
 data['cron']=cron; ui.ok(f'Cron configuration sources reviewed: {len(cron)}')
 # 7 kernel
 ui.section(7,'Kernel / CVE Candidate Review')
 data['kernel_analysis']={'kernel':platform.release(),'candidates':[{'cve':k,'description':v,'status':'candidate; verify with vendor'} for k,v in CANDIDATE_CVES.items()]}
 ui.ok(f'Kernel captured: {platform.release()}'); ui.info('CVE matches are candidate references, not proof of vulnerability.')
 finding(findings,'INFO','Kernel','Kernel/CVE review requires vendor verification',platform.release(),'Keep the distribution kernel supported and verify CVE applicability using vendor advisories.')
 return data,findings

def reports(out,data,findings):
 out=Path(out); out.mkdir(parents=True,exist_ok=True); stamp=dt.datetime.now().strftime('%Y-%m-%d_%H%M%S'); counts={s:sum(f['severity']==s for f in findings) for s in ['HIGH','MEDIUM','LOW','INFO']}
 payload={'toolkit_version':VERSION,'timestamp':dt.datetime.now().isoformat(timespec='seconds'),'summary':counts,'data':data,'findings':findings}
 jp=out/f'scan_{stamp}.json'; mp=out/f'scan_{stamp}.md'; jp.write_text(json.dumps(payload,indent=2,default=str))
 lines=['# Linux Privilege Escalation Automation Toolkit — Scan Report','',f'Generated: {payload["timestamp"]}','Mode: Detection, analysis and reporting only.','','## Summary','', '| Severity | Count |','|---|---:|']+[f'| {s} | {counts[s]} |' for s in counts]+['','## System Information','']
 lines += [f'- **{k}:** {v}' for k,v in data.get('system',{}).items()]+['','## Findings','']
 for i,f in enumerate(findings,1): lines += [f'### {i}. [{f["severity"]}] {f["title"]}',f'**Category:** {f["category"]}',f'**Evidence:** {f["evidence"]}',f'**Mitigation:** {f["mitigation"]}','']
 lines += ['## SUID/SGID Inventory','']+[f'- `{x["path"]}` — mode `{x["mode"]}`, owner `{x["owner"]}`, group `{x["group"]}`' for x in data.get('suid_sgid',[])]+['','## Kernel Candidate Review','']+[f'- **{x["cve"]}:** {x["description"]}' for x in data.get('kernel_analysis',{}).get('candidates',[])]
 mp.write_text('\n'.join(lines)); return jp,mp,counts

def main():
 ap=argparse.ArgumentParser(description='CLI-only Linux privilege-escalation security auditor (detection/reporting only).'); ap.add_argument('--output',default='reports'); ap.add_argument('--no-color',action='store_true'); args=ap.parse_args(); ui=UI(not args.no_color and os.environ.get('TERM','')!='dumb'); ui.banner(); ui.info('Authorized auditing only. No exploitation or system modification.'); print()
 try: data,findings=scan(ui)
 except KeyboardInterrupt: ui.warn('Scan interrupted; no changes were made.'); return 130
 except Exception as e: ui.err(f'Unexpected scanner error: {e}'); return 1
 ui.section('R','Risk Analysis & Automated Reporting'); jp,mp,c=reports(args.output,data,findings); ui.ok(f'JSON report: {jp}'); ui.ok(f'Markdown report: {mp}'); print(); print('SCAN SUMMARY'); print('─'*62)
 for s in ['HIGH','MEDIUM','LOW','INFO']: print(f'  {s:<8} {c[s]}')
 print(); ui.ok('Security audit completed.'); return 0
if __name__=='__main__': raise SystemExit(main())
