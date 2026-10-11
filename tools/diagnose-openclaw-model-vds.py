"""Read-only, sanitized diagnosis of the first bounded OpenClaw model test.

No inference, model load/unload, service actions, config writes or raw journal
messages. The journal scope is fixed to the owned Gateway unit and test window.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

VERIFIER_SHA256 = '5d584197504767f5decff45ddb1a1e4e8009caee8e69628bd8de33822d0ddb9a'
verifier_path = Path(__file__).with_name('verify-openclaw-model-vds.py')
if hashlib.sha256(verifier_path.read_bytes()).hexdigest() != VERIFIER_SHA256:
    raise RuntimeError('reviewed_model_verifier_source_drift')
spec = importlib.util.spec_from_file_location('reviewed_model_verifier', verifier_path)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def readonly_rpc_source():
    """Copy only the reviewed read-only definitions, never RPC/inference paths."""
    functions = {'existing_verification_lock', 'private_claw_config', 'bounded_metadata'}
    constants = {'MODEL_DIGEST', 'SOURCE_HASHES', 'FRAME_LIMIT'}
    selected = []
    tree = ast.parse(verifier.RPC)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            selected.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets):
            selected.append(node)
    if {n.name for n in selected if isinstance(n, ast.FunctionDef)} != functions:
        raise RuntimeError('reviewed_readonly_definition_missing')
    return ast.unparse(ast.Module(body=selected, type_ignores=[]))


DIAGNOSIS = r'''
import datetime,resource,select,signal

JOURNAL_SINCE='2026-10-11 15:27:00 UTC'
JOURNAL_ENTRIES=100
JOURNAL_BYTES=2*1024**2
MESSAGE_CHARACTERS=32768
LOG_FILE_NAME='openclaw-2026-10-11.log'
CGROUP_KEYS={
 'memory.events':('low','high','max','oom','oom_kill','oom_group_kill'),
 'memory.stat':('anon','file','kernel','kernel_stack','pagetables','shmem','slab'),
 'cpu.stat':('usage_usec','user_usec','system_usec','nr_periods','nr_throttled',
             'throttled_usec','nr_bursts','burst_usec'),
}
CLIENT_MIB=128
REQUIRED_MODEL_MIB=1920
ALLOWED_CODES=('EACCES','ENOENT','ETIMEDOUT','ECONNREFUSED','ENOMEM',
 'ECONNRESET','EPERM','ERR_MODULE_NOT_FOUND','MODULE_NOT_FOUND','UNAVAILABLE',
 'INVALID_REQUEST','AUTH_FAILED','SCOPE_MISSING','MISSING_SCOPE',
 'MODEL_NOT_FOUND','CONTEXT_LENGTH_EXCEEDED')
ALLOWED_EXCEPTIONS=('TypeError','ReferenceError','SyntaxError','RangeError',
 'AbortError','TimeoutError','PermissionError','FileNotFoundError',
 'SystemAgentInferenceUnavailableError','ProviderError','ModelNotFoundError',
 'GatewayError')
CATEGORY_PATTERNS={
 'timeout':r'\btimeout\b|timed[ -]out|ETIMEDOUT|TimeoutError',
 'oom':r'out of memory|oom[ -]kill|ENOMEM|heap limit|Killed process',
 'permission':r'\bEACCES\b|\bEPERM\b|permission denied|PermissionError',
 'missing_file':r'\bENOENT\b|FileNotFoundError|no such file',
 'provider':r'\bprovider\b|\bOllama\b|ECONNREFUSED|ECONNRESET|ProviderError',
 'model':r'\bmodel\b.{0,80}(not found|unknown|failed|missing|does not support)|MODEL_NOT_FOUND|ModelNotFoundError',
 'auth_scope':r'unauthenticated|unauthorized|forbidden|AUTH_FAILED|MISSING_SCOPE|SCOPE_MISSING|missing.{0,40}scope|scope.{0,40}(denied|required)',
 'context':r'context.{0,80}(length|window|exceed|small)|CONTEXT_LENGTH_EXCEEDED',
 'plugin':r'plugin.{0,80}(failed|error|missing|not found)|ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND|cannot find module',
}
# Fixed wording from installed/pinned 2026.9.9 primary source excerpts. These
# are lexical categories, not proof that a particular run used that stage.
TIMEOUT_PRIMARY_SOURCE_HASHES={
 'agent-exec-CT8rwfN2.mjs':'0226675495b0ea626dd44bd692a304d044d458ce26e80ccec52f54f320f93dd9',
}
TIMEOUT_SOURCE_PHRASES={
 'model_idle_timeout':'The model did not produce a response before the model idle timeout.',
 'agent_run_ceiling':'Request timed out before a response was generated.',
 'provider_request_timeout':'LLM request timed out.',
 'provider_continuation_timeout':'Provider continuation timed out',
 'profile_idle_timeout':'idle timeout (model silent)',
 'timeout_compaction':'[timeout-compaction] LLM timed out with high prompt token usage',
 'preflight_compaction':'Auto-compaction timed out',
 'gateway_request_timeout':'gateway request timeout for ',
 'websocket_handshake_timeout':'Opening handshake has timed out',
 'gateway_client_stop_timeout':'gateway client stop timed out after ',
 'node_dispatch_drain_timeout':'node lifecycle dispatch drain timed out after ',
 'agent_run_timeout_text':'Agent run timed out',
}
GENERIC_TIMEOUT_WORDING={
 'run':r'\b(?:agent )?run (?:timeout|timed out)\b|\btimeout (?:during|for) (?:the )?(?:agent )?run\b',
 'request':r'\b(?:rpc )?request (?:timeout|timed out)\b|\btimeout (?:during|for) (?:the )?request\b',
 'handshake':r'\bhandshake (?:timeout|timed out|has timed out)\b',
 'preparation':r'\b(?:preparation|preparing|prepare) (?:timeout|timed out)\b|\btimeout (?:during|for) (?:the )?preparation\b',
}

def safe_integer(value,maximum=2**50):
    if isinstance(value,int) and not isinstance(value,bool):number=value
    elif isinstance(value,str) and re.fullmatch('[0-9]{1,18}',value):number=int(value)
    else:return None
    return number if 0<=number<=maximum else None

def safe_timestamp(value):
    number=safe_integer(value,2**63-1)
    if number is None:return None
    try:return datetime.datetime.fromtimestamp(number/1000000,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except (ValueError,OverflowError,OSError):return None

def safe_service_facts(unit):
    if unit not in ('quantum-openclaw.service','ollama.service'):raise GuardError('diagnostic_unit_scope')
    properties=('ActiveState','SubState','MainPID','NRestarts','MemoryCurrent',
                'MemoryPeak','MemoryMax','MemorySwapMax','Result','ExecMainStatus',
                'CPUQuotaPerSecUSec','FragmentPath','DropInPaths')
    argv=['systemctl','show',unit]
    for key in properties:argv.extend(['-p',key])
    answer=command(argv,timeout=5,check=False)
    if answer.returncode:raise GuardError('diagnostic_service_inventory_failed')
    raw=dict(line.split('=',1) for line in answer.stdout.splitlines() if '=' in line)
    result={}
    states={'active','inactive','activating','deactivating','failed','reloading','maintenance'}
    substates={'running','start','start-pre','start-post','stop','stop-sigterm','stop-sigkill','dead','failed','exited','auto-restart'}
    outcomes={'success','exit-code','signal','core-dump','timeout','watchdog','start-limit-hit','oom-kill','resources','protocol'}
    result['active_state']=raw.get('ActiveState') if raw.get('ActiveState') in states else 'unknown'
    result['sub_state']=raw.get('SubState') if raw.get('SubState') in substates else 'unknown'
    result['result']=raw.get('Result') if raw.get('Result') in outcomes else 'unknown'
    for key,label in (('MainPID','main_pid'),('NRestarts','restarts'),('ExecMainStatus','last_exit_status')):
        result[label]=safe_integer(raw.get(key),2**31-1)
    for key,label in (('MemoryCurrent','memory_current_bytes'),('MemoryPeak','memory_peak_bytes'),('MemoryMax','memory_max_bytes'),('MemorySwapMax','memory_swap_max_bytes')):
        result[label]=safe_integer(raw.get(key))
    pid=result['main_pid']
    result['process_uid']=None
    if pid and pid>1:
        try:result['process_uid']=Path('/proc/'+str(pid)).stat().st_uid
        except (FileNotFoundError,ProcessLookupError):pass
    if unit=='quantum-openclaw.service':
        result['configured_runtime_limits_match']=(raw.get('MemoryMax')=='1073741824' and
            raw.get('MemorySwapMax')=='0' and raw.get('CPUQuotaPerSecUSec')=='250ms' and
            raw.get('FragmentPath')=='/etc/systemd/system/quantum-openclaw.service' and
            raw.get('DropInPaths')=='')
    return result

def bounded_journal():
    # No raw stderr. Read stdout under one wall/aggregate bound instead of an
    # unbounded communicate() allocation. Only our diagnostic child is killed.
    argv=['journalctl','-u','quantum-openclaw.service','--since',JOURNAL_SINCE,
          '--no-pager','-n',str(JOURNAL_ENTRIES),'-o','json',
          '--output-fields=MESSAGE,__REALTIME_TIMESTAMP']
    process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    data=b'';deadline=time.monotonic()+15
    try:
        fd=process.stdout.fileno()
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise GuardError('diagnostic_journal_timeout')
            readable,_,_=select.select([fd],[],[],remaining)
            if not readable:raise GuardError('diagnostic_journal_timeout')
            block=os.read(fd,min(65536,JOURNAL_BYTES-len(data)+1))
            if not block:break
            data+=block
            if len(data)>JOURNAL_BYTES:raise GuardError('diagnostic_journal_output_bound')
        if process.wait(timeout=5)!=0:raise GuardError('diagnostic_journal_read_failed')
        return data
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
        process.stdout.close()

def summarize_records(records):
    counts={key:0 for key in CATEGORY_PATTERNS}
    codes={};exceptions={};timestamps=[];unclassified=0;truncated=0
    timeout_phrases={key:0 for key in TIMEOUT_SOURCE_PHRASES}
    generic_timeout={key:0 for key in GENERIC_TIMEOUT_WORDING}
    unmatched_timeout=0
    for timestamp,message in records:
        if timestamp:timestamps.append(timestamp)
        if not isinstance(message,str):message=''
        if len(message)>MESSAGE_CHARACTERS:message=message[:MESSAGE_CHARACTERS];truncated+=1
        found=False
        for category,pattern in CATEGORY_PATTERNS.items():
            if re.search(pattern,message,re.I):counts[category]+=1;found=True
        for code in ALLOWED_CODES:
            if re.search(r'(?<![A-Za-z0-9_])'+code+r'(?![A-Za-z0-9_])',message):codes[code]=codes.get(code,0)+1
        for exception in ALLOWED_EXCEPTIONS:
            if re.search(r'(?<![A-Za-z0-9_])'+exception+r'(?![A-Za-z0-9_])',message):exceptions[exception]=exceptions.get(exception,0)+1
        matched_phrase=False
        for label,phrase in TIMEOUT_SOURCE_PHRASES.items():
            if phrase in message:timeout_phrases[label]+=1;matched_phrase=True
        for label,pattern in GENERIC_TIMEOUT_WORDING.items():
            if re.search(pattern,message,re.I):generic_timeout[label]+=1
        if re.search(CATEGORY_PATTERNS['timeout'],message,re.I) and not matched_phrase:unmatched_timeout+=1
        if not found:unclassified+=1
    return {'since_utc':JOURNAL_SINCE,'entries_examined':len(records),'entry_limit':JOURNAL_ENTRIES,
            'first_entry_utc':min(timestamps) if timestamps else None,
            'last_entry_utc':max(timestamps) if timestamps else None,
            'category_counts':counts,'allowed_code_counts':codes,
            'allowed_exception_counts':exceptions,'unclassified_entries':unclassified,
            'truncated_messages':truncated,'classification_only':True,'raw_messages_returned':False,
            'timeout_source_phrase_counts':timeout_phrases,
            'generic_timeout_wording_counts':generic_timeout,
            'timeout_entries_without_known_source_phrase':unmatched_timeout,
            'timeout_stage_or_run_correlation_proven':False}

def summarize_journal(data):
    if len(data)>JOURNAL_BYTES:raise GuardError('diagnostic_journal_output_bound')
    lines=data.splitlines()
    if len(lines)>JOURNAL_ENTRIES:raise GuardError('diagnostic_journal_entry_bound')
    records=[]
    for line in lines:
        entry=json.loads(line)
        if not isinstance(entry,dict):raise GuardError('diagnostic_journal_schema')
        records.append((safe_timestamp(entry.get('__REALTIME_TIMESTAMP')),entry.get('MESSAGE','')))
    return summarize_records(records)

def log_timestamp(entry):
    meta=entry.get('_meta',{})
    candidates=(entry.get('time'),meta.get('date') if isinstance(meta,dict) else None)
    for value in candidates:
        if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})',value):continue
        try:
            parsed=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
            return parsed.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        except (ValueError,OverflowError):pass
    return None

def summarize_owned_file_log(data):
    if len(data)>JOURNAL_BYTES:raise GuardError('diagnostic_file_log_output_bound')
    lines=data.splitlines();records=[];invalid=0;without_time=0;before_window=0
    for line in lines[-JOURNAL_ENTRIES:]:
        try:entry=json.loads(line)
        except (ValueError,UnicodeError):invalid+=1;continue
        if not isinstance(entry,dict):invalid+=1;continue
        timestamp=log_timestamp(entry)
        if timestamp is None:without_time+=1;continue
        if timestamp<'2026-10-11T15:27:00Z':before_window+=1;continue
        # Raw bounded JSON is used only for fixed lexical classification. No
        # message, structured argument, identifier, prompt or path is returned.
        records.append((timestamp,line.decode('utf-8',errors='replace')))
    return {**summarize_records(records),'tail_bytes_examined':len(data),
            'tail_entry_candidates':min(len(lines),JOURNAL_ENTRIES),
            'invalid_json_entries':invalid,'entries_without_valid_time':without_time,
            'entries_before_window':before_window,'older_tail_entries_omitted':max(0,len(lines)-JOURNAL_ENTRIES)}

def owned_file_log_facts(gateway):
    pid=gateway.get('main_pid')
    if not isinstance(pid,int) or pid<=1 or gateway.get('process_uid')!=CLAW_UID:
        return {'available':False,'code':'owned_log_process_identity_unavailable'}
    descriptors=[]
    try:
        proc=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);descriptors.append(proc)
        process=os.open(str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=proc);descriptors.append(process)
        identity=os.fstat(process)
        if (identity.st_uid,identity.st_gid)!=(CLAW_UID,CLAW_GID) or os.readlink('cwd',dir_fd=process)!=STATE+'/openclaw' or unit_state(SERVICES['openclaw']).get('MainPID')!=str(pid):raise GuardError('owned_log_process_identity_changed')
        # /proc/<verified live owned MainPID>/root is the sole intentional
        # procfs magic-link traversal, required to enter systemd PrivateTmp.
        root=os.open('root',os.O_RDONLY|os.O_DIRECTORY,dir_fd=process);descriptors.append(root)
        root_info=os.fstat(root)
        if (root_info.st_uid,root_info.st_gid)!=(0,0) or stat.S_IMODE(root_info.st_mode)&0o022:raise GuardError('unsafe_owned_log_mount_root')
        tmp=os.open('tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root);descriptors.append(tmp)
        tmp_info=os.fstat(tmp)
        if (tmp_info.st_uid,tmp_info.st_gid)!=(0,0) or stat.S_IMODE(tmp_info.st_mode)!=0o1777:raise GuardError('unsafe_owned_private_tmp')
        directory=os.open('openclaw',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=tmp);descriptors.append(directory)
        dir_info=os.fstat(directory)
        if (dir_info.st_uid,dir_info.st_gid)!=(CLAW_UID,CLAW_GID) or stat.S_IMODE(dir_info.st_mode)!=0o700:raise GuardError('unsafe_owned_log_directory')
        fd=os.open(LOG_FILE_NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory);descriptors.append(fd)
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or (before.st_uid,before.st_gid)!=(CLAW_UID,CLAW_GID) or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>100*1024**2:raise GuardError('unsafe_owned_log_file')
        start=max(0,before.st_size-JOURNAL_BYTES);os.lseek(fd,start,os.SEEK_SET)
        data=b'';remaining=before.st_size-start
        while remaining:
            block=os.read(fd,min(65536,remaining))
            if not block:raise GuardError('owned_log_truncated_during_read')
            data+=block;remaining-=len(block)
        after=os.fstat(fd);entry=os.stat(LOG_FILE_NAME,dir_fd=directory,follow_symlinks=False)
        fields=lambda item:(item.st_dev,item.st_ino,item.st_uid,item.st_gid,item.st_mode)
        if fields(before)!=fields(after) or fields(entry)!=fields(before) or after.st_size<before.st_size or os.fstat(process).st_ino!=identity.st_ino or os.readlink('cwd',dir_fd=process)!=STATE+'/openclaw' or unit_state(SERVICES['openclaw']).get('MainPID')!=str(pid):raise GuardError('owned_log_identity_changed_during_read')
        if start:data=data.split(b'\n',1)[1] if b'\n' in data else b''
        return {'available':True,'source':'owned_private_tmp_daily_log','bounded_tail':True,
                'older_bytes_omitted':start,**summarize_owned_file_log(data)}
    except FileNotFoundError:return {'available':False,'code':'owned_daily_log_not_found'}
    except GuardError:return {'available':False,'code':'owned_file_log_guard_failed'}
    except OSError:return {'available':False,'code':'owned_file_log_read_unavailable'}
    finally:
        for fd in reversed(descriptors):os.close(fd)

def parse_cgroup_counters(data,filename):
    if filename not in CGROUP_KEYS or len(data)>16384:raise GuardError('diagnostic_cgroup_scope_or_bound')
    counters={}
    for line in data.decode('ascii').splitlines():
        fields=line.split()
        if len(fields)==2 and fields[0] in CGROUP_KEYS[filename]:
            value=safe_integer(fields[1])
            if value is not None:counters[fields[0]]=value
    return counters

def cgroup_facts():
    answer=command(['systemctl','show','quantum-openclaw.service','-p','ControlGroup'],timeout=5,check=False)
    if answer.returncode or answer.stdout.strip()!='ControlGroup=/system.slice/quantum-openclaw.service':return {'available':False,'code':'owned_cgroup_identity_unavailable'}
    descriptors=[]
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);descriptors.append(parent)
        for name in ('sys','fs','cgroup','system.slice','quantum-openclaw.service'):
            parent=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);descriptors.append(parent)
            info=os.fstat(parent)
            if (info.st_uid,info.st_gid)!=(0,0) or stat.S_IMODE(info.st_mode)&0o022:raise GuardError('unsafe_owned_cgroup_parent')
        result={}
        for filename in CGROUP_KEYS:
            fd=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            try:
                before=os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or (before.st_uid,before.st_gid)!=(0,0) or stat.S_IMODE(before.st_mode)&0o022:raise GuardError('unsafe_owned_cgroup_counter_file')
                data=os.read(fd,16385);after=os.fstat(fd)
                if (before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode)!=(after.st_dev,after.st_ino,after.st_uid,after.st_gid,after.st_mode):raise GuardError('owned_cgroup_counter_identity_changed')
                result[filename]=parse_cgroup_counters(data,filename)
            finally:os.close(fd)
        return {'available':True,'cumulative_not_test_delta':True,'counters':result}
    except FileNotFoundError:return {'available':False,'code':'owned_cgroup_counter_not_found'}
    except GuardError:return {'available':False,'code':'owned_cgroup_guard_failed'}
    except (OSError,UnicodeError):return {'available':False,'code':'owned_cgroup_read_unavailable'}
    finally:
        for fd in reversed(descriptors):os.close(fd)

def metadata_facts():
    result={'metadata_ready':False,'expected_model_present':False,'expected_model_digest_match':False,
            'loaded_expected_count':None,'other_loaded_count':None,'loaded_context_lengths':[]}
    try:
        tags=bounded_metadata('tags');loaded=bounded_metadata('ps')
    except Exception:return result
    matches=[model for model in tags if isinstance(model,dict) and model.get('name')=='qwen3:0.6b' and model.get('model')=='qwen3:0.6b']
    expected=[model for model in loaded if isinstance(model,dict) and model.get('name')=='qwen3:0.6b']
    result.update(metadata_ready=True,expected_model_present=len(matches)==1,
                  expected_model_digest_match=len(matches)==1 and matches[0].get('digest')==MODEL_DIGEST,
                  loaded_expected_count=len(expected),other_loaded_count=len(loaded)-len(expected),
                  loaded_context_lengths=[safe_integer(model.get('context_length'),2**31-1) for model in expected])
    return result

def diagnostic_main():
    resource.setrlimit(resource.RLIMIT_AS,(CLIENT_MIB*1024**2,CLIENT_MIB*1024**2))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_CPU,(30,30));signal.alarm(90)
    lock=existing_verification_lock()
    try:
        data,_=read_fixed(INTENT);docs=validate_completed_intent(json.loads(data))
        config=private_claw_config()
        if config!=openclaw_config(docs[JOURNAL]['credentials']['token']) or config.get('tools',{}).get('deny')!=['*']:raise GuardError('diagnostic_security_policy_drift')
        for name,expected in {**SOURCE_HASHES,**TIMEOUT_PRIMARY_SOURCE_HASHES}.items():
            if immutable_digest(RELEASE+'/openclaw/node_modules/openclaw/dist/'+name)!=expected:raise GuardError('diagnostic_rpc_source_drift')
        gateway=safe_service_facts('quantum-openclaw.service')
        gateway['loopback_http_ready']=service_probe('openclaw')
        ollama=safe_service_facts('ollama.service')
        memory=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
        available_values=memory.get('MemAvailable','').split()
        available=safe_integer(available_values[0]) if available_values else None
        available=available//1024 if available is not None else None
        result={'status':'DiagnosticReady','mode':'read_only','inference':False,'model_verified':False,
                'security_policy_verified':True,'gateway':gateway,'ollama':ollama,
                'model_metadata':metadata_facts(),'memory_available_mib':available,
                'model_smoke_required_mib':REQUIRED_MODEL_MIB,
                'model_smoke_headroom_met':available is not None and available>=REQUIRED_MODEL_MIB,
                'journal':summarize_journal(bounded_journal()),
                'owned_file_log':owned_file_log_facts(gateway),'owned_cgroup':cgroup_facts()}
        output(result)
    finally:os.close(lock);signal.alarm(0)
'''


def remote_script():
    migration = verifier.migration
    return '\n'.join(['PINS='+repr(migration.base.PINS), migration.base.COMMON,
                      migration.base.REMOTE, 'import grp', migration.MIGRATION,
                      readonly_rpc_source(), DIAGNOSIS,
                      "try:\n diagnostic_main()\nexcept GuardError:\n output({'status':'Blocked','code':'diagnostic_preflight_or_bound_guard','inference':False,'model_verified':False});raise SystemExit(2)\nexcept Exception:\n output({'status':'Failed','code':'sanitized_diagnostic_exception','inference':False,'model_verified':False});raise SystemExit(3)"])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--known-hosts',default=str(Path.home()/'.ssh/known_hosts'))
    args=parser.parse_args()
    password=os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        print(json.dumps({'status':'Blocked','code':'missing_password_environment'}));return 2
    import paramiko
    client=paramiko.SSHClient();client.load_host_keys(args.known_hosts)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191',username='root',password=password,
                       allow_agent=False,look_for_keys=False,timeout=15)
        incoming,out,err=client.exec_command('python3 -B -',timeout=120)
        incoming.write(remote_script());incoming.channel.shutdown_write()
        raw=out.read(16385);error=err.read(4096);status=out.channel.recv_exit_status()
        if error or len(raw)>16384:
            print(json.dumps({'status':'Failed','code':'bounded_sanitized_report_required'}));return 3
        value=json.loads(raw);print(json.dumps(value,ensure_ascii=False));return status
    except Exception:
        print(json.dumps({'status':'Failed','code':'sanitized_ssh_diagnostic_failure'}));return 3
    finally:client.close()


if __name__=='__main__':sys.exit(main())
