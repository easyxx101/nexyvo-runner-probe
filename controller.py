"""Generic manual controller: private input fetch, credential-free execution, sealed evidence."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from envelope import canonical, context, public_key, seal, LIMIT
from prerequisites import preflight

MAX_INPUT = 256 * 1024 * 1024
PUBLIC_FIELDS = {'status', 'failed_stage', 'capacity', 'guest', 'readiness', 'fresh_starts',
    'app_tests', 'security_tests', 'restart_probes', 'stress_rounds', 'stress_invocations',
    'stress_cases', 'cleanup', 'identity_stable', 'recognized_crashes'}
STAGES = {'GUARD', 'FETCH', 'HOST_TESTS', 'KVM', 'CAPACITY', 'SDK', 'BOOT', 'GUEST', 'READINESS',
    'FRESH', 'INSTRUMENTATION', 'STRESS', 'CLEANUP', 'INSPECTION', 'EXECUTION', 'SEAL', 'NONE'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url, token=None, archive=False):
    """Bounded official redirects; never forward credentials to artifact storage."""
    opener = urllib.request.build_opener(NoRedirect())
    for _ in range(4):
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ''
        allowed = host in {'api.github.com', 'codeload.github.com'} or host.endswith('.blob.core.windows.net')
        if parsed.scheme != 'https' or parsed.port not in {None,443} or not allowed or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('Refused download boundary')
        headers = {'User-Agent': 'reviewed-manual-controller', 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28'}
        if token and (host == 'api.github.com' or archive and host == 'codeload.github.com'):
            headers['Authorization'] = 'Bearer '+token
        try:
            with opener.open(urllib.request.Request(url, headers=headers), timeout=60) as response:
                raw = response.read(MAX_INPUT+1)
                if len(raw) > MAX_INPUT:
                    raise ValueError('Input size bound')
                return raw
        except urllib.error.HTTPError as error:
            if error.code not in {301, 302, 303, 307, 308}:
                raise RuntimeError('Input API refused') from None
            url = error.headers.get('Location', '')
    raise RuntimeError('Redirect bound')


def api(path, token):
    return json.loads(request('https://api.github.com/'+path, token))


def validate_plan(plan):
    required = {'repository', 'harness_sha', 'harness_tree_sha', 'artifact_id', 'artifact_run_id',
        'artifact_sha256', 'apk_source_sha', 'apk_files', 'executor', 'controller_files'}
    if not isinstance(plan, dict) or set(plan) != required:
        raise ValueError('Invalid private input plan')
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', plan['repository'])
            or any(not re.fullmatch(r'[0-9a-f]{40}', plan[k]) for k in ['harness_sha','harness_tree_sha','apk_source_sha'])
            or any(type(plan[k]) is not int or plan[k] <= 0 for k in ['artifact_id','artifact_run_id'])
            or not re.fullmatch(r'[0-9a-f]{64}', plan['artifact_sha256'])
            or plan['executor'] != 'ci/run_public_linux_m8.py'
            or not isinstance(plan['apk_files'], dict) or len(plan['apk_files']) != 3):
        raise ValueError('Invalid pinned private inputs')
    for path, digest in plan['apk_files'].items():
        if not safe_path(path) or not path.endswith('.apk') or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Invalid APK pins')
    if set(plan['controller_files']) != {'controller.py', 'envelope.py', 'prerequisites.py', 'requirements.lock', '.github/workflows/encrypted-validation.yml'}:
        raise ValueError('Incomplete public controller pins')
    for digest in plan['controller_files'].values():
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Invalid controller pin')
    return plan


def safe_path(name):
    path = PurePosixPath(name)
    return bool(name) and '\\' not in name and not path.is_absolute() and not any(
        p in {'.','..',''} for p in name.split('/')) and ':' not in name


def source_extract(raw, root, expected_tree):
    """Verify every tracked blob, reject links/traversal/duplicates before writing."""
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        seen, selected, total = set(), [], 0
        prefix = None
        for item in archive.infolist():
            if item.is_dir():
                continue
            bits = item.filename.split('/', 1)
            if len(bits) != 2 or not safe_path(bits[1]):
                raise ValueError('Invalid source archive path')
            if prefix is None: prefix = bits[0]
            if bits[0] != prefix or bits[1] in seen or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Ambiguous source archive')
            seen.add(bits[1]); total += item.file_size
            if total > LIMIT or item.file_size > MAX_INPUT or len(seen) > 10000:
                raise ValueError('Source archive bound')
            data = archive.read(item)
            blob = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            expected = expected_tree.get(bits[1])
            if not expected or expected['sha'] != blob or expected['mode'] not in {'100644','100755'}:
                raise ValueError('Source blob provenance mismatch')
            selected.append((bits[1], data, expected['mode']))
        if seen != set(expected_tree):
            raise ValueError('Incomplete pinned source archive')
        for name, data, mode in selected:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o755 if mode == '100755' else 0o644)
    return [{'path': name, 'git_blob_sha': expected_tree[name]['sha'],
        'git_mode':mode,'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)} for name, data, mode in selected]


def apk_extract(raw, target, pins):
    if hashlib.sha256(raw).hexdigest() != pins['artifact_sha256']:
        raise ValueError('APK archive digest mismatch')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        files = [x for x in archive.infolist() if not x.is_dir()]
        if len(files) != 3 or {x.filename for x in files} != set(pins['apk_files']):
            raise ValueError('Unexpected APK archive contents')
        for item in files:
            if stat.S_ISLNK(item.external_attr >> 16) or item.file_size > 128*1024*1024:
                raise ValueError('Invalid APK archive entry')
            data = archive.read(item)
            if hashlib.sha256(data).hexdigest() != pins['apk_files'][item.filename]:
                raise ValueError('APK byte provenance mismatch')
            path = target / item.filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)


def guard_runs(runs, campaign, run_id):
    title = 'Encrypted validation '+campaign
    matches = [r for r in runs if r.get('display_title') == title]
    if len(matches) != 1 or str(matches[0]['id']) != run_id or matches[0].get('run_attempt') != 1:
        raise ValueError('Duplicate or unconfirmed dispatch')


def root_path():
    binding = context({'campaign': os.environ['CAMPAIGN_ID'], 'run_id': os.environ['GITHUB_RUN_ID'],
        'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'controller_sha': os.environ['GITHUB_SHA']})
    return Path(os.environ['RUNNER_TEMP']) / ('encrypted-validation-'+binding['run_id']), binding


def phase(root, name, status, error=None):
    path = root/'raw/controller.json'
    value = json.loads(path.read_text()) if path.exists() else {'phases': []}
    value['phases'].append({'phase': name, 'status': status, **({'error_type': error} if error else {})})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def guard(root, binding):
    if (os.environ['GITHUB_EVENT_NAME'] != 'workflow_dispatch'
            or os.environ['GITHUB_ACTOR'] != os.environ['GITHUB_REPOSITORY_OWNER']
            or os.environ['GITHUB_TRIGGERING_ACTOR'] != os.environ['GITHUB_REPOSITORY_OWNER']
            or os.environ['GITHUB_REF'] != 'refs/heads/main'
            or binding['controller_sha'] != os.environ['REVIEWED_CONTROLLER_SHA']
            or binding['campaign'] != os.environ['AUTHORIZED_CAMPAIGN_ID']):
        raise ValueError('Owner manual dispatch required')
    token = os.environ.pop('PUBLIC_GUARD_TOKEN')
    runs = []
    for page in range(1, 4):
        result = api('repos/'+os.environ['GITHUB_REPOSITORY']+'/actions/runs?event=workflow_dispatch&per_page=100&page='+str(page), token)
        if result['total_count'] > 300:
            raise ValueError('Dispatch history bound')
        runs.extend(result['workflow_runs'])
        if len(runs) >= result['total_count']: break
    guard_runs(runs, binding['campaign'], binding['run_id'])
    public_key(os.environ['EVIDENCE_RECIPIENT'].encode('ascii'))
    root.mkdir(mode=0o700, exist_ok=False)
    (root/'raw').mkdir(mode=0o700)
    (root/'context.json').write_bytes(canonical(binding))
    phase(root, 'GUARD', 'PASSED')


def fetch(root, binding):
    token = os.environ.pop('PRIVATE_INPUT_TOKEN')
    if not token.startswith('github_pat_'):
        raise ValueError('Fine-grained input credential required')
    plan = validate_plan(json.loads(os.environ.pop('PRIVATE_EXECUTION_PLAN')))
    # Pin and verify the public controller too; no credential reaches execution.
    for name, digest in plan['controller_files'].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
            raise ValueError('Controller source mismatch')
    inputs = root/'inputs'; inputs.mkdir(mode=0o700, exist_ok=False)
    (inputs/'plan.json').write_bytes(canonical(plan))
    repo = api('repos/'+plan['repository'], token)
    if repo.get('private') is not True or repo.get('full_name') != plan['repository']:
        raise ValueError('Private input repository required')
    commit = api('repos/'+plan['repository']+'/git/commits/'+plan['harness_sha'], token)
    if commit['sha'] != plan['harness_sha'] or commit['tree']['sha'] != plan['harness_tree_sha']:
        raise ValueError('Harness commit mismatch')
    tree = api('repos/'+plan['repository']+'/git/trees/'+plan['harness_tree_sha']+'?recursive=1', token)
    if tree.get('truncated'):
        raise ValueError('Source tree truncated')
    expected = {e['path']:e for e in tree['tree'] if e['type'] != 'tree'}
    source = request('https://api.github.com/repos/'+plan['repository']+'/zipball/'+plan['harness_sha'], token, archive=True)
    (inputs/'source.zip').write_bytes(source)
    manifest = source_extract(source, root/'harness', expected)
    (inputs/'source-manifest.json').write_bytes(canonical({'harness_sha':plan['harness_sha'],
        'tree_sha':plan['harness_tree_sha'], 'archive_sha256':hashlib.sha256(source).hexdigest(), 'files':manifest}))
    artifacts = api('repos/'+plan['repository']+'/actions/runs/'+str(plan['artifact_run_id'])+'/artifacts', token)
    selected = [a for a in artifacts['artifacts'] if a['id'] == plan['artifact_id']]
    if (len(selected) != 1 or selected[0]['expired'] or selected[0]['digest'] != 'sha256:'+plan['artifact_sha256']
            or selected[0].get('workflow_run',{}).get('id') != plan['artifact_run_id']
            or selected[0].get('workflow_run',{}).get('head_sha') != plan['apk_source_sha']):
        raise ValueError('Pinned APK artifact unavailable or changed')
    (inputs/'artifact.json').write_bytes(canonical(selected[0]))
    apks = request('https://api.github.com/repos/'+plan['repository']+'/actions/artifacts/'+str(plan['artifact_id'])+'/zip', token)
    (inputs/'apks.zip').write_bytes(apks)
    apk_extract(apks, root/'harness/android-player', plan)
    token = None
    phase(root, 'FETCH', 'PASSED')


def kvm_observation(open_readwrite=False):
    """Fixed device only; retain finite categories, never exception strings."""
    path = Path('/dev/kvm')
    result = {'device_present':False, 'character_device':False, 'symlink':False,
              'mode':None, 'rw_access':False, 'open_readwrite':False, 'failure_category':'NONE'}
    try:
        info = path.lstat()
        result.update(device_present=True, character_device=stat.S_ISCHR(info.st_mode),
                      symlink=stat.S_ISLNK(info.st_mode), mode=oct(stat.S_IMODE(info.st_mode)),
                      rw_access=os.access(path,os.R_OK|os.W_OK))
        if not result['character_device'] or result['symlink']:
            result['failure_category']='KVM_DEVICE_INVALID'
        elif open_readwrite:
            fd=os.open(path,os.O_RDWR|os.O_CLOEXEC)
            os.close(fd)
            result['open_readwrite']=True
    except OSError as error:
        import errno
        result['failure_category']=('KVM_DEVICE_ABSENT' if error.errno==errno.ENOENT else
            'KVM_PERMISSION_DENIED' if error.errno in {errno.EACCES,errno.EPERM} else 'KVM_OPERATION_FAILED')
        result['error_type']=type(error).__name__
    return result


def prerequisites(root, binding):
    diagnostic={'status':'RUNNING','operation':'KVM_DEVICE_CHECK','before':None,
                'after':None,'udev_settled':False,'settle_timeout_seconds':10}
    try:
        diagnostic['before']=kvm_observation()
        if (not diagnostic['before']['character_device'] or diagnostic['before']['symlink']
                or diagnostic['before']['failure_category']!='NONE'):
            raise RuntimeError('KVM device required')
        with (root/'raw/kvm-setup.log').open('wb') as log:
            diagnostic['operation']='UDEV_RULE'
            subprocess.run(['sudo','-n','tee','/etc/udev/rules.d/99-kvm4all.rules'],
                input=b'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"\n',
                stdout=log,stderr=subprocess.STDOUT,timeout=10,check=True)
            for operation,args,timeout in [
                    ('UDEV_RELOAD',['sudo','-n','udevadm','control','--reload-rules'],10),
                    ('UDEV_TRIGGER',['sudo','-n','udevadm','trigger','--name-match=kvm'],10),
                    ('UDEV_SETTLE',['sudo','-n','udevadm','settle','--timeout=10'],11)]:
                diagnostic['operation']=operation
                subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,timeout=timeout,check=True)
            diagnostic['udev_settled']=True
        # trigger is asynchronous. Check the actual device once after bounded
        # event completion; no permission-error retry or assumed open success.
        diagnostic['operation']='KVM_OPEN'
        diagnostic['after']=kvm_observation(open_readwrite=True)
        if (not diagnostic['after']['rw_access'] or not diagnostic['after']['open_readwrite']
                or diagnostic['after']['failure_category']!='NONE'):
            raise RuntimeError('KVM actual readwrite open refused')
        diagnostic['operation']='CAPACITY_MEASUREMENT'
        report=preflight()
        report.update(actual_kvm_open_readwrite=True, public_controller_sha=binding['controller_sha'])
        (root/'raw/actual-vm-capacity.json').write_bytes(canonical(report))
        if report['status']!='PASSED':raise RuntimeError('Actual execution VM capacity refused')
        diagnostic.update(status='PASSED',operation='COMPLETE')
        phase(root,'CAPACITY','PASSED')
    except Exception as error:
        diagnostic.update(status='FAILED',error_type=type(error).__name__)
        raise
    finally:
        (root/'raw/prerequisites-diagnostic.json').write_bytes(canonical(diagnostic))


def execution_env(environment, plan, root):
    # In particular: no GH_TOKEN, GITHUB_TOKEN, PRIVATE_*, ACTIONS_* or credential-store HOME.
    allowed = {'PATH', 'JAVA_HOME', 'ANDROID_HOME', 'LANG', 'LC_ALL', 'LD_LIBRARY_PATH', 'TMPDIR'}
    result = {k:v for k,v in environment.items() if k in allowed or re.fullmatch(r'JAVA_HOME_[0-9]+_X64', k)}
    result.update(HOME=str(root/'home'), TMPDIR=str(root/'tmp'), PYTHONUNBUFFERED='1',
        GITHUB_SHA=plan['harness_sha'], GITHUB_RUN_ID=environment['GITHUB_RUN_ID'], GITHUB_RUN_ATTEMPT='1',
        NEXYVO_APK_SOURCE_SHA=plan['apk_source_sha'], NEXYVO_STARTUP_ANR_DIAGNOSTICS='1')
    for name in ['home','tmp']:(root/name).mkdir(exist_ok=True)
    return result


def execute(root, binding):
    plan = validate_plan(json.loads((root/'inputs/plan.json').read_text()))
    env = execution_env(os.environ, plan, root)
    with (root/'raw/executor.log').open('wb') as log:
        process = subprocess.Popen([sys.executable, str(root/'harness'/plan['executor']), '--state', str(root)],
            cwd=root/'harness', env=env, stdout=log, stderr=subprocess.STDOUT,start_new_session=True)
        try:
            result = process.wait(timeout=1980)
        except subprocess.TimeoutExpired:
            process.terminate()
            try: result = process.wait(timeout=105)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL); process.wait(timeout=5); result=1
    # Save reports even if the private driver's finalizer was interrupted or
    # failed; original raw files remain in their immutable partial state.
    reports=root/'harness/android-player/build/reports/device-tests'
    retained=root/'raw/partial-device-reports'
    if reports.is_dir():
        import shutil
        shutil.copytree(reports,retained,symlinks=True)
    phase(root, 'EXECUTION', 'PASSED' if result == 0 else 'FAILED')
    return result


def pack(root):
    """Preserve completed and partial inputs/raw evidence; never include SDK/AVD state."""
    data = io.BytesIO(); total = 0
    with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for folder in ['inputs','raw']:
            for path in sorted((root/folder).rglob('*')):
                if not path.is_file(): continue
                if path.is_symlink(): raise ValueError('Evidence link refused')
                total += path.stat().st_size
                if total > LIMIT: raise ValueError('Evidence size bound')
                archive.write(path, path.relative_to(root).as_posix())
        archive.writestr('context.json', (root/'context.json').read_bytes())
    return data.getvalue()


def aggregate(raw):
    result = {k:'UNKNOWN' for k in ['capacity','guest','readiness','cleanup']}
    result.update(status='INCOMPLETE', failed_stage='NONE')
    for key in ['fresh_starts','app_tests','security_tests','restart_probes','stress_rounds','stress_invocations','stress_cases','recognized_crashes']:
        value = raw.get(key)
        if type(value) is int and 0 <= value <= 100: result[key] = value
    for key in ['capacity','guest','readiness','cleanup']:
        if raw.get(key) in {'PASSED','FAILED','UNKNOWN'}: result[key] = raw[key]
    if raw.get('status') in {'PASSED','INCOMPLETE'}: result['status'] = raw['status']
    if raw.get('failed_stage') in STAGES: result['failed_stage'] = raw['failed_stage']
    if type(raw.get('identity_stable')) is bool: result['identity_stable'] = raw['identity_stable']
    return result


def seal_evidence(root, binding):
    plaintext = pack(root)
    payload = seal(plaintext, os.environ['EVIDENCE_RECIPIENT'].encode('ascii'), binding)
    output = Path('sealed'); output.mkdir(exist_ok=False)
    (output/'evidence.bin').write_bytes(payload)
    summary_path = root/'raw/aggregate.json'
    raw = json.loads(summary_path.read_text()) if summary_path.exists() else {}
    phases=json.loads((root/'raw/controller.json').read_text()).get('phases',[])
    failures=[p for p in phases if p.get('status')=='FAILED']
    if failures:
        stage=failures[-1]['phase']
        raw=dict(raw,status='INCOMPLETE',failed_stage=stage if stage in STAGES else 'EXECUTION')
    receipt = {'schema':'EVSEAL01', 'context':binding, 'ciphertext_sha256':hashlib.sha256(payload).hexdigest(),
        'ciphertext_bytes':len(payload), 'aggregate':aggregate(raw)}
    (output/'receipt.json').write_bytes(canonical(receipt))
    print(json.dumps(receipt, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['guard','prerequisites','fetch','execute','seal'])
    args = parser.parse_args()
    root, binding = root_path()
    try:
        if args.phase == 'guard': guard(root, binding)
        elif args.phase == 'prerequisites': prerequisites(root,binding)
        elif args.phase == 'fetch': fetch(root, binding)
        elif args.phase == 'execute':
            if execute(root, binding): raise RuntimeError('Execution failed')
        else: seal_evidence(root, binding)
    except Exception as error:
        stage='CAPACITY' if args.phase=='prerequisites' else args.phase.upper()
        if (root/'context.json').exists(): phase(root, stage, 'FAILED', type(error).__name__)
        if args.phase=='prerequisites' and root.exists():
            (root/'raw/aggregate.json').write_bytes(canonical({'status':'INCOMPLETE','failed_stage':'CAPACITY','capacity':'FAILED'}))
        # Never expose exception messages, paths, command output, private hashes or API URLs.
        print(json.dumps({'phase':args.phase.upper(), 'status':'FAILED'}))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
