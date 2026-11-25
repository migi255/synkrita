"""Read-only host safety gate for Synkrita's dedicated systemd VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import stat
import subprocess
import sys


PASS, FAIL, REVIEW = 'PASS', 'FAIL', 'REQUIRES REVIEW'
DNS_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}')
BASE_SERVICES = {
    'auditd', 'apparmor', 'cron', 'chronyd', 'chrony', 'dbus', 'irqbalance', 'nginx',
    'rsyslog', 'ssh', 'sshd', 'systemd-journald', 'systemd-logind', 'systemd-networkd',
    'systemd-resolved', 'systemd-timesyncd', 'systemd-udevd', 'unattended-upgrades',
    'getty@tty1', 'serial-getty@ttyS0', 'cloud-init-local', 'cloud-init', 'cloud-config', 'cloud-final',
    'qemu-guest-agent', 'polkit', 'NetworkManager', 'firewalld', 'ufw', 'nftables',
}
SHARED_SERVICE = re.compile(r'(?:docker|containerd|podman|kube|apache|httpd|caddy|haproxy|traefik|'
                            r'postgres|mysql|mariadb|redis|mongod|rabbitmq|libvirt|jenkins)', re.I)
PATHS = (
    '/opt/synkrita', '/etc/synkrita', '/var/lib/synkrita',
    '/etc/systemd/system/synkrita.service', '/etc/nginx/conf.d/synkrita.conf',
)
UNIT = {
    'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running',
    'User': 'synkrita', 'Group': 'synkrita', 'NoNewPrivileges': 'yes',
    'ProtectSystem': 'strict', 'ProtectHome': 'yes', 'PrivateTmp': 'yes',
    'PrivateDevices': 'yes', 'ProtectKernelTunables': 'yes', 'ProtectKernelModules': 'yes',
    'ProtectKernelLogs': 'yes', 'ProtectControlGroups': 'yes', 'RestrictSUIDSGID': 'yes',
    'LockPersonality': 'yes', 'UMask': '0077', 'StateDirectory': 'synkrita',
    'StateDirectoryMode': '0700', 'CapabilityBoundingSet': '', 'AmbientCapabilities': '',
    'ReadWritePaths': '', 'BindPaths': '', 'RuntimeDirectory': '', 'CacheDirectory': '',
    'LogsDirectory': '', 'ConfigurationDirectory': '', 'Restart': 'on-failure',
    'ExecStartPre': '', 'ExecStartPost': '', 'ExecStop': '', 'ExecStopPost': '',
    'RestartUSec': '3s', 'StartLimitBurst': '3', 'StartLimitIntervalUSec': '1min',
    'MemoryMax': '536870912', 'TasksMax': '64', 'LimitNOFILE': '512', 'LimitCORE': '0',
    'FragmentPath': '/etc/systemd/system/synkrita.service',
    'WorkingDirectory': '/opt/synkrita', 'CPUQuotaPerSecUSec': '1s',
}
MANUAL = {
    'change_scope': 'Host owner approved a dedicated VM, maintenance scope and Synkrita-only paths.',
    'release_trust': 'Verified the approved revision, pinned release signature and complete inventory.',
    'ingress_policy': 'Owner verified default-deny IPv4/IPv6 and approved peers on 443 only. Public ingress stays closed until authorization.',
    'egress_policy': 'Owner verified service-UID egress enforcement, including DNS and issuer JWKS destination checks, IPv4/IPv6, and denial of metadata/private destinations.',
    'isolation_and_disk': 'Owner verified process identity and sandbox, that Synkrita owns the loopback socket, root-owned release files, effective limits and encrypted bounded state, backup and log storage.',
    'proxy_effective': 'Proxy owner verified effective config and syntax, exact vhost/routes, TLS 1.2/1.3, limits and header rules, reload scope and no impact to other services.',
    'tls_effective': 'Certificate owner verified key pairing, trust chain, hostname, protected key and renewal. Confirm served TLS on an approved peer after opening staging.',
    'oauth_provider': 'Identity owner verified approved OAuth config/provider policy and closed enrollment. Real callbacks and session behavior are staging acceptance checks.',
    'monitoring': 'Named responder, alert test route and independent redacted audit destination are ready.',
    'recovery': 'Owner verified rollback plan, independent backup/decrypt access and an isolated restore rehearsal.',
}
REQUIRED_EXPOSURE = tuple(MANUAL)


class Local:
    uid = staticmethod(os.geteuid)
    system = staticmethod(platform.system)
    machine = staticmethod(platform.machine)
    euid = staticmethod(lambda value: pwd.getpwnam(value).pw_uid)
    gid = staticmethod(lambda value: pwd.getpwnam(value).pw_gid)
    lstat = staticmethod(lambda value: Path(value).lstat())

    @staticmethod
    def read(path, limit=32768):
        with Path(path).open('rb') as f:
            value = f.read(limit + 1)
        if len(value) > limit:
            raise ValueError('input exceeds bound')
        return value.decode('utf-8')

    @staticmethod
    def command(*args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=8, check=True,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                                     'SYSTEMD_PAGER': 'cat', 'SYSTEMD_COLORS': '0'})
        return result.stdout


PROBE_ERRORS = (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError)


class Assessment:
    def __init__(self, local, phase, host, environment, attestations):
        self.local, self.phase, self.host = local, phase, host
        self.environment, self.attestations = environment, attestations
        self.checks, self.evidence, self.fingerprint = [], {}, None

    def add(self, name, status, detail, source='local'):
        self.checks.append(dict(id=name, status=status, detail=detail, source=source))

    def assess(self, name, probe, detail, hidden=None):
        try:
            ok = probe()
        except PermissionError:
            if hidden:
                self.attest(name, hidden)
            else:
                self.add(name, REVIEW, 'Local probe was denied. Ask the owner to review.')
        except FileNotFoundError:
            self.add(name, FAIL, 'Required file or command is missing.')
        except PROBE_ERRORS:
            self.add(name, REVIEW, 'Local evidence is unavailable or could not be interpreted.')
        else:
            self.add(name, PASS if ok else FAIL, detail)

    def attest(self, name, key):
        result = self.evidence.get(key)
        detail = (MANUAL | PROTECTED)[key]
        if result is None:
            self.add(name, REVIEW, detail, 'operator evidence required')
        else:
            self.add(name, PASS if result['result'] == 'verified' else FAIL, detail,
                     f'operator:{result["reference"]}')

    def bind_evidence(self):
        try:
            ident = self.local.read('/etc/machine-id', 128).strip()
            if not re.fullmatch('[a-f0-9]{32}', ident):
                raise ValueError('invalid machine identity')
            self.fingerprint = hashlib.sha256(('synkrita-preflight-v1:' + ident).encode()).hexdigest()
        except PROBE_ERRORS:
            self.add('host_binding', REVIEW, 'Unable to bind the report to this machine.')
            return
        if self.attestations is None:
            return
        try:
            record = json.loads(self.local.read(self.attestations))
            if (not isinstance(record, dict)
                    or (record['machine'], record['host'], record['phase']) != (self.fingerprint, self.host, self.phase)
                    or not REFERENCE.fullmatch(record['reviewer'])
                    or not isinstance(record['evidence'], dict)
                    or set(record['evidence']) - (MANUAL.keys() | PROTECTED.keys())
                    or any(not isinstance(value, dict) or set(value) != {'result', 'reference'}
                           or value['result'] not in ('verified', 'failed')
                           or not REFERENCE.fullmatch(value['reference']) for value in record['evidence'].values())):
                raise ValueError('unbound or invalid record')
            self.evidence = record['evidence']
            self.add('host_binding', PASS, 'Operator evidence record matches this host and phase.', 'operator')
        except PROBE_ERRORS:
            self.add('host_binding', FAIL, 'Attestations are invalid or belong to another host or phase.')

    def inventory(self):
        out = self.local.command('systemctl', 'list-units', '--type=service', '--state=active',
                                 '--no-legend', '--no-pager', '--plain')
        rows = [line.split() for line in out.splitlines() if line.strip()]
        if not rows or any(len(row) < 4 or not row[0].endswith('.service') for row in rows):
            raise ValueError('missing or malformed active-service inventory')
        services = {row[0].removesuffix('.service') for row in rows}
        unrelated = services - BASE_SERVICES - ({'synkrita'} if self.phase == 'expose' else set())
        if any(SHARED_SERVICE.match(service) for service in unrelated):
            self.add('inventory', FAIL, 'Unrelated application, proxy, database or container runtime detected.')
        elif unrelated:
            names = ', '.join(sorted(name for name in unrelated if re.fullmatch(r'[A-Za-z0-9@_.-]{1,80}', name))[:12])
            self.add('inventory', REVIEW, 'Unclassified active services require review: ' + (names or 'names omitted'))
        else:
            self.add('inventory', PASS, 'Active services match the dedicated-VM profile.')

    def listeners(self):
        out = self.local.command('ss', '-H', '-lntu')
        application, https, unexpected = False, False, set()
        for line in out.splitlines():
            columns = line.split()
            if len(columns) < 6 or columns[0] not in ('tcp', 'udp'):
                raise ValueError('unsupported socket inventory')
            proto = columns[0]
            address, port = columns[4].rsplit(':', 1)
            address = address.strip('[]').split('%', 1)[0]
            port = int(port)
            if port == 8765:
                if self.phase != 'expose' or address != '127.0.0.1' or proto != 'tcp':
                    return False
                application = True
            elif self.phase == 'expose' and (proto, port) == ('tcp', 443):
                https = True
            elif (proto, port) in {('tcp', 22), ('udp', 68), ('udp', 546)}:
                continue
            elif address not in ('::1', '127.0.0.1', '127.0.0.53', '127.0.0.54') or port != 53:
                unexpected.add(port)
        return not unexpected and (self.phase == 'prepare' or (application and https))

    def file(self, path, uid, mode, directory=False, gid=None):
        info = self.local.lstat(path)
        return ((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode)
                and stat.S_IMODE(info.st_mode) in mode and info.st_uid == uid
                and (gid is None or info.st_gid == gid))

    def absent(self, paths):
        for path in paths:
            try:
                self.local.lstat(path)
            except FileNotFoundError:
                continue
            return False
        return True

    def pristine(self):
        if not self.absent(PATHS):
            return False
        try:
            self.local.euid('synkrita')
        except KeyError:
            return True
        return False

    def effective_unit(self):
        fields = (*UNIT, 'RestrictAddressFamilies', 'RestrictNamespaces', 'ExecStart', 'MainPID', 'ControlGroup')
        output = self.local.command('systemctl', 'show', '--no-pager', '--all',
                                    '--property=' + ','.join(fields), 'synkrita.service')
        properties = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        if set(fields) - properties.keys():
            raise ValueError('unsupported or incomplete systemd properties')
        exec_prefix = '/opt/synkrita/venv/bin/python'
        argv = (f'{exec_prefix} -m synkrita remote-mcp serve --database /var/lib/synkrita/research.sqlite'
                ' --config /etc/synkrita/oauth.json')
        if (any(properties[key] != value for key, value in UNIT.items())
                or set(properties['RestrictAddressFamilies'].split()) != {'AF_UNIX', 'AF_INET', 'AF_INET6'}
                or properties['RestrictNamespaces'] != 'yes'
                or not properties['ExecStart'].startswith(f'{{ path={exec_prefix} ; argv[]={argv} ;')
                or int(properties['MainPID']) <= 1
                or properties['ControlGroup'] != '/system.slice/synkrita.service'):
            return False
        group = '/sys/fs/cgroup/system.slice/synkrita.service'
        quota, period = self.local.read(group + '/cpu.max', 128).split()
        memory = self.local.read(group + '/memory.max', 128).strip()
        tasks = self.local.read(group + '/pids.max', 128).strip()
        return ('max' not in (quota, memory, tasks) and 0 < int(quota) <= int(period)
                and 0 < int(memory) <= 536870912 and 0 < int(tasks) <= 64)

    def host_controls(self):
        self.assess('service_identity', lambda: self.local.euid('synkrita') > 0 and self.local.gid('synkrita') > 0,
                    'The configured user and group must resolve to dedicated non-root IDs.')
        self.assess('unit', self.effective_unit, 'Expected unprivileged active unit and Linux CPU, memory and task limits.')
        self.assess('release_paths', lambda: all(
            self.file(path, 0, (0o755,), directory=True) for path in ('/opt/synkrita', '/opt/synkrita/venv')
        ) and all(self.file(path, 0, (0o644,)) for path in PATHS[3:]),
            'Release directories and installed unit/proxy entry points are root-owned and non-writable by others.')
        self.assess('state', lambda: self.file('/var/lib/synkrita', self.local.euid('synkrita'), (0o700,), True)
                    and self.file('/var/lib/synkrita/research.sqlite', self.local.euid('synkrita'), (0o600,)),
                    'Dedicated non-symlink state directory and SQLite file are mode 0700/0600.', 'state_files')
        self.assess('oauth_file', self.oauth_file, 'Private closed-enrollment OAuth configuration matches the public resource.',
                    'oauth_file')
        self.assess('tls_files', self.tls_files, 'Restricted key path and a readable, current certificate matching host.',
                    'tls_files')

    def oauth_file(self):
        path = '/etc/synkrita/oauth.json'
        if not (self.file('/etc/synkrita', 0, (0o750,), True, self.local.gid('synkrita'))
                and self.file(path, 0, (0o640,), gid=self.local.gid('synkrita'))):
            return False
        try:
            config = json.loads(self.local.read(path, 8192))
            if (not isinstance(config, dict) or set(config) !=
                    {'issuer', 'resource', 'jwks_url', 'clients', 'max_token_age', 'self_registration'}):
                return False
            issuer = re.fullmatch(r'https://([a-z0-9.-]+)(?:/[A-Za-z0-9._~/\-]*)?', config['issuer'])
            jwks = re.fullmatch(r'https://([a-z0-9.-]+)/(?:[A-Za-z0-9._~/\-]+)', config['jwks_url'])
            clients = config['clients']
            return (bool(issuer and jwks and issuer[1] == jwks[1] and not issuer[1].endswith('.invalid'))
                    and config['resource'] == f'https://{self.host}/mcp' and config['self_registration'] is False
                    and type(config['max_token_age']) is int and 60 <= config['max_token_age'] <= 3600
                    and isinstance(clients, list) and 1 <= len(clients) <= 8
                    and all(re.fullmatch(r'[!-~]{1,256}', client) for client in clients)
                    and len(set(clients)) == len(clients))
        except (ValueError, TypeError):
            return False

    def tls_files(self):
        base = '/etc/synkrita/tls'
        cert = base + '/fullchain.pem'
        if not (self.file(base, 0, (0o700,), True)
                and self.file(base + '/privkey.pem', 0, (0o600, 0o400))
                and self.file(cert, 0, (0o644, 0o640, 0o600, 0o440, 0o400))):
            return False
        try:
            self.local.command('openssl', 'x509', '-in', cert, '-noout', '-checkend', '86400')
            check = self.local.command('openssl', 'x509', '-in', cert, '-noout', '-checkhost', self.host)
            return check.strip() == f'Hostname {self.host} does match certificate'
        except subprocess.CalledProcessError:
            return False

    def run(self, container):
        if self.local.uid() == 0:
            self.add('operator_privilege', FAIL, 'Run the assessment as a regular user without sudo.')
            return self.report()
        self.assess('platform', lambda: self.local.system() == 'Linux' and self.local.machine() == 'x86_64'
                    and self.local.read('/proc/1/comm', 128).strip() == 'systemd'
                    and bool(self.local.read('/sys/fs/cgroup/cgroup.controllers', 128).strip()),
                    'Primary target is x86-64 Linux with systemd PID 1 and cgroup v2.')
        self.assess('python', lambda: self.local.command(
            'python3.13', '-I', '-c', 'import ensurepip, platform, venv; '
            'print(platform.python_implementation(), *platform.libc_ver())'
        ).split()[:2] == ['CPython', 'glibc'] and tuple(map(int, self.local.command(
            'getconf', 'GNU_LIBC_VERSION').split()[1].split('.'))) >= (2, 34),
            'The locked wheels require system CPython 3.13 with venv, ensurepip and glibc 2.34 or later.')
        self.add('dedicated_profile', PASS if self.environment == 'dedicated' else REVIEW,
                 'Only an owner-approved dedicated VM can pass this profile.')
        if container:
            self.assess('container_plan', lambda: safe_container(json.loads(self.local.read(container))),
                        'Reject unsafe Docker settings. All production container plans require a separate review.')
            self.add('container_profile', REVIEW, 'Containers are outside this deployment profile.')
        self.bind_evidence()
        try:
            self.inventory()
        except PROBE_ERRORS:
            self.add('inventory', REVIEW, 'Active service inventory could not be verified.')
        self.assess('listeners', self.listeners, 'Expected listeners only. Port 8765 must be free before setup and loopback-only before exposure.')
        self.assess('docker_socket', lambda: self.absent(('/run/docker.sock', '/var/run/docker.sock')),
                    'A host Docker socket is outside the dedicated systemd profile.')
        if self.phase == 'prepare':
            self.assess('fresh_paths', self.pristine, 'Synkrita paths and account must be absent on a fresh dedicated VM.')
        else:
            self.host_controls()
        for key in REQUIRED_EXPOSURE if self.phase == 'expose' else ('change_scope', 'release_trust'):
            self.attest(key, key)
        for key in PROTECTED.keys() & self.evidence.keys():
            if self.evidence[key]['result'] == 'failed':
                self.attest(f'owner_{key}', key)
        return self.report()

    def report(self):
        states = {check['status'] for check in self.checks}
        overall = FAIL if FAIL in states else REVIEW if REVIEW in states else PASS
        recommendation = {
            FAIL: 'Stop. Ask the host owner to resolve the issue or provide a dedicated VM.',
            REVIEW: 'Pause. Obtain the missing owner evidence or a reviewed dedicated VM.',
            PASS: 'Keep ingress closed until the authorized operator approves the next step.',
        }[overall]
        return dict(schema_version=1, phase=self.phase, host=self.host, machine=self.fingerprint,
                    overall=overall, recommendation=recommendation, checks=self.checks)


PROTECTED = {
    'state_files': 'State owner verified nonsymlink 0700/0600 paths, service ownership and SQLite integrity.',
    'oauth_file': 'Identity owner checked file ownership/mode, canonical resource and parsed configuration with the installed verifier.',
    'tls_files': 'Certificate owner checked ownership/modes, expiry and hostname from the protected directory.',
}


def safe_container(record):
    """Assess selected unsafe flags from owner-supplied Docker inspect metadata without opening a socket."""
    host, config = record['HostConfig'], record['Config']
    mounts = record['Mounts']
    if not (isinstance(mounts, list) and isinstance(host['Binds'], (list, type(None)))):
        return False
    host_mount = bool(host['Binds']) or any(m['Type'] == 'bind' or
                     'docker.sock' in m.get('Destination', '') for m in mounts)
    return (host['Privileged'] is False and not host_mount and host['NetworkMode'] != 'host'
            and all(host.get(mode) != 'host' for mode in ('PidMode', 'IpcMode', 'UsernsMode'))
            and host['ReadonlyRootfs'] is True and not host['CapAdd']
            and bool(re.fullmatch(r'[1-9][0-9]*(?::[1-9][0-9]*)?', config['User'])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('prepare', 'expose'), default='prepare')
    parser.add_argument('--host', required=True, help='Approved lowercase TLS hostname')
    parser.add_argument('--environment', choices=('dedicated', 'shared', 'rehearsal'), default='shared')
    parser.add_argument('--attestations', type=Path, help='Read owner evidence with host and phase binding')
    parser.add_argument('--container-plan', type=Path, help='Read sanitized Docker inspect object. No daemon access.')
    args = parser.parse_args()
    if len(args.host) > 253 or not re.fullmatch(rf'{DNS_LABEL}(?:\.{DNS_LABEL})+', args.host):
        parser.error('expected a lowercase DNS name')
    report = Assessment(Local(), args.phase, args.host, args.environment, args.attestations).run(args.container_plan)
    print(json.dumps(report, indent=2))
    return {PASS: 0, FAIL: 1, REVIEW: 2}[report['overall']]


if __name__ == '__main__':
    sys.exit(main())
