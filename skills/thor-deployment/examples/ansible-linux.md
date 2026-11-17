# Example: THOR sweep with Ansible (Linux, macOS, Windows via WinRM)

Copy the prepared folder, run THOR, fetch the results, remove everything. Works the same for
THOR Lite (other binary name). Replaces the outdated playbook template in the THOR manual
(`thor-x64` binary, 60 MB ramfs, text-log-only).

## Prepare (control node)

```bash
# prepared THOR 11 Linux folder in ./thor-linux (updated, licenses/, config/thor.yml)
tar -czf files/thor-linux.tar.gz -C thor-linux .
```

Inventory `hosts.ini`:

```ini
[wave1]
web01.corp.internal
db01.corp.internal

[wave1:vars]
ansible_user=ansible
```

## Playbook `thor-sweep.yml`

```yaml
- name: THOR sweep (Linux)
  hosts: wave1
  become: true
  gather_facts: false
  vars:
    thor_archive: files/thor-linux.tar.gz
    thor_bin: thor-linux-64              # Lite: thor-lite-linux-64
    thor_dir: /opt/thor-sweep            # not on a noexec mount such as /tmp
    out_dir: /var/tmp/thor-results
    thor_args: "--timestamp-utc --cpu-limit 60"   # v10: "--utc --cpulimit 60 --jsonfile --jsonv2"
    max_hours: 24
  tasks:
    - name: Create program directory
      ansible.builtin.file:
        path: "{{ thor_dir }}"
        state: directory
        mode: "0700"

    - name: Unpack THOR (needs tar/gzip on the target)
      ansible.builtin.unarchive:
        src: "{{ thor_archive }}"
        dest: "{{ thor_dir }}"

    - name: Run THOR
      ansible.builtin.command: >-
        {{ thor_dir }}/{{ thor_bin }} -e {{ out_dir }} --timeout {{ max_hours }} {{ thor_args }}
      async: "{{ (max_hours + 1) * 3600 }}"
      poll: 60
      register: thor_run
      failed_when: false                 # keep going; rc != 0 = license error, timeout, abort

    - name: Report exit code
      ansible.builtin.debug:
        msg: "THOR exit code {{ thor_run.rc | default('n/a') }}"

    - name: Find result files
      ansible.builtin.find:
        paths: "{{ out_dir }}"
      register: results

    - name: Fetch results to the control node
      ansible.builtin.fetch:
        src: "{{ item.path }}"
        dest: "results/{{ inventory_hostname }}/"
        flat: true
      loop: "{{ results.files }}"

    - name: Remove THOR and local results
      ansible.builtin.file:
        path: "{{ item }}"
        state: absent
      loop:
        - "{{ thor_dir }}"
        - "{{ out_dir }}"
```

Run a wave with controlled parallelism:

```bash
ansible-playbook -i hosts.ini -f 20 thor-sweep.yml
```

`-f/--forks` (default 5) is the number of hosts scanned at the same time: this is your wave
size. Long scans need `async` (as above) so SSH timeouts don't kill THOR.

Notes:

- THOR 10.7: `--timeout` is `--max_runtime`; `--jsonfile` adds a JSON log (text log is default).
- v10 text-log triage on the control node: `grep -h "Alert:" results/*/*.txt`; v11:
  `jq` over `results/*/*.jsonl` (see `references/collecting-results.md`).
- No disk footprint wanted? Mount a tmpfs sized for the package plus results
  (`mount -t tmpfs -o size=1G,mode=0700 tmpfs /opt/thor-sweep`); `ramfs` ignores size limits.
  Keep the ThorDB in mind (`/var/lib/thor/`), or add `--no-thordb` (v10 `--nothordb`) if
  resume/delta are not needed.
- macOS targets: same playbook with `thor_bin: thor-macosx` and a macOS package; the SSH
  user's session needs Full Disk Access granted via MDM (PPPC profile) for complete coverage.
- Results can also be written straight to an NFS/SMB mount (`-e /mnt/thor-results`) instead of
  fetching; root-squash on NFS breaks that.

## Windows over WinRM

```yaml
- name: THOR sweep (Windows)
  hosts: windows_wave1
  gather_facts: false
  vars:
    thor_dir: 'C:\ProgramData\thor-sweep'
    out_dir: 'C:\ProgramData\thor-results'
  tasks:
    - name: Copy THOR folder
      ansible.windows.win_copy:
        src: thor-windows/              # trailing slash: copy the contents
        dest: '{{ thor_dir }}\'

    - name: Run THOR
      ansible.windows.win_command: '{{ thor_dir }}\thor64.exe -e {{ out_dir }} --timestamp-utc --timeout 24'
      async: 90000
      poll: 60
      register: thor_run
      failed_when: false

    - name: Find results
      ansible.windows.win_find:
        paths: '{{ out_dir }}'
      register: results

    - name: Fetch results
      ansible.builtin.fetch:
        src: '{{ item.path }}'
        dest: 'results/{{ inventory_hostname }}/'
        flat: true
      loop: '{{ results.files }}'

    - name: Clean up
      ansible.windows.win_file:
        path: '{{ item }}'
        state: absent
      loop: ['{{ thor_dir }}', '{{ out_dir }}']
```

WinRM connection variables (`ansible_connection: winrm`, transport, credentials) come from
your inventory. The WinRM user must be a local administrator. Copying the full folder per host
is slow over WinRM; for large Windows fleets a share + GPO is usually faster
(`examples/windows-share-gpo.md`).
