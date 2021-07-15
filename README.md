# fluent-plugin-go-audit-parser

[go-audit](https://github.com/slackhq/go-audit) outputs audit logs in a raw json format.

```
{
  "sequence": 1053,
  "timestamp": "1626105161.783",
  "messages": [
    {
      "type": 1300,
      "data": "arch=c000003e syscall=257 success=yes exit=0 a0=55b5827dfaf0 a1=55b5827df360 a2=55b582819870 a3=8 items=2 ppid=10366 pid=10539 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts3 ses=47 comm=\"sudo\" exe=\"/usr/bin/sudo\" key=etcpasswd"
    },
    {
    {
      "type": 1302,
      "data": "item=0 name=\"/etc/shadow\" inode=6948426 dev=fc:03 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"
    },
    {
      "type": 1327,
      "data": "proctitle=7375646F007461696C002D66002F7661722F6C6F672F676F2D61756469742E6C6F67"
    }
  ],
  "uid_map": {
    "0": "root",
    "1000": "vagrant"
  }
}
```

This [Fluentd](https://fluentd.org/) plugin transforms go-audit logs and make it easy to be handled by modern log aggregators.

```
{
  "sequence": 1053,
  "messages": {
    "syscall": {
      "type": 1300,
      "arch": "c000003e",
      "syscall": 257,
      "success": "yes",
      "exit": "0",
      "a0": "55b5827dfaf0",
      "a1": "55b5827df360",
      "a2": "55b582819870",
      "a3": "8",
      "items": "2",
      "ppid": 10366,
      "pid": 10539,
      "auid": { "id": 1000, "name": "vagrant" },
      "uid": { "id": 1000, "name": "vagrant" },
      "gid": 1000,
      "euid": { "id": 0, "name": "root" },
      "suid": { "id": 0, "name": "root" },
      "fsuid": { "id": 0, "name": "root" },
      "egid": 1000,
      "sgid": 1000,
      "fsgid": 1000,
      "tty": "pts3",
      "ses": 47,
      "comm": "sudo",
      "exe": "/usr/bin/sudo",
      "key": "etcpasswd"
    },
    "path": {
      "type": 1302,
      "item": "0",
      "name": "/etc/shadow",
      "inode": 6948416,
      "dev": "fc:03",
      "mode": "0100640",
      "ouid": { "id": 0, "name": "root" },
      "ogid": 42,
      "rdev": "00:00",
      "nametype": "NORMAL",
      "cap_fp": "0",
      "cap_fi": "0",
      "cap_fe": "0",
      "cap_fver": "0",
      "cap_frootid": "0"
    },
    "proctitle": {
      "type": 1327,
      "proctitle": "sudo tail -f /var/log/go-audit.log"
    }
  },
  "message_types": [ "syscall", "path", "proctitle" ]
}
```

## Installation

### RubyGems

```
$ gem install fluent-plugin-go-audit-parser
```

### Bundler

Add following line to your Gemfile:

```ruby
gem "fluent-plugin-go-audit-parser"
```

And then execute:

```
$ bundle
```

## Configuration

```
<source>
  @type tail
  @id go-audit.tail
  path /var/log/go-audit.log
  <parse>
    @type json
  </parse>
  tag audit
</source>

<filter audit>
  @type go_audit_parser
  @id go-audit.parser
</filter>

<match audit>
  @type stdout
  @id go-audit.stdout
</match>
```

## Copyright

* Copyright(c) 2021- haccht
* License
  * Apache License, Version 2.0
