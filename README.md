## Intoroduction
I wanted checked query answer for many FQDN and DNS Resolver.
query response data is output by json. and this tools do 'diff' at this data.

fqdnlist template
```
google.com
youtube.com
baidu.com
tmall.com
qq.com
```
## Required
```
$ sudo yum install python-dns
$ sudo pip install jsondiff
$ sudo pip install ipaddress
```

## Confirmed version
CentOS7.6
Python2.7

## Command
```
$ python dnspython-util.py [options]
```

### args option single resolv only
```
optional arguments:
  -t TARGET, --target TARGET
                        default is /etc/resolv.conf mynameserver
  -4, --ipv4            default is ipv4, IPversion 4
  -6, --ipv6            default is ipv4, IPversion 6
  -p PORT, --port PORT  default is 53
  -P {udp,tcp}, --protocol {udp,tcp}
                        default is udp
  -T TIMEOUT, --timeout TIMEOUT
                        set Nsec, default is None
  -l LIST, --list LIST  fqdn list simple txt file. default is ./sample.txt
  --qtype [QTYPE [QTYPE ...]], --qtype [QTYPE [QTYPE ...]]
                        --qtype A AAAA ..andmore default is A
  --edns                --edns default is no ENDS
  --dnssec              --dsnssec default is no DNSSEC
  -n NUMERIC, --numeric NUMERIC
                        fqdn max count. default is 100
  -v, --verbose         --verbose
```

### many fqdn/resolv setting by yaml
```
optional arguments:
  -c CONFIG, --config CONFIG
                        example is ./config.yaml
```

### only diff
```
optional arguments:
-d [DIFF [DIFF ...]], --diff [DIFF [DIFF ...]]
                      --diff file1 file2
```

## yaml config
```
list: sample.txt                # required fqdnlist files path
max: 100                        # default => 100 fqdn max search number of record
qtype:                          # default => 'A' querytype add list.
  - A
  - AAAA
resolv:                         # default is
  - host: 8.8.8.8               # requied query target full-resolv
    addressfamily: 2            # default => '2' choise { ipv4:2, ipv6:10 }
    port: 53                    # default => '53', integer
    protocol: udp               # default => 'udp' choise | udp, tcp }
    timeout: 0                  # default => 0(disabled) set is (N>0)sec, inteeger
    ends: False                 # default => Flase, boolean
    dnssec: False               # default => Flase, boolean
sleep:
  interval: 100                 # default => sleep disable, sleep interval count of record 1/N is sleep
  time: 1                       # default => sleep disable, sleep duration time
output:
  index: test                  # default => '%Y%m%d-%H%M%S'
  path: './tmp/'                # required, if output is enable
verbose: True                  # default => Flase , boolean
```

## Comments
for extract fqdn.csv is 2nd row
```
$ cut -f2 -d',' fqdn.csv >> fqdn2.csv
```
