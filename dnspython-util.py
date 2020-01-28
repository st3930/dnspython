# coding: utf-8

# sudo yum install python-dns
# sudo pip install jsondiff
# sudo pip install ipaddress

import os
import re
import sys
import time
import datetime
import yaml
import socket
import argparse
import json
import ipaddress
from jsondiff import diff
import dns.resolver
import dns.message
import dns.rcode
import dns.rdatatype
import dns.flags

def main():

    """ load arguments """
    parser = argparse.ArgumentParser(description=u"this script args...")
    parser.add_argument("-t", "--target", type=str, help=u"default is /etc/resolv.conf mynameserver")
    parser.add_argument("-4", "--ipv4", action='store_const', const=2, help=u"default is ipv4, IPversion 4")
    parser.add_argument("-6", "--ipv6", action='store_const', const=10, help=u"default is ipv6, IPversion 6")
    parser.add_argument("-p", "--port", type=int, help=u"default is 53")
    parser.add_argument("-P", "--protocol", choices=['udp','tcp'], help=u"default is udp")
    parser.add_argument("-T", "--timeout", type=int, help=u"set Nsec, default is None")
    parser.add_argument("-l", "--list", type=str, help=u"fqdn list simple txt file. default is ./sample.txt")
    parser.add_argument("--qtype", "--qtype", type=str, nargs="*", help=u"--qtype A AAAA ..andmore default is A")
    parser.add_argument("--edns", action='store_true', help=u"--edns default is no ENDS")
    parser.add_argument("--dnssec", action='store_true', help=u"--dsnssec default is no DNSSEC")
    parser.add_argument("-n", "--numeric", type=int, help=u"fqdn max count. default is 100")
    parser.add_argument("-v", "--verbose", action='store_true', help=u"--verbose")
    parser.add_argument("-c", "--config", type=str, help=u"example is ./config.yaml")
    parser.add_argument("-d", "--diff", type=str, nargs="*", help=u"--diff file1 file2")
    args = parser.parse_args()

    """ GET DATETIME NOW """
    nowtime = def_get_now('%Y%m%d-%H%M%S')

    """ DEFAULT settings """
    conf = {
            'list':'sample.txt',
            'qtype':['A'],
            'resolv':[{'host':None, 'ip':None, 'addressfamily':2, 'protocol':'udp', 'port':53, 'timeout':None, 'edns':False, 'dnssec':False}],
            'max': 100,
            'verbose' : False,
            'sleep':{'interval':100, 'time':1},
            'output':{'index':nowtime, 'path':None}
            }

    """ CONFIG parser """
    argslist = [args.target, args.list, args.qtype, args.config]
    if not args.diff is None:
        if not len(argslist) == argslist.count(None):
            print "Error Args --diff not permit with other args"
            sys.exit(1)
        else:
            def_json_diff(args.diff)
            sys.exit(1)

    elif not args.config is None:
        conf_file= args.config
        config = def_load_config(conf_file)
        conf = def_config_parser(config, conf)

    else:
        conf = def_args_parser(args, conf)

    if conf['verbose'] is True:
        print "--verbose CONFIG Parameters ###"
        print json.dumps(conf)

    """ GET my resolv.conf nameserver ip """
    if conf['resolv'][0]['host'] is None:
        mynameserver = def_get_mynameserver()
        conf['resolv'][0]['host'] = mynameserver
        if conf['verbose'] is True:
            print "--verbose mynamesever from /etc/resolv.conf ###"
            print mynameserver

    """ FQDN parser """
    fqdnlist = def_load_fqdn(conf['list'], conf['max'])
#    print fqdnlist

    """ DNSPYTHON done """
    qtype = conf['qtype']
    sleep = conf['sleep']
    for r in conf['resolv']:
        servername = r['host']
        af = r['addressfamily']
        r['ip'] = def_get_ip(servername, af)
        if conf['verbose'] is True:
            print "--verbose target resolver ip address socket.getaddrinfo ###"
            print(r['host'], '-->', r['ip'])

        rdata = def_dns_query(fqdnlist, r, qtype, sleep)
        data = {
            servername : rdata
        }
        if conf['output']['path'] is None:
            print json.dumps(data)

        else:
            json_file_name = str(conf['output']['path']) + str(r['host']) + '_' + str(conf['output']['index']) + '.json'
            json_write = def_fwrite_rdata(rdata, json_file_name)
            print(json_file_name, ' ...succeed json to file')


""" def modules """
def def_get_now(format):
    dt_now = datetime.datetime.now()
    now = dt_now.strftime(format)

    return now

def def_load_config(conf_file):
    try:
        with open(conf_file, 'r') as f:
            config = yaml.load(f, Loader=yaml.SafeLoader)
    except:
        print "Error... read file error %s" % yaml
        sys.exit(1)

    return config

def def_config_parser(config, conf):
    if 'list' in config:
        conf['list'] = config['list']
    else:
        print "Error... error requied for fqdn list file"
        sys.exit(1)

    if 'resolv' in config:
        def_conf = conf['resolv'][0]
        conf['resolv'] = []
        for item in config['resolv']:
            if 'host' in item:
                p_host = item['host']
            else:
                p_host = def_conf['host']

            if 'addressfamily' in item:
                p_addressfamily = def_choise_varidate('addressfamily', item['addressfamily'], [2,10])
            else:
                p_addressfamily = def_conf['addressfamily']

            if 'port' in item:
                p_port = def_type_varidate('port', item['port'], int)
            else:
                p_port = def_conf['port']

            if 'protocol' in item:
                p_protocol = def_choise_varidate('protocol', item['protocol'], ['udp', 'tcp'])
            else:
                p_protocol = def_conf['protocol']

            if 'timeout' in item:
                t = def_type_varidate('timeout', item['timeout'], int)
                if t != 0:
                    p_timeout = t
                else:
                    p_timeout = None
            else:
                p_timeout = def_conf['timeout']

            if 'edns' in item:
                p_edns = def_type_varidate('edns', item['edns'], bool)
            else:
                p_edns = def_conf['edns']

            if 'dnssec' in item:
                p_dnssec = def_type_varidate('dnssec', item['dnssec'], bool)
            else:
                p_dnssec = def_conf['dnssec']

            data = {
                'host' : p_host,
                'addressfamily' : p_addressfamily,
                'port' : p_port,
                'protocol' : p_protocol,
                'timeout' : p_timeout,
                'edns' : p_edns,
                'dnssec' : p_dnssec
            }
            conf['resolv'].append(data)
    else:
        print "Error... error requied for resolv.host"
        sys.exit(1)

    if 'qtype' in config:
        conf['qtype'] = def_qdatatype_varidate(config['qtype'])

    if 'max' in config:
        conf['max'] = def_type_varidate('max', config['max'], int)

    if 'verbose' in config:
        conf['verbose'] = def_type_varidate('verbose', config['verbose'], bool)

    if 'sleep' in config:
        if 'interval' in config['sleep']:
            conf['sleep']['interval'] = def_type_varidate('interval', config['sleep']['interval'], int)
        if 'time' in config['sleep']:
            conf['sleep']['time'] = def_type_varidate('time', config['sleep']['time'], int)

    if 'output' in config:
        if 'index' in config['output']:
            conf['output']['index'] = config['output']['index']
        if 'path' in config['output']:
            conf['output']['path'] =  config['output']['path']

    return conf

def def_args_parser(args, conf):
    if not args.list is None:
        conf['list'] = args.list

    if not args.target is None:
        conf['resolv'][0]['host'] = args.target

    if not args.port is None:
        conf['resolv'][0]['port'] = def_type_varidate('port', args.port, int)

    if not args.protocol is None:
        conf['resolv'][0]['protocol'] = args.protocol

    if not args.ipv6 is None:
        conf['resolv'][0]['addressfamily'] = args.ipv6

    if not args.timeout is None:
        t = def_type_varidate('timeout', args.timeout, int)
        if t != 0:
            conf['resolv'][0]['timeout'] = t
        else:
            conf['resolv'][0]['timeout'] = None

    if not args.edns is None:
        conf['resolv'][0]['edns'] = args.edns

    if not args.dnssec is None:
        conf['resolv'][0]['dnssec'] = args.dnssec

    if not args.qtype is None:
        conf['qtype'] = def_qdatatype_varidate(args.qtype)

    if not args.numeric is None:
        conf['max'] = def_type_varidate('verbose', args.numeric, int)

    if not args.verbose is None:
        conf['verbose'] = args.verbose

    return conf

def def_type_varidate(desc, items, types):
    if type(items) is types:
        v_value = items
    else:
        print('Error...,', desc, items, 'is not', types)
        sys.exit(1)

    return v_value

def def_choise_varidate(desc, items, choises):
    if items in choises:
        v_value = items
    else:
        print('Error...,', desc, items, 'is not in', choises)
        sys.exit(1)

    return v_value

def def_qdatatype_varidate(items):
    for n in items:
        if not n in dns.rdatatype._by_text.keys():
            print "Error... error %s is nothing qtype" % n
            sys.exit(1)

    return items

def def_get_mynameserver():
    try:
        with open('/etc/resolv.conf', 'r') as f:
            n = [line for line in f if line.startswith('nameserver ')]
            mynameserver =  n[0].split()[-1].rstrip('\n')
    except:
        print "Error... read file error /etc/resolv.conf"
        sys.exit(1)

    return mynameserver

def def_get_ip(hostname, af):
    try:
        ip = ipaddress.ip_address(unicode(hostname))

    except ValueError:
        try:
            ipaddrinfo = socket.getaddrinfo(hostname, None, af)
            ip = ipaddrinfo[0][4][0]

        except:
            print "Error Get resolver ip address %s" % hostname
            sys.exit(1)

    return unicode(ip)

def def_load_fqdn(fqdn_file, max):
    try:
        with open(fqdn_file, 'r') as f:
            fqdnlist = []
            for s in f.readlines():
                fqdnlist.append(s.strip())
                if len(fqdnlist) == max:
                    break
#        print len(fqdnlist)
    except:
        print "Error... read file error %s" % fqdn_file
        sys.exit(1)

    return fqdnlist

def def_dns_query(fqdnlist, resolv, qtype, sleep):
    res = {}
    q_host = resolv['host']
    q_ip = resolv['ip']
    q_af = resolv['addressfamily']
    q_port = resolv['port']
    q_protocol = resolv['protocol']
    q_timeout = resolv['timeout']
    q_edns = resolv['edns']
    q_dnssec = resolv['dnssec']
    s_interval = sleep['interval']
    s_time = sleep['time']
    i = 1
    for f in fqdnlist:
        rr = {}
        for t in qtype:
            if s_time != 0:
                if i % s_interval == 0:
                    time.sleep(s_time)
            q = dns.message.make_query(f, t, use_edns=q_edns, want_dnssec=q_dnssec)
            if q_protocol == 'udp' :
                query = dns.query.udp
            elif q_protocol == 'tcp':
                query = dns.query.tcp
            try:
                r = query(q, q_ip, timeout=q_timeout, port=q_port, af=q_af)
                #print r
                rcode = dns.rcode.to_text(r.rcode())
                answer = []
                if not len(r.answer) is 0:
                    for a in str(r.answer[0]).split('\n'):
                        answer.append(a.split()[-1])
                        answer.sort()
            except:
                answer = "timeout"
                rcode = "timeout"

            data = {
                t:{
                    'ANSWER':answer,
                    'rcode': rcode
                }
            }
            rr.update(data)

        res.update({f:rr})

    return res

def def_fwrite_rdata(data, path):
    try:
        with open(path, 'w') as f:
            f.write(json.dumps(data))
    except:
        print "Error... write file error %s" % path
        sys.exit(1)

def def_json_diff(json_file):
    try:
        j_data = []
        for l in json_file:
            with open(l) as f:
                j_data.append(json.load(f))
        json_diff = diff(j_data[0], j_data[1], syntax='explicit', dump=True)
        print json_diff

    except:
        print "Error... diff error %s" % json_file

main()

""" changelog
2019-12-06 init by st3930
2020-01-28 bugfix resolver timeout by st3930
"""
