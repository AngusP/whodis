#!/usr/bin/env python3

import sys
import redis
import json
from arpscan import ArpScanner
from celery import Celery

app = Celery('events', broker='redis+socket:///tmp/whodis.sock')


def _parse_xadd(response):
    '''
    Parse the response back from the server
    '''
    timestamp, _, sequence = response.partition('-')
    return timestamp, sequence

def _flatten_to_str(thing):
    return [str(item) for sublist in tuple(thing) for item in sublist]

def truncate(s, max_len=20):
    '''
    Truncate a string
    '''
    return s if len(s) <= max_len else s[:max(0, max_len-3)] + '...'


class UnstableRedis(redis.StrictRedis):
    '''
    Implement some Redis 5.0 Streams 
    '''

    def __init__(self, *args, **kwargs):
        '''
        Initialise super and add response parsing callbacks
        '''
        super().__init__(*args, **kwargs)

        self.response_callbacks['XADD'] = _parse_xadd
        self.response_callbacks['XLEN'] = int


    def xadd(self, stream, kv_dict, ident='*', count=None):
        '''
        Add an item to a stream.
        If ident is '*', we will get an auto-generated monotonic ident
        as a response from the server
        
        `stream` is a key name
        `kv_dict` is a dict of keys and values (will be flattened to kv pairs, str)
        '''
        if count is None:
            return self.execute_command('XADD', stream, ident,
                                        *_flatten_to_str(kv_dict.items()))
        else:
            return self.execute_command('XADD', stream, ident,
                                        *_flatten_to_str(kv_dict.items()),
                                        'COUNT', int(count))


    def xlen(self, stream):
        '''
        Return the length of a stream
        '''
        return self.execute_command('XLEN', stream)


    def xrange(self, stream, start='-', stop='+'):
        '''
        Read a range from a stream
        '''
        return self.execute_command('XRANGE', stream, start, stop)


    def xread(self, *args, **kwargs):
        raise NotImplementedError()


    def xgroup(self, *args, **kwargs):
        raise NotImplementedError()


    def xreadgroup(self, *args, **kwargs):
        raise NotImplementedError()


    def xack(self, *args, **kwargs):
        raise NotImplementedError()



class Whodis(object):

    def __init__(self, r):
        '''
        Init Whodis class, which handles taking ARP scans and
        pushing them in to Redis 5.0 Streams
        '''
        self.r = r

    def set_mac_alias(self, mac_address, name):
        return self.r.hset('mac_addr_aliases', mac_address.lower(), name)

    def get_all_mac_aliases(self):
        return self.r.hgetall('mac_addr_aliases')

    def get_mac_aliases(self, *mac_addresses):
        return self.r.hmget('mac_addr_aliases', *map(lambda x: x.lower(), mac_addresses))

    def remove_mac_alias(self, mac_address):
        return self.r.hdel('mac_addr_aliases',  mac_address.lower())

    def get_ignore_macs(self):
        return self.r.smembers('mac_addrs_ignore')

    def set_ignore_macs(self, *mac_addresses):
        return self.r.sadd('mac_addrs_ignore', *map(lambda x: x.lower(), mac_addresses))

    def remove_ignored_mac(self, mac_address):
        return self.r.srem('mac_addrs_ignore', mac_address.lower())

    def set_macs(self, *mac_addresses):
        return self.r.sadd('mac_addrs', *map(lambda x: x.lower(), mac_addresses))

    def get_macs(self):
        return self.r.smembers('mac_addrs')

    def rm_macs(self, *mac_addresses):
        return self.r.srem('mac_addrs', *map(lambda x: x.lower(), mac_addresses))

    def flush_all_macs(self):
        return self.r.delete('mac_addrs')

    def push_update(self, scan):
        '''
        Push to stream
        '''
        ignore_macs = self.get_ignore_macs()
        p = self.r.pipeline()
        kvs = []
        seen_macs = set()
        for result in scan:
            # Skip any macs we've already seen
            if (result['mac'] in seen_macs or
                result['mac'] in ignore_macs):
                continue
            # Push a seen event to each MAC address
            hw_truncated = truncate(result['hw'], 15)
            p.execute_command('XADD', 'mac_ts_{}'.format(result['mac']), '*',
                              'ip', result['ip'], 'hw', hw_truncated)
            kvs.extend([result['mac'], hw_truncated])
            seen_macs.add(result['mac'])
        # Push to an aggregate stream
        p.execute_command('XADD', 'mac_ts', '*', *kvs)
        p.sadd('mac_addrs', *list(seen_macs))
        return p.execute()

    def save_configuration(self):
        '''
        Dump ignored macs and mac aliases to JSON file
        '''
        ignores = sorted(list(self.get_ignore_macs()))
        aliases = self.get_all_mac_aliases()
        with open('whodis-config.json', 'w') as f:
            json.dump({
                'aliases': aliases,
                'ignores': ignores,
            }, f, indent=4, ensure_ascii=False, sort_keys=True)

    def load_configuration(self):
        raise NotImplementedError()


testscan = [
    {'hw': '(Unknown)', 'ip': '231.218.30.167',  'mac': '00:16:3e:2c:ce:f0'},
    {'hw': '(Unknown)', 'ip': '253.63.251.160',  'mac': '00:16:3e:07:b7:01'},
    {'hw': '(Unknown)', 'ip': '118.250.201.65',  'mac': '00:16:3e:29:93:44'},
    {'hw': '(Unknown)', 'ip': '167.239.57.33',   'mac': '00:16:3e:02:12:9f'},
    {'hw': '(Unknown)', 'ip': '98.164.190.164',  'mac': '00:16:3e:2f:a4:86'},
    {'hw': '(Unknown)', 'ip': '29.130.33.50',    'mac': '00:16:3e:2b:21:ae'},
    {'hw': '(Unknown)', 'ip': '185.101.24.195',  'mac': '00:16:3e:19:ae:ec'},
    {'hw': '(Unknown)', 'ip': '116.252.251.247', 'mac': '00:16:3e:3a:17:f6'},
    {'hw': '(Unknown)', 'ip': '133.14.138.39',   'mac': '00:16:3e:47:17:ca'},
    {'hw': '(Unknown)', 'ip': '241.217.44.194',  'mac': '00:16:3e:55:37:d4'},
    {'hw': '(Unknown)', 'ip': '54.149.222.214',  'mac': '00:16:3e:32:8e:c4'},
    {'hw': '(Unknown)', 'ip': '232.236.219.211', 'mac': '00:16:3e:4e:10:ec'},
    {'hw': '(Unknown)', 'ip': '247.235.240.66',  'mac': '00:16:3e:66:44:3a'},
    {'hw': '(Unknown)', 'ip': '95.59.158.220',   'mac': '00:16:3e:2f:af:22'},
    {'hw': '(Unknown)', 'ip': '136.193.20.105',  'mac': '00:16:3e:76:3b:94'}
]


arp = ArpScanner('enp2s0', '--localnet')
r = UnstableRedis(unix_socket_path='/tmp/whodis.sock', decode_responses=True)
w = Whodis(r)



FREQUENCY = 30 * 60 # in seconds

@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    #sender.add_periodic_task(FREQUENCY, echo.s('hello world'), expires=10)
    sender.add_periodic_task(FREQUENCY,
                             arpscan_and_push.s(),
                             expires=max(10, int(FREQUENCY * 0.25)))


@app.task
def echo(string):
    print(string)


@app.task
def arpscan_and_push():
    '''
    Perform an ARP scan and push to Redis
    '''
    w.push_update(arp.scan())


if __name__ == '__main__':
    print('')
    print(' ---')
    print(' W H O D I S ?')
    print(' ---')
    if len(sys.argv) > 1:
        app.start()

