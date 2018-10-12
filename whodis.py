#!/usr/bin/env python3

import sys
import redis
import json
import arrow
import random

from arpscan import ArpScanner
from matplotlib import cm

from celery import Celery
from flask import Flask, render_template, Markup

app = Flask(__name__)
tasks = Celery('events', broker='redis+socket:///tmp/whodis.sock')

cmap = cm.get_cmap('summer_r')
colours = cmap(range(256))


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


def rgb_to_web_hex(r,g,b,a=None):
    '''
    Take RGB(A) values in [0,1] interval and produce web HEX string
    '''
    return "#%0.2X%0.2X%0.2X" % (int(r * 255), int(g * 255), int(b * 255))


def tooltip_text(cell):
    '''
    Returns the tooltip text for a cell.
    '''
    return Markup("{} : <strong>{} devices present</strong>"
                  "".format(humanise_cell(cell), int(len(cell[1])/2)))

def humanise_cell(cell):
    '''
    Take Redis event ms timestamp and humaniz/se
    '''
    return arrow.get(float(cell[0].partition('-')[0])/1000.0).humanize()


def colourmap(point, range_min=0, range_max=256):
    '''
    Take a point in the range (range_min, range_max)
    and map it on to a colour map, returning a RGB tuple
    '''
    step = (range_max - range_min) / 256
    map_position = int(float(len(point[1])/2) / step)
    return rgb_to_web_hex(*colours[map_position % 256])



def cell_class(cell):
    '''
    Decide on a cell class for the data
    TODO: Colour Scale
    '''
    length = len(cell[1])/2
    if length == 0:
        return 'grad0'
    elif length < 6:
        return 'grad1'
    elif length < 8:
        return 'grad2'
    elif length < 12:
        return 'grad3'
    else:
        return 'grad4'

app.jinja_env.filters['tooltip'] = tooltip_text
app.jinja_env.filters['display_date'] = lambda x: x # TODO
app.jinja_env.filters['elapsed_time'] = lambda x: x # TODO
app.jinja_env.filters['humanise_cell'] = humanise_cell
app.jinja_env.globals['rgb_to_hex'] = rgb_to_web_hex
app.jinja_env.globals['colourmap'] = colourmap
app.jinja_env.globals['cell_class'] = cell_class


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

    
    def xrevrange(self, stream, start='+', stop='-'):
        '''
        Read a reversed range from a stream
        '''
        return self.execute_command('XREVRANGE', stream, start, stop)


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



FREQUENCY = 15 * 60 # in seconds

@tasks.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    #sender.add_periodic_task(FREQUENCY, echo.s('hello world'), expires=10)
    sender.add_periodic_task(FREQUENCY,
                             arpscan_and_push.s(),
                             expires=max(10, int(FREQUENCY * 0.25)))


@tasks.task
def echo(string):
    print(string)


@tasks.task
def arpscan_and_push():
    '''
    Perform an ARP scan and push to Redis
    '''
    w.push_update(arp.scan())


def gen_dateranges(latest, step, count):
    '''
    Generate a list of UNIX timestamp tuples
    that cover the step amount of time (secs), going back
    count * step in the past before latest
    '''
    window_start = latest
    window_stop = None
    for i in range(count):
        window_stop = window_start.shift(seconds=-step)
        yield (window_start.timestamp, window_stop.timestamp)
        window_start = window_stop.shift(seconds=-1)


@app.route("/")
def whodis_home():
    '''
    Render default time series visualisation
    '''
    graph = {
        'data': [],
        'repo_name': 'repo_name',
    }
    steps = ['00:00', '', '01:00', '', '02:00', '', '03:00', '',
             '04:00', '', '05:00', '', '06:00', '', '07:00', '',
             '08:00', '', '09:00', '', '10:00', '', '11:00', '',
             '12:00', '', '13:00', '', '14:00', '', '15:00', '',
             '16:00', '', '17:00', '', '18:00', '', '19:00', '',
             '20:00', '', '21:00', '', '22:00', '', '21:00', '',]
    start, end = list(gen_dateranges(arrow.now(), 60*60*24, 1))[0]
    #data = r.xrange('mac_ts', start*1000, end*1000)
    data = r.xrange('mac_ts', '-', '+')
    return render_template('index.html',
                           graph=graph,
                           data=data,
                           steps=steps)


if __name__ == '__main__':
    print('')
    print(' ---')
    print(' W H O D I S ?')
    print(' ---')
    if len(sys.argv) > 1:
        tasks.start()

