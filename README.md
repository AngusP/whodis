Whodis?
=======

A [Redis](https://github.com/antirez/redis) 5.0 Streams-based tool to build a time-series
of MAC addresses on a network, using `arp-scan`, Python 3 and Celery on Linux.


Install
-------

The usual Python jazz

```
       $ python3 -m venv ./VENV
       $ source ./VENV/bin/activate
(VENV) $ pip install -r ./requirements.txt
```

Also get Redis, you'll need **at least** a 5.0 release candidate or a stable 5.0+ release
if you're reading this in the future.

Running
-------

Start a Redis server

```
$ redis-server ./redis.conf
```

The bundled config file is configures to run over a **UNIX socket only**, at `/tmp/whodis.sock`.
You can tweak the file to make the server daemonise if needs-be

Then start a Celery worker *with* beat running so periodic tasks work:

```
(VENV) $ ./whodis.py worker --beat --loglevel=info -E --statedb=./worker.state --concurrency=1
```

**Note*** you'll need to run as root to be able to `arp-scan`, so either actually run as root,
or you can try:

```
(VENV) $ sudo -E ./VENV/bin/python3 ./whodis.py worker --beat --loglevel=info -E --statedb=./worker.state --concurrency=1
```
