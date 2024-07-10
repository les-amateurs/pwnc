#!/usr/bin/env python
import requests
import json
from urlparse import urljoin
import multiprocessing
import os
import time

ROOT = 'http://snapshot.debian.org/'

blacklist = [
'-bin',
'-doc',
'-dbg',
'-prof',
'-source',
'-src',
'-xen',
'udeb',
'linux-libc-dev',
'-pic'
]

Q_hash        = multiprocessing.Queue()
Q_binfiles    = multiprocessing.Queue()
Q_binpackages = multiprocessing.Queue()
Q_package     = multiprocessing.Queue()

def curl(url):
    r = requests.get(url, timeout=5)
    print '%s: %s' % (r.status_code, url)
    if r.ok: return r.content

def iterate_binfiles(package, version, name):
    url  = urljoin(ROOT, 'mr/binary')
    url = urljoin(url + '/', name)
    url = urljoin(url + '/', version)
    url = urljoin(url + '/', 'binfiles')

    data = curl(url)

    hashes = [y['hash'] for y in json.loads(data)['result']]

    for hash in hashes:
        Q_hash.put((package, version, name, hash))

def iterate_binpackages(package, version):
    url  = urljoin(ROOT, 'mr/package/')
    url  = urljoin(url, package)
    url  = urljoin(url + '/', version)
    url  = urljoin(url + '/', 'binpackages')


    data = curl(url)

    names = [y['name'] for y in json.loads(data)['result']]

    for name in names:
        if 'libc' not in name:
            continue
        if any(b in name for b in blacklist):
            continue
        Q_binfiles.put((package, version, name))

def iterate_versions(package):
    url  = urljoin(ROOT, 'mr/package/')
    url  = urljoin(url, package + '/')

    data = curl(url)

    versions = [y['version'] for y in json.loads(data)['result']]

    for version in versions:
        Q_binpackages.put((package, version))

def version_worker(Q):
    for package in iter(Q.get, "STOP"):
        iterate_versions(package)

def binpackages_worker(Q):
    for (package, version) in iter(Q.get, "STOP"):
        iterate_binpackages(package, version)

def binfiles_worker(Q):
    for (package, version, name) in iter(Q.get, "STOP"):
        iterate_binfiles(package, version, name)

def hash_worker(Q):
    for (package, version, name, hash) in iter(Q.get, "STOP"):
        path = '%s-%s.deb' % (name, version)
        if not os.path.exists(path):
            url = 'http://snapshot.debian.org/file/' + hash

            data = curl(url)

            with open(path, 'wb+') as w:
                w.write(data)
                w.flush()

os.chdir('debfiles')

workers = []
queues  = {
    hash_worker: Q_hash,
    binfiles_worker: Q_binfiles,
    binpackages_worker: Q_binpackages,
    version_worker: Q_package,
}
for function, queue in queues.items():
    for w in xrange(20):
        p = multiprocessing.Process(target=function, args=(queue,))
        p.start()
        workers.append(p)

Q_package.put('glibc')
Q_package.put('eglibc')

time.sleep(5)

while not Q_package.empty(): time.sleep(1)
while not Q_binpackages.empty(): time.sleep(1)
while not Q_binfiles.empty(): time.sleep(1)
while not Q_hash.empty(): time.sleep(1)

for w in workers:
    w.terminate()