import time
from os import getenv
import logging
import subprocess
import json
from itertools import islice
from pathlib import Path
from ipaddress import ip_network, ip_address, ip_interface
from kubernetes import client, config


logger = logging.getLogger('naivewg')

config.load_config()
v1 = client.CoreV1Api()

# process external inputs
NODENAME = getenv('NAIVEWG_NODENAME')
if not NODENAME:
    raise ValueError('NAIVEWG_NODENAME not provided')

WG_CNI_TEMPLATE = getenv('NAIVEWG_CNI_TEMPLATE',
                         Path(__file__).parent / 'cni_conf.json.template')
WG_CNI_PATH = getenv('NAIVEWG_CNI_TEMPLATE',
                     '/etc/cni/net.d/10-naivewg.conflist')
# we save the key on node so it can stick across reboots
WG_KEYPATH = getenv('NAIVEWG_KEYPATH', '/run/wg/privkey.key')
WG_CONFPATH = getenv('NAIVEWG_CONFPATH', '/run/wg/wg.conf')
WG_PUBKEY_ANNOTATION = getenv('NAIVEWG_PUBKEY_ANNOTATION',
                              'mncni.myakshack.tdihp.github.com/naivewg-pubkey')
WG_PORT = int(getenv('NAIVEWG_PORT', '28384'))
CLUSTER_CIDR = getenv('NAIVEWG_CLUSTER_CIDR', '10.244.0.0/16')


def sh(cmd, **kwargs):
    """utility function for easier access to shell-like command line"""
    logger.debug('$ %s (%s)', cmd, kwargs)
    kw = {
        'shell': True,
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE,
        'encoding': 'UTF-8',
    }
    kw.update(kwargs)
    result = subprocess.run(cmd, **kw)
    logger.debug('$> %s', result)
    return result


def has_link(name, ns=None):
    if ns:
        r = sh(f'ip -n {ns} link show {name}')
    else:
        r = sh(f'ip link show {name}')

    return r.returncode == 0


def get_podcidr(nodename):
    node = v1.read_node(nodename)
    return ip_network(node.spec.pod_cidr)


def ensure_cni_conf(cni_template, cni_path, podcidr):
    firstpodip, = islice(podcidr, 3, 4)
    template = Path(cni_template).read_text()
    conf = template % dict(podcidr=podcidr, firstpodip=firstpodip)
    Path(cni_path).write_text(conf)


def ensure_wg_credential(wg_keypath, nodename, annotation_key):
    p = Path(wg_keypath)
    if p.exists():
        privkey = p.read_text()
        logger.debug('got privkey from file %s' % p)
    else:
        privkey = sh('wg genkey', check=True).stdout
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(privkey)
        logger.debug('written privkey to file %s' % p)

    pubkey = sh('wg pubkey', check=True, input=privkey).stdout
    logger.debug('pubkey: %s', pubkey)
    body = {'metadata': {'annotations': {annotation_key: pubkey}}}
    v1.patch_node(nodename, body)
    logger.info('pubkey annotation patched')
    

def ensure_network(clustercidr, podcidr):
    
    br0_address, wg_veth_address = islice(podcidr, 1, 3)
    br0_interface = ip_interface(str(br0_address) + '/'
                                 + str(podcidr.prefixlen))
    wg_veth_interface = ip_interface(str(wg_veth_address) + '/'
                                     + str(podcidr.prefixlen))

    logger.info('ensuring namespace wg')
    r = sh('ip -json netns', check=True)
    nslist = json.loads(r.stdout) if r.stdout else []
    if not any(ns['name'] == 'wg' for ns in nslist):
        logger.info('creating namespace wg')
        r = sh('ip netns add wg', check=True)

    logger.info('ensuring br0')
    if not has_link('br0'):
        logger.info('br0 not found, creating')
        sh('ip link add br0 type bridge', check=True)
        sh('ip link set br0 up', check=True)
    sh(f'ip address replace {br0_interface} dev br0', check=True)
    sh(f'ip route replace {clustercidr} via {wg_veth_address} dev br0',
        check=True)
    
    logger.info('ensuring vethwg')
    if not has_link('vethwg'):
        logger.info('creating vethwg')
        sh('ip link add vethwg type veth peer name veth0 netns wg', check=True)
        sh('ip link set vethwg master br0 up', check=True)
        sh('ip -n wg link set veth0 up', check=True)
    sh(f'ip -n wg address replace {wg_veth_interface} dev veth0', check=True)
    sh(f'ip -n wg route replace default via {br0_address} dev veth0',
       check=True)

    logger.info('ensuring wg0')
    if not has_link('wg0', 'wg'):
        logger.info('wg0 not found, creating')
        # we first create wg0 in ns0, then move it to wg namespace.
        sh('ip link add wg0 type wireguard', check=True)
        sh('ip link set wg0 netns wg up')
    # sh(f'ip -n wg address replace {wg_magic_ip} dev wg0', check=True)
    sh(f'ip -n wg route replace {clustercidr} dev wg0', check=True)


def ensure_wg_peers(nodename, wg_keypath, wg_confpath, wg_port, annotation_key):
    """make sure we got all peer nodes configured"""
    nodes = v1.list_node()
    peers = []
    for node in nodes.items:
        if node.metadata.name == nodename:
            continue
        
        addresses = [addr.address for addr in node.status.addresses
                     if addr.type == 'InternalIP']
        podcidr = node.spec.pod_cidr
        pubkey = node.metadata.annotations.get(annotation_key)
        if addresses and podcidr and pubkey:
            address = addresses[0]
            peers.append((pubkey, ip_address(address), ip_network(podcidr)))
        else:
            logger.warning('cannot add node %s as peer. '
                            'addresses: %s, podcidr: %s, pubkey: %s',
                            node.metadata.name, pubkey, addresses, podcidr)

    privkey = Path(wg_keypath).read_text()
    ifsection = f"[Interface]\nPrivateKey = {privkey}\nListenPort = {wg_port}\n"
    del privkey
    sections = [ifsection]
    template = "[Peer]\nPublicKey = {}\nEndpoint = {}:{}\nAllowedIPs = {}\n"
    sections.extend(template.format(pubkey, addr, wg_port, podcidr)
                    for (pubkey, addr, podcidr) in peers)
    p = Path(wg_confpath)
    p.write_text('\n'.join(sections))
    sh(f'ip netns exec wg wg syncconf wg0 {p}', check=True)


def node_network_ready(nodename):
    req = {
        'status': {
            'conditions': [
                {
                    'type': 'NetworkUnavailable',
                    'status': 'False',
                    'reason': 'naivewg configured'
                }
            ]
        }
    }
    v1.patch_node_status(nodename, req)


def main():
    logger.info('getting podcidr')
    podcidr = get_podcidr(NODENAME)
    logger.info('got pod cidr: %s', podcidr)

    logger.info('generating cni template')
    ensure_cni_conf(WG_CNI_TEMPLATE, WG_CNI_PATH, podcidr)

    logger.info('ensuring wg credential')
    ensure_wg_credential(WG_KEYPATH, NODENAME, WG_PUBKEY_ANNOTATION)

    logger.info('ensuring node local network')
    ensure_network(CLUSTER_CIDR, podcidr)
    logger.info('network ensured')

    logger.info('ensuring peers the first time')
    ensure_wg_peers(NODENAME, WG_KEYPATH, WG_CONFPATH, WG_PORT,
                    WG_PUBKEY_ANNOTATION)
    logger.info('all green, we mark node network as ready')
    node_network_ready(NODENAME)
    while True:
        logger.info('ensuring wg peers')
        ensure_wg_peers(NODENAME, WG_KEYPATH, WG_CONFPATH, WG_PORT,
                        WG_PUBKEY_ANNOTATION)
        time.sleep(60)


# we configure logging here
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
main()
