import re
import os
import hashlib
import socket
import random
import os.path
import ipaddress
import yaml

from urllib.parse import urlparse
from plugins.IProxyPlugin import *
from sqlitedict import SqliteDict
from lib.ipLookupHelper import IPLookupHelper, IPGeolocationDeterminant
from datetime import datetime
import fnmatch

BANNED_AGENTS = []
OVERRIDE_BANNED_AGENTS = []
alreadyPrintedPeers = set()


class ProxyPlugin(IProxyPlugin):
    class AlterHostHeader(Exception):
        pass

    RequestsHashesDatabaseFile = '.anti-replay.sqlite'
    DynamicWhitelistFile = '.peers.sqlite'

    DefaultRedirectorConfig = {
        'destination_url': [],
        'drop_action': 'redirect',
        'action_url': ['https://google.com', ],
        'proxy_pass': {},
        'log_dropped': False,
        'report_only': False,
        'ban_blacklisted_ip_addresses': True,
        'ip_addresses_blacklist_file': 'data/banned_ips.txt',
        'banned_agents_words_file': 'data/banned_words.txt',
        'override_banned_agents_file': 'data/banned_words_override.txt',
        'mitigate_replay_attack': False,
        'whitelisted_ip_addresses': [],
        'remove_these_response_headers': [],
        'verify_peer_ip_details': True,
        'ip_details_api_keys': {},
        'ip_geolocation_requirements': {},

        'throttle_down_peer_logging': {
            'log_request_delay': 60,
            'requests_threshold': 3
        },

        'add_peers_to_whitelist_if_they_sent_valid_requests': {
            'number_of_valid_http_get_requests': 15,
            'number_of_valid_http_post_requests': 5
        },

        'policy': {
            'allow_proxy_pass': True,
            'allow_dynamic_peer_whitelisting': True,
            'drop_invalid_useragent': True,
            'drop_http_banned_header_names': True,
            'drop_http_banned_header_value': True,
            'drop_dangerous_ip_reverse_lookup': True,
            'drop_ipgeo_metadata_containing_banned_keywords': True,
            'drop_request_without_expected_header': True,
            'drop_request_without_expected_header_value': True,
            'drop_request_without_expected_http_method': True,
            'drop_request_without_expected_uri': True
        },

        'expected_headers': [],
        'expected_headers_value': {},
        'expected_http_methods': [],
        'expected_uri': []
    }

    def __init__(self, logger, proxyOptions):
        super().__init__(logger, proxyOptions)
        self.is_request = False
        self.logger = logger
        self.addToResHeaders = {}
        self.proxyOptions = proxyOptions
        self.ipLookupHelper = None
        self.origverbose = proxyOptions['verbose']
        self.ipGeolocationDeterminer = None

        self.banned_ips = {}

        for k, v in ProxyPlugin.DefaultRedirectorConfig.items():
            if k not in self.proxyOptions.keys():
                self.proxyOptions[k] = v

        open(ProxyPlugin.DynamicWhitelistFile, 'w').close()
        with SqliteDict(ProxyPlugin.DynamicWhitelistFile, autocommit=True) as mydict:
            mydict['whitelisted_ips'] = []
            mydict['peers'] = {}

    @staticmethod
    def get_name():
        return 'redirector'

    def drop_reason(self, text):
        self.logger.err(text, color='magenta')
        if not self.proxyOptions['report_only']:
            if 'X-Drop-Reason' in self.addToResHeaders.keys():
                self.addToResHeaders['X-Drop-Reason'] += '; ' + text
            else:
                self.addToResHeaders['X-Drop-Reason'] = text

    def help(self, parser):
        global BANNED_AGENTS
        global OVERRIDE_BANNED_AGENTS

        parametersRequiringDirectPath = (
            'ip_addresses_blacklist_file',
            'banned_agents_words_file',
            'override_banned_agents_file',
            'output'
        )

        proxy2BasePath = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

        if parser is not None:
            parser.add_argument('--redir-config', metavar='PATH', dest='redir_config',
                                help='Path to the redirector YAML config file. Not required if global proxy\'s config file was specified (--config) and includes options required by this plugin.')
        else:
            if not self.proxyOptions['config'] and not self.proxyOptions['redir_config']:
                self.logger.fatal('Redirector config file not specified (--redir-config)!')

            redirectorConfig = {}
            configBasePath = ''

            try:
                if not self.proxyOptions['config'] and self.proxyOptions['redir_config'] != '':
                    with open(self.proxyOptions['redir_config']) as f:
                        try:
                            redirectorConfig = yaml.load(f, Loader=yaml.FullLoader)
                        except Exception as e:
                            self.logger.fatal(f'Could not parse redirector {f} YAML file:\n\n{e}\n\n')

                    self.proxyOptions.update(redirectorConfig)

                    for k, v in ProxyPlugin.DefaultRedirectorConfig.items():
                        if k not in self.proxyOptions.keys():
                            self.proxyOptions[k] = v

                    p = os.path.join(proxy2BasePath, self.proxyOptions['redir_config'])
                    if os.path.isfile(p) or os.path.isdir(p):
                        configBasePath = p
                    else:
                        configBasePath = os.path.dirname(os.path.abspath(self.proxyOptions['redir_config']))
                else:
                    p = os.path.join(proxy2BasePath, self.proxyOptions['config'])
                    if os.path.isfile(p) or os.path.isdir(p):
                        configBasePath = p
                    else:
                        configBasePath = os.path.dirname(os.path.abspath(self.proxyOptions['config']))

                self.ipLookupHelper = IPLookupHelper(self.logger, self.proxyOptions['ip_details_api_keys'])
                self.ipGeolocationDeterminer = IPGeolocationDeterminant(self.logger, self.proxyOptions[
                    'ip_geolocation_requirements'])

                for paramName in parametersRequiringDirectPath:
                    if paramName in self.proxyOptions.keys() and self.proxyOptions[paramName] != '' and \
                            self.proxyOptions[paramName] is not None:
                        p = os.path.join(configBasePath, self.proxyOptions[paramName])
                        if not (os.path.isfile(self.proxyOptions[paramName]) or os.path.isdir(
                                self.proxyOptions[paramName])) and (os.path.isfile(p) or os.path.isdir(p)):
                            self.proxyOptions[paramName] = p
            except FileNotFoundError as e:
                self.logger.fatal(f'Redirector config file not found: ({self.proxyOptions["config"]})!')
            except Exception as e:
                self.logger.fatal(f'Unhandled exception occurred while parsing Redirector config file: {e}')

            if not self.proxyOptions['action_url'] or len(self.proxyOptions['action_url']) == 0:
                if self.proxyOptions['drop_action'] != 'reset':
                    self.logger.fatal('Action/Drop URL must be specified!')

            elif type(self.proxyOptions['action_url']) == str:
                url = self.proxyOptions['action_url']
                if ',' not in url:
                    self.proxyOptions['action_url'] = [url.strip(), ]
                else:
                    self.proxyOptions['action_url'] = [x.strip() for x in url.split(',')]

            if self.proxyOptions['proxy_pass'] is None:
                self.proxyOptions['proxy_pass'] = {}
            elif (type(self.proxyOptions['proxy_pass']) != list) and (type(self.proxyOptions['proxy_pass']) != tuple):
                self.logger.fatal('Proxy Pass must be a list of entries if used!')

            else:
                passes = {}
                num = 0

                for entry in self.proxyOptions['proxy_pass']:
                    if len(entry) < 6:
                        self.logger.fatal('Invalid Proxy Pass entry: ({}): too short!', format(entry))

                    splits = list(filter(None, entry.strip().split(' ')))

                    url = ''
                    host = ''

                    if len(splits) < 2:
                        self.logger.fatal(
                            'Invalid Proxy Pass entry: ({}): invalid syntax: <url host [options]> required!'.format(
                                entry))

                    url = splits[0].strip()
                    host = splits[1].strip()
                    scheme = ''

                    if host.startswith('https://') or host.startswith('http://'):
                        parsed = urlparse(host)

                        if len(parsed.scheme) > 0:
                            scheme = parsed.scheme

                            host = scheme + '://' + parsed.netloc

                            if len(parsed.path) > 0:
                                host += parsed.path
                            if len(parsed.query) > 0:
                                host += '?' + parsed.query
                            if len(parsed.fragment) > 0:
                                host += '#' + parsed.fragment

                        elif len(parsed.netloc) > 0:
                            host = parsed.netloc

                        else:
                            host = parsed.path
                            if len(parsed.query) > 0:
                                host += '?' + parsed.query
                            if len(parsed.fragment) > 0:
                                host += '#' + parsed.fragment
                    else:
                        host = host.strip().replace('https://', '').replace('http://', '')

                    passes[num] = {}
                    passes[num]['url'] = url
                    passes[num]['redir'] = host
                    passes[num]['scheme'] = scheme
                    passes[num]['options'] = {}

                    if len(splits) > 2:
                        opts = ' '.join(splits[2:])
                        for opt in opts.split(','):
                            opt2 = opt.split('=')
                            k = opt2[0]
                            v = ''
                            if len(opt2) == 2:
                                v = opt2[1]
                            else:
                                v = '='.join(opt2[1:])

                            passes[num]['options'][k.strip()] = v.strip()

                    if len(url) == 0 or len(host) < 4:
                        self.logger.fatal(
                            'Invalid Proxy Pass entry: (url="{}" host="{}"): either URL or host part were missing or too short (schema is ignored).',
                            format(url, host))

                    if not url.startswith('/'):
                        self.logger.fatal(
                            'Invalid Proxy Pass entry: (url="{}" host="{}"): URL must start with slash character (/).',
                            format(url, host))

                    num += 1

                if len(passes) > 0:
                    self.proxyOptions['proxy_pass'] = passes.copy()

                    lines = []
                    for num, e in passes.items():
                        what = 'host'
                        if '/' in e['redir']: what = 'target URL'

                        line = "\tRule {}. Proxy requests with URL: \"^{}$\" to {} {}".format(
                            num, e['url'], what, e['redir']
                        )

                        if len(e['options']) > 0:
                            line += " (options: "
                            opts = []
                            for k, v in e['options'].items():
                                if len(v) > 0:
                                    opts.append("{}: {}".format(k, v))
                                else:
                                    opts.append("{}".format(k))

                            line += ', '.join(opts) + ")"

                        lines.append(line)

                    self.logger.info('Collected {} proxy-pass statements: \n{}'.format(
                        len(passes), '\n'.join(lines)
                    ))


            if type(self.proxyOptions['destination_url']) == str:
                self.proxyOptions['destination_url'] = [self.proxyOptions['destination_url'], ]

            try:
                inports = []
                for ts in self.proxyOptions['destination_url']:
                    inport, scheme, host, port = self.interpretDestinationUrl(ts)
                    if inport != 0: inports.append(inport)

                    o = ''
                    if port < 1 or port > 65535: raise Exception()
                    if inport != 0:
                        if inport < 1 or inport > 65535: raise Exception()
                        o = 'originating from {} '.format(inport)

                    self.logger.dbg('Will pass inbound beacon traffic {}to {}{}:{}'.format(
                        o, scheme + '://' if len(scheme) else '', host, port
                    ))

                if len(inports) != len(self.proxyOptions['destination_url']) and len(
                        self.proxyOptions['destination_url']) > 1:
                    self.logger.fatal(
                        'Please specify inport:host:port form of destination-url parameter for each listening port of proxy2')

            except Exception as e:
                self.logger.fatal('Destination URLs does not follow <[https?://]host:port> scheme! {}'.format(str(e)))
                raise

            if (not self.proxyOptions['drop_action']) or (
                    self.proxyOptions['drop_action'] not in ['redirect', 'reset', 'proxy']):
                self.logger.fatal('Drop action must be specified as either "reset", redirect" or "proxy"!')

            if self.proxyOptions['drop_action'] == 'proxy':
                if len(self.proxyOptions['action_url']) == 0:
                    self.logger.fatal(
                        'Drop URL must be specified for proxy action - pointing from which host to fetch responses!')
                else:
                    self.logger.info('Will redirect/proxy requests to these hosts: {}'.format(
                        ', '.join(self.proxyOptions['action_url'])), color=self.logger.colors_map['cyan'])

            p = os.path.join(proxy2BasePath, self.proxyOptions['banned_agents_words_file'])
            if not os.path.isfile(p):
                p = self.proxyOptions['banned_agents_words_file']

            if not os.path.isfile(p):
                self.logger.fatal('Could not locate banned_agents_words_file file!\nTried following path:\n\t' + p)

            with open(p, 'r') as f:
                for line in f.readlines():
                    if len(line.strip()) == 0: continue
                    if line.strip().startswith('#'): continue
                    BANNED_AGENTS.append(line.strip().lower())

                self.logger.dbg(f'Loaded {len(BANNED_AGENTS)} banned words.')

            p = os.path.join(proxy2BasePath, self.proxyOptions['override_banned_agents_file'])
            if not os.path.isfile(p):
                p = self.proxyOptions['override_banned_agents_file']

            if not os.path.isfile(p):
                self.logger.fatal('Could not locate override_banned_agents_file file!\nTried following path:\n\t' + p)

            with open(p, 'r') as f:
                for line in f.readlines():
                    if len(line.strip()) == 0: continue
                    if line.strip().startswith('#'): continue
                    OVERRIDE_BANNED_AGENTS.append(line.strip().lower())

                self.logger.dbg(f'Loaded {len(OVERRIDE_BANNED_AGENTS)} whitelisted words.')

            if self.proxyOptions['ban_blacklisted_ip_addresses']:
                p = os.path.join(proxy2BasePath, self.proxyOptions['ip_addresses_blacklist_file'])
                if not os.path.isfile(p):
                    p = self.proxyOptions['ip_addresses_blacklist_file']

                if not os.path.isfile(p):
                    self.logger.fatal(
                        'Could not locate ip_addresses_blacklist_file file!\nTried following path:\n\t' + p)

                with open(p, 'r') as f:
                    for line in f.readlines():
                        l = line.strip()
                        if l.startswith('#') or len(l) < 7: continue

                        if '#' in l:
                            ip = l[:l.find('#')].strip()
                            comment = l[l.find('#') + 1:].strip()
                            self.banned_ips[ip] = comment
                        else:
                            self.banned_ips[l] = ''

                self.logger.info('Loaded {} blacklisted CIDRs.'.format(len(self.banned_ips)))

            if self.proxyOptions['mitigate_replay_attack']:
                with SqliteDict(ProxyPlugin.RequestsHashesDatabaseFile) as mydict:
                    self.logger.info('Opening request hashes SQLite from file {} to prevent Replay Attacks.'.format(
                        ProxyPlugin.RequestsHashesDatabaseFile))

            if 'policy' in self.proxyOptions.keys() and self.proxyOptions['policy'] is not None and len(
                    self.proxyOptions['policy']) > 0:
                log = 'Enabled policies:\n'
                for k, v in self.proxyOptions['policy'].items():
                    log += '\t{}: {}\n'.format(k, str(v))
                self.logger.dbg(log)
            else:
                self.logger.info("No policies defined in config. Defaults to all-set.")
                for k, v in ProxyPlugin.DefaultRedirectorConfig['policy'].items():
                    self.proxyOptions['policy'][k] = v

            if 'add_peers_to_whitelist_if_they_sent_valid_requests' in self.proxyOptions.keys() and self.proxyOptions[
                'add_peers_to_whitelist_if_they_sent_valid_requests'] is not None and len(
                self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests']) > 0:
                log = 'Dynamic peers whitelisting enabled with thresholds:\n'

                for k, v in self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests'].items():
                    if k not in ProxyPlugin.DefaultRedirectorConfig[
                        'add_peers_to_whitelist_if_they_sent_valid_requests'].keys():
                        self.logger.err("Dynamic whitelisting threshold named ({}) not supported! Skipped..".format(k))

                    log += '\t{}: {}\n'.format(k, str(v))
                self.logger.dbg(log)

            else:
                self.logger.info("Dynamic peers whitelisting disabled.")
                self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests'] = {}

    def report(self, ret, ts='', peerIP='', path='', userAgentValue='', reason=''):
        prefix = 'ALLOW'
        col = 'green'

        if self.res is not None:
            return ret

        if ret:
            prefix = 'DROP'
            col = 'magenta'

        if self.proxyOptions['report_only']:
            if ret:
                prefix = 'WOULD-BE-DROPPED'
                col = 'magenta'
                # self.logger.info(' (Report-Only) =========[X] REQUEST WOULD BE BLOCKED =======', color='magenta')
            ret = False

        if not self.req.suppress_log_entry:
            self.logger.info(
                '[{}, {}, {}, r:{}] "{}" - UA: "{}"'.format(prefix, ts, peerIP, reason, path, userAgentValue),
                color=col,
                forced=True,
                noprefix=True
            )
        return ret

    @staticmethod
    def get_mock_req(peerIP, command, path, headers):
        class Request(object):
            pass

        req = Request()
        req.method = command
        req.client_address = [peerIP, ]
        req.headers = {}
        req.uri = path
        if headers: req.headers = headers

        return req

    @staticmethod
    def get_peer_ip(req):
        regexes = {
            'first-ip': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            'forwarded-ip': r'for=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        }

        originating_ip_headers = {
            'x-forwarded-for': regexes['first-ip'],
            'forwarded': regexes['forwarded-ip'],
            'cf-connecting-ip': regexes['first-ip'],
            'true-client-ip': regexes['first-ip'],
            'x-real-ip': regexes['first-ip'],
        }

        peerIP = req.client_address[0]

        for k, v in req.headers.items():
            if k.lower() in originating_ip_headers.keys():
                res = re.findall(originating_ip_headers[k.lower()], v, re.I)
                if res and len(res) > 0:
                    peerIP = res[0]
                    break

        return peerIP

    def interpretDestinationUrl(self, ts):
        inport = 0
        host = ''
        scheme = ''
        port = 0

        try:
            _ts = ts.split(':')
            inport = int(_ts[0])
            ts = ':'.join(_ts[1:])
        except:
            pass

        u = urlparse(ts)
        scheme, _host = u.scheme, u.netloc
        if _host:
            host, _port = _host.split(':')
        else:
            host, _port = ts.split(':')

        port = int(_port)

        return inport, scheme, host, port

    def pickDestinationUrl(self, req, req_body=None, res=None, res_body=None):
        if len(self.proxyOptions['destination_url']) == 0:
            self.logger.err('No Destination URL origins specified: dropping request.')
            raise Exception(self._drop_action(req, req_body, res, res_body, False))

        self.logger.dbg('Peer reached the server at port: ' + str(req.server_port))
        for s in self.proxyOptions['destination_url']:
            u = urlparse(req.uri)
            inport, scheme, host, port = self.interpretDestinationUrl(s)
            if inport == req.server_port:
                return s
            elif inport == '':
                return s

        # return req.uri
        return random.choice(self.proxyOptions['destination_url'])

    def redirect(self, req, _target):
        # Passing the request forward.
        u = urlparse(req.uri)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        target = _target
        newhost = ''
        orighost = req.headers['Host']

        if target in self.proxyOptions['destination_url']:
            inport, scheme, host, port = self.interpretDestinationUrl(target)
            if not scheme: scheme = 'https'

            w = urlparse(target)
            scheme2, netloc2, path2 = w.scheme, w.netloc, (w.path + '?' + w.query if w.query else w.path)
            req.uri = '{}://{}:{}{}'.format(scheme, host, port, (u.path + '?' + u.query if u.query else u.path))
            newhost = host
            if port:
                newhost += ':' + str(port)

        else:
            if not target.startswith('http'):
                if req.is_ssl:
                    target = 'https://' + target
                else:
                    target = 'http://' + target

            w = urlparse(target)
            scheme2, netloc2, path2 = w.scheme, w.netloc, (w.path + '?' + w.query if w.query else w.path)
            if netloc2 == '': netloc2 = req.headers['Host']

            req.uri = '{}://{}{}'.format(scheme2, netloc2, (u.path + '?' + u.query if u.query else u.path))
            newhost = netloc2

        self.logger.dbg('Redirecting to "{}"'.format(req.uri))

        req.redirected_to_c2 = True
        req.headers[proxy2_metadata_headers['ignore_response_decompression_errors']] = "1"
        req.headers[proxy2_metadata_headers['override_host_header']] = newhost

        return None

    def response_handler(self, req, req_body, res, res_body):
        self.is_request = False
        self.logger.dbg('redirector: response_handler')
        return self._response_handler(req, req_body, res, res_body)

    def request_handler(self, req, req_body, res='', res_body=''):
        self.is_request = True
        return self._request_handler(req, req_body)

    def _request_handler(self, req, req_body):
        self.req = req
        self.req_body = req_body
        self.res = None
        self.res_body = None

        self.logger.options['verbose'] = self.origverbose if not req.suppress_log_entry else False
        peerIP = ProxyPlugin.get_peer_ip(req)

        drop_request = False
        newhost = ''

        try:
            drop_request = self.drop_check(req, req_body)
            host_action = 1

        except ProxyPlugin.AlterHostHeader as e:
            host_action = 2
            drop_request = True
            newhost = str(e)

        req.connection.no_keep_alive = drop_request

        if drop_request and host_action == 1:
            if self.proxyOptions['drop_action'] == 'proxy' and self.proxyOptions['action_url']:

                url = self.proxyOptions['action_url']
                if (type(self.proxyOptions['action_url']) == list or type(
                        self.proxyOptions['action_url']) == tuple) and len(self.proxyOptions['action_url']) > 0:
                    url = random.choice(self.proxyOptions['action_url'])
                    self.logger.dbg('Randomly chosen redirect to URL: "{}"'.format(url))

                self.logger.err('[PROXYING invalid request from {}] {} {}'.format(
                    req.client_address[0], req.method, req.uri
                ), color='cyan')

                return self.redirect(req, url)

            return self._drop_action(req, req_body, None, None)

        elif drop_request and host_action == 2:
            if newhost.startswith('http://') or newhost.startswith('https://'):
                self.logger.dbg('Altering URL to: "{}"'.format(newhost))
            else:
                self.logger.dbg('Altering host header to: "{}"'.format(newhost))

            return self.redirect(req, newhost)

        if not self.proxyOptions['report_only'] and self.proxyOptions['mitigate_replay_attack']:
            with SqliteDict(ProxyPlugin.RequestsHashesDatabaseFile, autocommit=True) as mydict:
                mydict[self._compute_request_hash(req, req_body)] = 1

        if self.proxyOptions['policy']['allow_dynamic_peer_whitelisting'] and len(
                self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests']) > 0:
            with SqliteDict(ProxyPlugin.DynamicWhitelistFile, autocommit=True) as mydict:
                if peerIP not in mydict.get('whitelisted_ips', []):

                    request_type = self._get_http_req_method_type(req)
                    key = '{}-{}'.format(request_type, peerIP)
                    prev = mydict.get(key, 0) + 1
                    mydict[key] = prev

                    a = mydict.get('http-get-{}'.format(peerIP), 0)
                    b = mydict.get('http-post-{}'.format(peerIP), 0)

                    a2 = int(self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests'][
                                 'number_of_valid_http_get_requests'])
                    b2 = int(self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests'][
                                 'number_of_valid_http_post_requests'])

                    self.logger.info(
                        'Connected peer sent {} valid http-get and {} valid http-post requests so far, out of {}/{} required to consider him temporarily trusted'.format(
                            a, b, a2, b2
                        ), color='yellow')

                    if a > a2:
                        if b > b2:
                            self.logger.info(
                                'Adding connected peer ({}) to a dynamic whitelist as it reached its thresholds: ({}, {})'.format(
                                    peerIP, a, b), color='green')
                            val = mydict.get('whitelisted_ips', [])
                            val.append(peerIP.strip())
                            mydict['whitelisted_ips'] = val

        ts = ''
        try:
            ts = self.pickDestinationUrl(req, req_body, self.res, self.res_body)
        except Exception as e:
            s = self.proxyOptions['drop_action']
            self.logger.err(f'No Destination URL provided. Falling back to drop request strategy.: {s}')
            raise Exception(str(e))

        return self.redirect(req, ts)

    def _response_handler(self, req, req_body, res, res_body):
        self.is_request = False
        self.req = req
        self.req_body = req_body
        self.res = res
        self.res_body = res_body

        self.logger.options['verbose'] = self.origverbose if not req.suppress_log_entry else False

        host_action = -1
        newhost = ''

        drop_request = False
        req.connection.no_keep_alive = True

        try:
            drop_request = self.drop_check(req, req_body)
            host_action = 1
        except ProxyPlugin.AlterHostHeader as e:
            host_action = 2
            drop_request = True
            newhost = str(e)

        if drop_request:
            if host_action == 1:
                self.logger.dbg('Not returning body from response handler')
                return self._drop_action(req, req_body, res, res_body, True)

            elif host_action == 2:
                self.logger.dbg('Altering host header in response_handler to: "{}"'.format(newhost))
                del req.headers['Host']
                req.headers['Host'] = newhost
                req.headers[proxy2_metadata_headers['override_host_header']] = newhost

        # A nifty hack to make the proxy2 believe we actually modified the response
        # so that the proxy will not encode it to gzip (or anything specified) and just
        # return the response as-is, in an "Content-Encoding: identity" kind of fashion
        res.headers[proxy2_metadata_headers['override_response_content_encoding']] = 'identity'

        if 'remove_these_response_headers' in self.proxyOptions.keys() and len(
                self.proxyOptions['remove_these_response_headers']) > 0:
            hdrs = ''

            for h in self.proxyOptions['remove_these_response_headers']:
                if h in res.headers.keys():
                    del res.headers[h]
                    hdrs += h + ', '

            if len(hdrs) > 0:
                self.logger.dbg('Removed these response headers: ' + hdrs)

        req.connection.no_keep_alive = False

        return res_body

    def _drop_action(self, req, req_body, res, res_body, quiet=False):
        if self.proxyOptions['report_only']:
            self.logger.info('(Report-Only) Not taking any action on invalid request.')
            if self.is_request:
                return req_body
            return res_body

        todo = ''
        if self.proxyOptions['drop_action'] == 'reset':
            todo = 'DROPPING'
        elif self.proxyOptions['drop_action'] == 'redirect':
            todo = 'REDIRECTING'
        elif self.proxyOptions['drop_action'] == 'proxy':
            todo = 'PROXYING'

        u = urlparse(req.uri)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)

        peer = req.client_address[0]

        try:
            resolved = socket.gethostbyaddr(req.client_address[0])[0]
            peer += ' ({})'.format(resolved)
        except:
            pass

        if not quiet:
            self.logger.err('[{} invalid request from {}] {} {}'.format(
                todo, peer, req.method, path
            ), color='cyan')

        if self.proxyOptions['log_dropped'] == True:
            req_headers = req.headers
            rb = req_body
            if rb is not None and len(rb) > 0:
                if type(rb) == type(b''):
                    rb = rb.decode()
                rb = '\r\n' + rb
            else:
                rb = ''

            request = '{} {} {}\r\n{}{}'.format(
                req.method, path, 'HTTP/1.1', req_headers, rb
            )

            if not quiet: self.logger.err('\n\n{}'.format(request), color='cyan')

        if self.proxyOptions['drop_action'] == 'reset':
            return DropConnectionException('Not a conformant beacon request.')

        elif self.proxyOptions['drop_action'] == 'redirect':
            if self.is_request:
                return DontFetchResponseException('Not a conformant beacon request.')

            if res is None:
                self.logger.err('Response handler received a None res object.')
                return res_body

            url = self.proxyOptions['action_url']
            if (type(self.proxyOptions['action_url']) == list or type(
                    self.proxyOptions['action_url']) == tuple) and len(self.proxyOptions['action_url']) > 0:
                url = random.choice(self.proxyOptions['action_url'])

            res.status = 301
            res.response_version = 'HTTP/1.1'
            res.reason = 'Moved Permanently'
            res_body = '''<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="{}">here</A>.
</BODY></HTML>'''.format(url)

            res.headers = {
                'Server': 'nginx',
                'Location': url,
                'Cache-Control': 'no-cache',
                'Content-Type': 'text/html; charset=UTF-8',
            }

            if len(self.addToResHeaders) > 0:
                # res.headers.update(self.addToResHeaders)
                self.addToResHeaders.clear()

            return res_body.encode()

        elif self.proxyOptions['drop_action'] == 'proxy':
            self.logger.dbg('Proxying forward...')

        if self.is_request:
            return req_body

        return res_body

    def _compute_request_hash(self, req, req_body):
        m = hashlib.md5()
        req_headers = req.headers
        rb = req_body
        if rb is not None and len(rb) > 0:
            if type(rb) == type(b''):
                rb = rb.decode()
            rb = '\r\n' + rb
        else:
            rb = ''

        request = '{} {} {}\r\n{}{}'.format(
            req.method, req.uri, 'HTTP/1.1', req_headers, rb
        )

        m.update(request.encode())
        h = m.hexdigest()
        self.logger.dbg("Requests's MD5 hash computed: {}".format(h))

        return h

    ####
    ## START: Peer and HTTP Headers validation logic
    ####

    def _whitelist_ip_check(self, peerIP, ts, req, returnJson, respJson):
        """
        Check if peer IP is in our whitelist
        Option: whitelisted_ip_addresses
        :param peerIP:
        :param ts:
        :param req:
        :param returnJson:
        :param respJson:
        :return:
        """
        userAgentValue = req.headers.get('User-Agent')

        if self.proxyOptions['whitelisted_ip_addresses'] is not None and len(
                self.proxyOptions['whitelisted_ip_addresses']) > 0:
            for cidr in self.proxyOptions['whitelisted_ip_addresses']:
                cidr = cidr.strip()
                if ipaddress.ip_address(peerIP) in ipaddress.ip_network(cidr, False):
                    msg = '[ALLOW, {}, reason:1, {}] peer\'s IP address is whitelisted: ({})'.format(ts, peerIP, cidr)

                    if returnJson:
                        respJson['action'] = 'allow'
                        respJson['reason'] = '1'
                        respJson['message'] = msg
                        respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                        return True, respJson
                    else:
                        self.logger.info(msg, color='green')
                        return True, self.report(False, ts, peerIP, req.uri, userAgentValue, '1')

        return None

    def _dynamic_peer_whitelisting_check(self, peerIP, ts, req, returnJson, respJson):
        """
        Check if peer IP is eligible for whitelisting
        Policy: allow_dynamic_peer_whitelisting
        :param peerIP:
        :param ts:
        :param req:
        :param returnJson:
        :param respJson:
        :return:
        """
        userAgentValue = req.headers.get('User-Agent')

        if self.proxyOptions['policy']['allow_dynamic_peer_whitelisting'] and len(
                self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests']) > 0:
            with SqliteDict(ProxyPlugin.DynamicWhitelistFile) as mydict:
                if peerIP in mydict.get('whitelisted_ips', []):
                    msg = '[ALLOW, {}, reason:2, {}] Peer\'s IP was added dynamically to a whitelist based on a number of allowed requests.'.format(
                        ts, peerIP)

                    if returnJson:
                        respJson['action'] = 'allow'
                        respJson['reason'] = '2'
                        respJson['message'] = msg
                        respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                        return True, respJson
                    else:
                        self.logger.info(msg, color='green')
                        return True, self.report(False, ts, peerIP, req.uri, userAgentValue, '2')

        return None

    def _ban_blacklisted_ip_addresses_check(self, peerIP, ts, req, returnJson, respJson):
        """
        Check if peer IP is in our black-list
        Option: ban_blacklisted_ip_addresses
        :param peerIP:
        :param ts:
        :param req:
        :param returnJson:
        :param respJson:
        :return:
        """
        userAgentValue = req.headers.get('User-Agent')

        if self.proxyOptions['ban_blacklisted_ip_addresses']:
            for cidr, _comment in self.banned_ips.items():
                if ipaddress.ip_address(peerIP) in ipaddress.ip_network(cidr, False):
                    reverseIp = ''
                    try:
                        reverseIp = socket.gethostbyaddr(peerIP)[0]
                    except:
                        pass

                    blockAnyway = True
                    entry = ''

                    for w in OVERRIDE_BANNED_AGENTS:
                        if w.lower() in reverseIp.lower():
                            blockAnyway = False
                            entry = w
                            break

                    if blockAnyway:
                        comment = ''
                        if len(_comment) > 0:
                            comment = ' - ' + _comment

                        msg = '[DROP, {}, reason:4a, {}] Peer\'s IP address is blacklisted: ({}{} - rev_ip: "{}")'.format(
                            ts, peerIP, cidr, comment, reverseIp
                        )

                        if returnJson:
                            respJson['action'] = 'drop'
                            respJson['reason'] = '4a'
                            respJson['message'] = msg
                            respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                            return True, respJson
                        else:
                            self.drop_reason(msg)
                            self._print_peer_info(peerIP)
                            return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '4a')

                    else:
                        self.logger.dbg(
                            f'The peer with IP: {peerIP} (rev_ip: {reverseIp}) would be banned if there was no blacklist override entry ({entry}).')

        return None

    def _drop_dangerous_ip_reverse_lookup_check(self, peerIP, ts, req, returnJson, respJson):
        """
        Check if peer hostname contain banned words
        Policy: drop_dangerous_ip_reverse_lookup
        :param peerIP:
        :param ts:
        :param req:
        :param returnJson:
        :param respJson:
        :return:
        """
        userAgentValue = req.headers.get('User-Agent')

        if self.proxyOptions['policy']['drop_dangerous_ip_reverse_lookup']:
            whitelisted = False
            try:
                resolved = socket.gethostbyaddr(req.client_address[0])[0]
                for part in resolved.split('.')[:-1]:
                    if whitelisted: break
                    if not part: continue
                    foo = any(re.search(r'\b' + re.escape(part) + r' \b', b, re.I) for b in BANNED_AGENTS)
                    if foo or part.lower() in BANNED_AGENTS and part.lower() not in OVERRIDE_BANNED_AGENTS:
                        a = part.lower() in OVERRIDE_BANNED_AGENTS
                        b = (x in part.lower() for x in OVERRIDE_BANNED_AGENTS)
                        if a or b:
                            self.logger.dbg(
                                'Peer\'s reverse-IP lookup would be banned because of word "{}" but was whitelisted.'.format(
                                    part))
                            whitelisted = True
                            break

                        msg = '[DROP, {}, reason:4b, {}] peer\'s reverse-IP lookup contained banned word: "{}"'.format(
                            ts, peerIP, part)

                        if returnJson:
                            respJson['action'] = 'drop'
                            respJson['reason'] = '4b'
                            respJson['message'] = msg
                            respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                            return (True, respJson)
                        else:
                            self.drop_reason(msg)
                            self._print_peer_info(peerIP)
                            return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '4b')

            except Exception as e:
                pass

        return None

    def _drop_http_banned_header_names_check(self, peerIP, ts, req, returnJson, respJson):
        """
        Check if Incoming HTTP headers names and values contains banned words
        Policy: drop_http_banned_header_names, drop_http_banned_header_value
        :param peerIP:
        :param ts:
        :param req:
        :param returnJson:
        :param respJson:
        :return:
        """
        userAgentValue = req.headers.get('User-Agent')

        if self.proxyOptions['policy']['drop_http_banned_header_names'] or self.proxyOptions['policy'][
            'drop_http_banned_header_value']:
            whitelisted = False
            for k, v in req.headers.items():
                if whitelisted: break
                kv = k.split('-')
                vv = v.split(' ') + v.split('-')
                if self.proxyOptions['policy']['drop_http_banned_header_names']:
                    for kv1 in kv:
                        if whitelisted: break
                        if not kv1: continue
                        foo = any(re.search(r'\b' + re.escape(kv1) + r' \b', b, re.I) for b in BANNED_AGENTS)

                        # Match any e.g *User-AgenT*
                        boo = any(x in kv1.lower() for x in BANNED_AGENTS)

                        if foo or kv1.lower() in BANNED_AGENTS or boo:
                            a = kv1.lower() in OVERRIDE_BANNED_AGENTS
                            b = any(x in kv1.lower() for x in OVERRIDE_BANNED_AGENTS)
                            c = any(x in k.lower() for x in OVERRIDE_BANNED_AGENTS)
                            if a or b or c:
                                self.logger.dbg(
                                    'HTTP header name would be banned because of word "{}" but was overridden by whitelist file entries.'.format(
                                        kv1))
                                whitelisted = True
                                break

                            msg = '[DROP, {}, reason:2, {}] HTTP header name contained banned word: "{}" ({}: {})'.format(
                                ts, peerIP, kv1, kv, vv)

                            if returnJson:
                                respJson['action'] = 'drop'
                                respJson['reason'] = '2'
                                respJson['message'] = msg
                                respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                                return True, respJson
                            else:
                                self.drop_reason(msg)
                                self._print_peer_info(peerIP)
                                return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '2')

                if self.proxyOptions['policy']['drop_http_banned_header_value']:
                    whitelisted = False
                    for vv1 in vv:
                        if whitelisted: break
                        if not vv1: continue
                        foo = any(re.search(r'\b' + re.escape(vv1) + r' \b', b, re.I) for b in BANNED_AGENTS)

                        # Match any e.g *curl*
                        boo = any(x in vv1.lower() for x in BANNED_AGENTS)

                        if foo or vv1.lower() in BANNED_AGENTS or boo:
                            a = vv1.lower() in OVERRIDE_BANNED_AGENTS
                            b = any(x in vv1.lower() for x in OVERRIDE_BANNED_AGENTS)
                            c = any(x in v.lower() for x in OVERRIDE_BANNED_AGENTS)
                            if a or b or c:
                                self.logger.dbg(
                                    'HTTP header value would be banned because of word "{}" but was overridden by whitelist file entries.'.format(
                                        vv1))
                                whitelisted = True
                                break

                            msg = '[DROP, {}, reason:3, {}] HTTP header value contained banned word: "{}" ({}: {})'.format(
                                ts, peerIP, vv1, kv, vv)

                            if returnJson:
                                respJson['action'] = 'drop'
                                respJson['reason'] = '3'
                                respJson['message'] = msg
                                respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                                return (True, respJson)
                            else:
                                self.drop_reason(msg)
                                self._print_peer_info(peerIP)
                                return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '3')

        return None

    def _verify_peer_ip_details_check(self, peerIP, ts, req, returnJson, respJson):
        """
        Verify peer IP against third-party IP Lookup. e.g. ipinfo.io
        Option: verify_peer_ip_details
        :param peerIP:
        :param ts:
        :param req:
        :param returnJson:
        :param respJson:
        :return:
        """

        userAgentValue = req.headers.get('User-Agent')
        ipLookupDetails = None
        if self.proxyOptions['verify_peer_ip_details']:
            try:
                ipLookupDetails = self.ipLookupHelper.lookup(peerIP)
                whitelisted = False

                if ipLookupDetails and len(ipLookupDetails) > 0:
                    if 'organization' in ipLookupDetails.keys():
                        for orgWord in ipLookupDetails['organization']:
                            if whitelisted: break
                            for word in orgWord.split(' '):
                                if whitelisted: break
                                if not word: continue
                                foo = any(re.search(r'\b' + re.escape(word) + r' \b', b, re.I) for b in BANNED_AGENTS)
                                if foo or word.lower() in BANNED_AGENTS:
                                    a = word.lower() in OVERRIDE_BANNED_AGENTS
                                    b = any(x in orgWord.lower() for x in OVERRIDE_BANNED_AGENTS)
                                    if a or b:
                                        self.logger.dbg(
                                            'IP lookup organization field "{}" would be banned because of word "{}" but was overridden by whitelist file entries.'.format(
                                                orgWord, word))
                                        whitelisted = True
                                        break

                                    msg = '[DROP, {}, reason:4c, {}] peer\'s IP lookup organization field ({}) contained banned word: "{}"'.format(
                                        ts, peerIP, orgWord, word)

                                    if returnJson:
                                        respJson['action'] = 'drop'
                                        respJson['reason'] = '4c'
                                        respJson['message'] = msg
                                        respJson['ipgeo'] = ipLookupDetails
                                        return (True, respJson)
                                    else:
                                        self.drop_reason(msg)
                                        return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '4c')

            except Exception as e:
                self.logger.err(f'IP Lookup failed for some reason on IP ({peerIP}): {e}', color='cyan')

            try:
                if not self.ipGeolocationDeterminer.determine(ipLookupDetails):
                    msg = '[DROP, {}, reason:4d, {}] peer\'s IP geolocation ("{}", "{}", "{}", "{}", "{}") DID NOT met expected conditions'.format(
                        ts, peerIP, ipLookupDetails['continent'], ipLookupDetails['continent_code'],
                        ipLookupDetails['country'], ipLookupDetails['country_code'], ipLookupDetails['city'],
                        ipLookupDetails['timezone']
                    )

                    if returnJson:
                        respJson['action'] = 'drop'
                        respJson['reason'] = '4d'
                        respJson['message'] = msg
                        respJson['ipgeo'] = ipLookupDetails
                        return (True, respJson)
                    else:
                        self.drop_reason(msg)
                        return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '4d')

            except Exception as e:
                self.logger.err(f'IP Geolocation determinant failed for some reason on IP ({peerIP}): {e}',
                                color='cyan')

            if self.proxyOptions['policy']['drop_ipgeo_metadata_containing_banned_keywords']:
                self.logger.dbg("Analysing IP Geo metadata keywords...")
                try:
                    metaAnalysis = self.ipGeolocationDeterminer.validateIpGeoMetadata(ipLookupDetails, BANNED_AGENTS,
                                                                                      OVERRIDE_BANNED_AGENTS)

                    if metaAnalysis[0] == False:
                        a = (metaAnalysis[1].lower() in OVERRIDE_BANNED_AGENTS)
                        b = any(x in metaAnalysis[1] for x in OVERRIDE_BANNED_AGENTS)
                        if a or b:
                            self.logger.dbg(
                                'Peer\'s IP geolocation metadata would be banned because it contained word "{}" but was overridden by whitelist file.'.format(
                                    metaAnalysis[1]))

                        else:
                            msg = '[DROP, {}, reason:4e, {}] Peer\'s IP geolocation metadata ("{}", "{}", "{}", "{}", "{}") contained banned keyword: ({})! Peer banned in generic fashion.'.format(
                                ts, peerIP, ipLookupDetails['continent'], ipLookupDetails['continent_code'],
                                ipLookupDetails['country'], ipLookupDetails['country_code'], ipLookupDetails['city'],
                                ipLookupDetails['timezone'],
                                metaAnalysis[1]
                            )

                            if returnJson:
                                respJson['action'] = 'drop'
                                respJson['reason'] = '4e'
                                respJson['message'] = msg
                                respJson['ipgeo'] = ipLookupDetails
                                return True, respJson
                            else:
                                self.drop_reason(msg)
                                return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '4e')

                except Exception as e:
                    self.logger.dbg(
                        f"Exception was thrown during drop_ipgeo_metadata_containing_banned_keywords verifcation:\n\t({e})")

        if returnJson:
            msg = '[ALLOW, {}, reason:99, {}] Peer IP and HTTP headers did not contain anything suspicious.'.format(
                ts, peerIP)

            if not ipLookupDetails or (type(ipLookupDetails) == dict and len(ipLookupDetails) == 0):
                respJson['ipgeo'] = self._print_peer_info(peerIP, True)
            else:
                respJson['ipgeo'] = ipLookupDetails

            respJson['action'] = 'allow'
            respJson['reason'] = '99'
            respJson['message'] = msg
            return False, respJson
        else:
            return False, False

    def _drop_request_without_expected_header_check(self, peerIP, ts, req, returnJson, respJson):
        if self.proxyOptions['policy']['drop_request_without_expected_header']:
            expected_headers = [x.lower() for x in self.proxyOptions['expected_headers']]
            req_headers_keys = [x.lower() for x in req.headers.keys()]
            drop = False
            msg = ''
            userAgentValue = req.headers.get('user-agent')

            for header_key in expected_headers:
                exist = header_key in req_headers_keys

                if not exist:
                    drop = True
                    msg = '[DROP, {}, reason:5, {}] HTTP request did not contain expected header: "{}"'.format(ts,
                                                                                                               peerIP,
                                                                                                               header_key)
                    break

            if drop:
                if returnJson:
                    respJson['action'] = 'drop'
                    respJson['reason'] = '5'
                    respJson['message'] = msg
                    respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                    return True, respJson
                else:
                    self.drop_reason(msg)
                    return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '5')

        return None

    def _drop_request_without_expected_header_value_check(self, peerIP, ts, req, returnJson, respJson):
        if self.proxyOptions['policy']['drop_request_without_expected_header_value']:
            drop = False
            userAgentValue = req.headers.get('User-Agent')

            for header in self.proxyOptions['expected_headers_value'].items():
                k, v = header
                match = req.headers[k.lower()].lower() == v.lower()

                if not match:
                    drop = True
                elif k.lower() == 'host' and match:
                    req.headers[proxy2_metadata_headers['override_host_header']] = v

                if drop:
                    msg = '[DROP, {}, reason:6, {}] HTTP request did not contain expected header value: "{}: {}"'.format(
                        ts, peerIP, k, v)

                    if returnJson:
                        respJson['action'] = 'drop'
                        respJson['reason'] = '6'
                        respJson['message'] = msg
                        respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                        return True, respJson
                    else:
                        self.drop_reason(msg)
                        return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '6')
        return None

    def _drop_request_without_expected_http_method_check(self, peerIP, ts, req, returnJson, respJson):
        if self.proxyOptions['policy']['drop_request_without_expected_http_method']:
            userAgentValue = req.headers.get('User-Agent')
            req_method = req.method

            if req_method is None or req_method.upper() not in map(str.upper,
                                                                   self.proxyOptions['expected_http_methods']):
                msg = '[DROP, {}, reason:7, {}] Unexpected HTTP method: "{}"'.format(ts, peerIP, req_method)
                if returnJson:
                    respJson['action'] = 'drop'
                    respJson['reason'] = '7'
                    respJson['message'] = msg
                    respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                    return True, respJson
                else:
                    self.drop_reason(msg)
                    return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '7')

        return None

    def _drop_request_without_expected_uri_check(self, peerIP, ts, req, returnJson, respJson):
        if self.proxyOptions['policy']['drop_request_without_expected_uri']:
            userAgentValue = req.headers.get('User-Agent')
            drop = True

            for uri in self.proxyOptions['expected_uri']:
                match = fnmatch.fnmatch(req.uri, uri)
                if match:
                    drop = False
                    break

            if drop:
                msg = '[DROP, {}, reason:8, {}] Unexpected URI: "{}"'.format(ts, peerIP, req.uri)
                if returnJson:
                    respJson['action'] = 'drop'
                    respJson['reason'] = '8'
                    respJson['message'] = msg
                    respJson['ipgeo'] = self._print_peer_info(peerIP, True)
                    return True, respJson
                else:
                    self.drop_reason(msg)
                    return True, self.report(True, ts, peerIP, req.uri, userAgentValue, '8')

        return None

    def _client_request_inspect(self, peerIP, ts, req, req_body, res, res_body, parsedJson):
        respJson = {}
        returnJson = (parsedJson is not None and res is not None)

        respJson['drop_type'] = self.proxyOptions['drop_action']
        respJson['action_url'] = self.proxyOptions['action_url']

        # Option: whitelisted_ip_addresses
        whitelist_ip_check = self._whitelist_ip_check(peerIP, ts, req, returnJson, respJson)
        if whitelist_ip_check is not None:
            return whitelist_ip_check

        # Policy check: allow_dynamic_peer_whitelisting
        dynamic_peer_whitelisting_check = self._dynamic_peer_whitelisting_check(peerIP, ts, req, returnJson, respJson)
        if dynamic_peer_whitelisting_check is not None:
            return dynamic_peer_whitelisting_check

        # Option: ban_blacklisted_ip_addresses
        ban_blacklisted_ip_addresses_check = self._ban_blacklisted_ip_addresses_check(peerIP, ts, req, returnJson,
                                                                                      respJson)
        if ban_blacklisted_ip_addresses_check is not None:
            return ban_blacklisted_ip_addresses_check

        # Policy: drop_dangerous_ip_reverse_lookup
        drop_dangerous_ip_reverse_lookup = self._drop_dangerous_ip_reverse_lookup_check(peerIP, ts, req, returnJson,
                                                                                        respJson)
        if drop_dangerous_ip_reverse_lookup is not None:
            return drop_dangerous_ip_reverse_lookup

        # Policy: drop_http_banned_header_names, drop_http_banned_header_value
        drop_http_banned_header_names_check = self._drop_http_banned_header_names_check(peerIP, ts, req, returnJson,
                                                                                        respJson)
        if drop_http_banned_header_names_check is not None:
            return drop_http_banned_header_names_check

        # Policy: drop_request_without_expected_header_value
        drop_request_without_expected_header_check = self._drop_request_without_expected_header_check(peerIP, ts, req,
                                                                                                      returnJson,
                                                                                                      respJson)
        if drop_request_without_expected_header_check is not None:
            return drop_request_without_expected_header_check

        # Validations: Expected headers values
        drop_request_without_expected_header_value_check = self._drop_request_without_expected_header_value_check(
            peerIP, ts, req, returnJson, respJson)
        if drop_request_without_expected_header_value_check is not None:
            return drop_request_without_expected_header_value_check

        # Validations: Expected HTTP Methods
        drop_request_without_expected_http_method_check = self._drop_request_without_expected_http_method_check(peerIP,
                                                                                                                ts, req,
                                                                                                                returnJson,
                                                                                                                respJson)
        if drop_request_without_expected_http_method_check is not None:
            return drop_request_without_expected_http_method_check

        # Validations: Expected URI
        drop_request_without_expected_uri_check = self._drop_request_without_expected_uri_check(peerIP, ts, req,
                                                                                                returnJson, respJson)
        if drop_request_without_expected_uri_check is not None:
            return drop_request_without_expected_uri_check

        # Option: verify_peer_ip_details
        verify_peer_ip_details_check = self._verify_peer_ip_details_check(peerIP, ts, req, returnJson, respJson)
        if verify_peer_ip_details_check is not None:
            return verify_peer_ip_details_check

    def drop_check(self, req, req_body):
        peerIP = ProxyPlugin.get_peer_ip(req)
        userAgentValue = req.headers.get('User-Agent')
        ts = datetime.now().strftime('%Y-%m-%d/%H:%M:%S')

        self._process_proxy_pass(ts, peerIP, req, True)
        (outstatus, outresult) = self._client_request_inspect(peerIP, ts, req, req_body, '', '', None)

        if outstatus:
            return outresult

        self._process_proxy_pass(ts, peerIP, req, False)

        if self.is_request:
            self._print_peer_info(peerIP)

        self.logger.dbg('[{}: ALLOW] Peer\'s request is accepted'.format(peerIP), color='green')
        return self.report(False, ts, peerIP, req.uri, userAgentValue, '0')

    ####
    ## END: Peer and HTTP Headers validation logic
    ####

    def _process_proxy_pass(self, ts, peerIP, req, processNodrops):
        if self.proxyOptions['proxy_pass'] is not None and len(self.proxyOptions['proxy_pass']) > 0 and \
                self.proxyOptions['policy']['allow_proxy_pass']:
            for num, entry in self.proxyOptions['proxy_pass'].items():
                scheme = entry['scheme']
                url = entry['url']
                host = entry['redir']
                opts = ''

                if processNodrops:
                    if ('options' not in entry.keys()) or ('nodrop' not in entry['options'].keys()):
                        continue

                if 'nodrop' in entry['options'].keys():
                    opts += ', nodrop'

                if re.match('^' + url + '$', req.uri, re.I) is not None:
                    self.logger.info(
                        '[ALLOW, {}, reason:0, {}]  Request conforms ProxyPass entry {} (url="{}" redir="{}"{}). Passing request to specified host.'.format(
                            ts, peerIP, num, url, host, opts
                            ), color='green')
                    self._print_peer_info(peerIP)
                    self.report(False, ts, peerIP, req.uri, req.headers.get('User-Agent'), '0')

                    # del req.headers['Host']
                    # req.headers['Host'] = host
                    if '/' in host:
                        req.headers[proxy2_metadata_headers['override_host_header']] = host[:host.find('/')]
                        req.uri = host
                    else:
                        req.headers[proxy2_metadata_headers['override_host_header']] = host

                    if scheme and (scheme + '://' not in req.uri):
                        req.uri = '{}://{}'.format(scheme, host)

                    raise ProxyPlugin.AlterHostHeader(host)

                else:
                    self.logger.dbg(
                        '(ProxyPass) Processed request with URL ("{}"...) didnt match ProxyPass entry {} URL regex: "^{}$".'.format(
                            req.uri[:32], num, url))

    def _print_peer_info(self, peerIP, returnInstead=False):
        global alreadyPrintedPeers
        try:
            ipLookupDetails = self.ipLookupHelper.lookup(peerIP)
            if ipLookupDetails and len(ipLookupDetails) > 0:
                if returnInstead:
                    return ipLookupDetails

                printit = self.logger.info
                if peerIP in alreadyPrintedPeers:
                    printit = self.logger.dbg

                printit('Here is what we know about that address ({}): ({})'.format(peerIP, ipLookupDetails),
                        color='grey')
                alreadyPrintedPeers.add(peerIP)

                return ipLookupDetails
        except Exception as e:
            pass
        return {}

    def _get_http_req_method_type(self, request):
        if request.method == 'GET':
            return 'http-get'
        if request.method == 'POST':
            return 'http-post'
        if request.method == 'HEAD':
            return 'http-head'
        if request.method == 'PUT':
            return 'http-put'

        return request.method
