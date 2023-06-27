#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# RedWardenLite
# This project is based on the RedWarden project https://github.com/mgeeky/RedWarden
# RedWardenLite: https://github.com/iomoath/RedWardenLite
#
# RedWarden Author:
#   Mariusz Banach / mgeeky, '16-'22
#   <mb@binary-offensive.com>
#
#   (originally based on: @inaz2 implementation: https://github.com/futuresimple/proxy2)
#   (now obsoleted)
#

VERSION = '0.9.3'

import logging
import tornado.web
import tornado.httpserver
import tornado.netutil
import asyncio

from lib.proxyhandler import *


normpath = lambda p: os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), p))


# Global options dictionary, that will get modified after parsing
# program arguments. Below state represents default values.
options = {
    'bind': 'http://0.0.0.0',
    'port': [8080, ],
    'debug': False,                  # Print's out debugging information
    'verbose': False,
    'tee': False,
    'log': None,
    'proxy_self_url': 'http://RedWardenLite.test/',
    'timeout': 90,
    'access_log' : '',
    'access_log_format' : 'apache2',
    'redelk_frontend_name' : 'http-redwarden',
    'redelk_backend_name_c2' : 'c2',
    'redelk_backend_name_decoy' : 'decoy',
    'no_ssl': False,
    'drop_invalid_http_requests': True,
    'no_proxy': False,
    'cakey':  normpath('ca-cert/ca.key'),
    'cacert': normpath('ca-cert/ca.crt'),
    'certkey': normpath('ca-cert/cert.key'),
    'certdir': normpath('certs/'),
    'cacn': 'RedWarden CA',
    'plugins': set(),
    'plugin_class_name': 'ProxyPlugin',
}

logger = None


def create_ssl_context():
    ssl_ctx  = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(options['cacert'], options['cakey'])

    return ssl_ctx

async def server_loop(servers):
    # Schedule calls *concurrently*:
    L = await asyncio.gather(*servers)

async def serve_proxy(bind, port, _ssl, foosock):
    ProxyRequestHandler.protocol_version = "HTTP/1.1"
    scheme = None
    certpath = ''

    if not bind or len(bind) == 0:
        if options['bind'].startswith('http') and '://' in options['bind']:
            colon = options['bind'].find(':')
            scheme = options['bind'][:colon].lower()
            if scheme == 'https' and not _ssl:
                logger.fatal('You can\'t specify different schemes in bind address (-B) and on the port at the same time! Pick one place for that.\nSTOPPING THIS SERVER.')

            bind = options['bind'][colon + 3:].replace('/', '').lower()
        else:
            bind = options['bind']

    if _ssl:
        scheme = 'https'

    if scheme == None: scheme = 'http'

    server_address = (bind, port)
    app = None

    logging.getLogger('tornado.access').disabled = True

    try:
        params = dict(server_bind=bind, server_port=port)
        app = tornado.web.Application([
            (r'/.*', ProxyRequestHandler, params),
            (scheme + r'://.*', ProxyRequestHandler, params),
        ],
        transforms=[RemoveXProxy2HeadersTransform, ])

    except OSError as e:
        if 'Address already in use' in str(e):
            logger.err("Could not bind to specified port as it is already in use!")
            return
        else:
            raise

    logger.info("Serving proxy on: {}://{}:{} ...".format(scheme, bind, port),
        color=ProxyLogger.colors_map['yellow'])

    server = None
    if scheme == 'https':
        ssl_ctx = create_ssl_context()
        server = tornado.httpserver.HTTPServer(
            app,
            ssl_options=ssl_ctx,
            idle_connection_timeout = options['timeout'],
            body_timeout = options['timeout'],
            )
    else:
        server = tornado.httpserver.HTTPServer(
            app,
            idle_connection_timeout = options['timeout'],
            body_timeout = options['timeout'],
            )

    server.add_sockets(foosock)
    await asyncio.Event().wait()

def main():
    global options
    global logger

    try:
        (options, logger) = init(options, VERSION)

        logger.info(r'''

    :: RedWarden Lite
    :: A lightweight HTTP/HTTPS reverse proxy for efficient, rule-based traffic filtering and redirection.

    v{}

'''.format(VERSION))

        threads = []
        if len(options['port']) == 0:
            options['port'].append('8080/http')

        servers = []
        portsBound = set()

        for port in options['port']:
            p = 0
            scheme = 'http'
            bind = ''

            if port in portsBound:
                logger.err(f'TCP Port {port} already bound. Possibly a duplicate configuration line. Skipping it.')
                continue

            portsBound.add(port)

            try:
                _port = port

                if type(port) == int:
                    bind = options['bind']

                if ':' in port:
                    bind, port = _port.split(':')

                if '/http' in port:
                    _port, scheme = port.split('/')

                p = int(_port)
                if p < 0 or p > 65535: raise Exception()
                if not bind:
                    bind = '0.0.0.0'

                foosock = tornado.netutil.bind_sockets(p, address = bind)
                servers.append((bind, p, scheme.lower() == 'https', foosock, options))

            except OSError as e:
                logger.err('Could not bind to specified TCP port: {}\nException: {}\n'.format(port, e))
                raise
                return False

            except Exception as e:
                logger.err('Specified port ({}) is not a valid number in range of 1-65535!\n'.format(port))
                raise
                return False

        # https://www.tornadoweb.org/en/stable/tcpserver.html
        # advanced multi-process:
        tornado.process.fork_processes(0)

        statements = []
        for srv in servers:
            statements.append(serve_proxy(srv[0], srv[1], srv[2], srv[3]))
        asyncio.run(server_loop(statements))

    except KeyboardInterrupt:
        logger.info('\nProxy serving interrupted by user.', noprefix=True)

    except Exception as e:
        print(ProxyLogger.with_color(ProxyLogger.colors_map['red'], 'Fatal error has occured.'))
        print(ProxyLogger.with_color(ProxyLogger.colors_map['red'], '\t%s\nTraceback:' % e))
        print(ProxyLogger.with_color(ProxyLogger.colors_map['red'], '-'*30))
        traceback.print_exc()
        print(ProxyLogger.with_color(ProxyLogger.colors_map['red'], '-'*30))

    finally:
        cleanup()

if __name__ == '__main__':
    main()