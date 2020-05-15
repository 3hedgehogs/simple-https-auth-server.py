#!/usr/bin/env /usr/bin/python3
# Extended python -m http.serve with --username and --password parameters for
# basic auth, based on https://gist.github.com/fxsjy/5465353
# and http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python3 simple-https-auth-server.py
# then in your browser, visit:
#    https://localhost:4443

from functools import partial
from http.server import SimpleHTTPRequestHandler
import base64
import os
import ssl
import http.server
from threading import Thread
from socketserver import ThreadingMixIn


class ThreadingHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    pass


class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    """ Main class to present webpages and authentication. """

    def __init__(self, *args, **kwargs):
        username  = kwargs.pop("username")
        password  = kwargs.pop("password")
        directory = kwargs.pop("directory")
        self._auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Test"')
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """ Present frontpage with user authentication. """
        if self.headers.get("Authorization") == None:
            self.do_AUTHHEAD()
            self.wfile.write(b"no auth header received")
        elif self.headers.get("Authorization") == "Basic " + self._auth:
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.get("Authorization").encode())
            self.wfile.write(b"not authenticated")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--cgi", action="store_true", help="Run as CGI Server")
    parser.add_argument(
        "--bind",
        "-b",
        metavar="ADDRESS",
        default="127.0.0.1",
        help="Specify alternate bind address " "[default: localhost]",
    )
    parser.add_argument(
        "--directory",
        "-d",
        default=os.getcwd(),
        help="Specify alternative directory " "[default:current directory]",
    )
    parser.add_argument(
        "port",
        action="store",
        default=4443,
        type=int,
        nargs="?",
        help="Specify alternate port [default: 4443]",
    )
    parser.add_argument(
        "--certificate",
        "-c",
        metavar="ServerCertificate",
        default="./server.pem",
        help="Specify PEM file with server certificate " "[default: ./server.pem]",
    )
    parser.add_argument("--username", "-u", metavar="USERNAME")
    parser.add_argument("--password", "-p", metavar="PASSWORD")
    args = parser.parse_args()
    handler_class = partial(
        AuthHTTPRequestHandler,
        username=args.username,
        password=args.password,
        directory=args.directory,
    )
    httpd = ThreadingHTTPServer((args.bind, args.port), handler_class)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile=args.certificate, server_side=True)
    os.chdir(args.directory)
    httpd.serve_forever()
