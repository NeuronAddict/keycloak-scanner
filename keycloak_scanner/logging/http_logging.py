import logging
import http.client


def httpclient_logging_patch(level=logging.DEBUG):

    logging.basicConfig(level=logging.DEBUG)
    httpclient_logger = logging.getLogger("http.client")

    """Enable HTTPConnection debug logging to the logging framework"""

    def httpclient_log(*args):
        httpclient_logger.log(level, " ".join(args))

    # mask the print() built-in in the http.client module to use
    # logging instead
    http.client.print = httpclient_log
    # enable debugging
    http.client.HTTPConnection.debuglevel = 1
