"""
    Replays responses from a file based on requests.
"""

import hashlib
import urllib
import logging
import re
import time
from typing import Any  # noqa
from typing import List  # noqa

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import io


class ServerPlayback:
    """
        Replays responses from a file based on requests.
    """

    def __init__(self):
        self.log_requests = False  # developer; need to decide if this should be a command-line flag
        self.options = None

        self.flowmap = {}
        self.stop = False
        self.final_flow = None
        if self.log_requests:
            filename = "server-playback-{}.log".format(time.time())
            logging.basicConfig(filename=filename, level=logging.DEBUG)
        self.defaultdoc = re.compile(r"/(default|index)\.(aspx?|html?)$", re.IGNORECASE)

    def load(self, flows):
        """
            Loads flows into the flowmap.
        """
        for flow in flows:
            if flow.response:
                self._log(flow.request, True)
                mapper = self.flowmap.setdefault(self._hash(flow), [])
                mapper.append(flow)

    def clear(self):
        """
            Clears the flowmap.
        """
        self.flowmap = {}

    def count(self):
        """
            Counts the number of flows in the flowmap.
        """
        return sum([len(flow) for flow in self.flowmap.values()])

    def _log(self, request, loading):
        if self.log_requests:
            _, _, path, _, query, _ = urllib.parse.urlparse(request.url)

            location = 'LOAD' if loading else 'REPLAY'

            logging.debug('%s: %s %s://%s:%s/%s?%s',
                          location, request.method, request.scheme,
                          request.host, request.port, path, query)

    def _hash(self, flow):
        """
            Calculates a loose hash of the flow request.
        """
        request = flow.request

        _, _, path, _, query, _ = urllib.parse.urlparse(request.url)
        querystringvalues = urllib.parse.parse_qsl(query, keep_blank_values=True)

        # Attempt to normalize the path for common variances (lowercase,
        # default document, trailing slash)
        path = path.lower()

        path = self.defaultdoc.sub("", path)

        if path.endswith('/'):
            path = path[:-1]

        hashkey = [str(request.port), str(request.scheme),
                   str(request.method), str(path)]  # type: List[Any]

        if not self.options.server_replay_ignore_content:
            if self.options.server_replay_ignore_payload_params and request.multipart_form:
                hashkey.extend(
                    (key, value)
                    for key, value in request.multipart_form.items(multi=True)
                    if key.decode(errors="replace") not
                    in self.options.server_replay_ignore_payload_params
                )
            elif self.options.server_replay_ignore_payload_params and request.urlencoded_form:
                hashkey.extend(
                    (key, value)
                    for key, value in request.urlencoded_form.items(multi=True)
                    if key not in self.options.server_replay_ignore_payload_params
                )
            else:
                hashkey.append(str(request.raw_content))

        if not self.options.server_replay_ignore_host:
            hashkey.append(request.host.lower())

        filtered = []
        ignore_params = self.options.server_replay_ignore_params or []
        for qsv in querystringvalues:
            if qsv[0] not in ignore_params:
                filtered.append(qsv)
        for qsv in filtered:
            hashkey.append(qsv[0].lower())
            hashkey.append(qsv[1].lower())

        if self.options.server_replay_use_headers:
            headers = []
            for header in self.options.server_replay_use_headers:
                value = request.headers.get(header)
                headers.append((header, value))
            hashkey.append(headers)
        return hashlib.sha256(
            repr(hashkey).encode("utf8", "surrogateescape")
        ).digest()

    def next_flow(self, flow):
        """
            Returns the next flow object, or None if no matching flow was
            found.
        """
        hsh = self._hash(flow)

        self._log(flow.request, False)

        _, _, path, _, _, _ = urllib.parse.urlparse(flow.request.url)

        no_pop = self.options.server_replay_nopop

        method = flow.request.method

        formats = (".ashx", ".axd", ".css", ".gif", ".htm", ".html", ".ico", ".jpeg",
                   ".jpg", ".js", ".png", ".svg", ".ttf", ".txt", ".woff", ".woff2")

        if hsh in self.flowmap:
            if no_pop or (path.endswith(formats) and method == "GET"):
                return self.flowmap[hsh][0]
            else:
                ret = self.flowmap[hsh].pop(0)
                if not self.flowmap[hsh]:
                    del self.flowmap[hsh]
                return ret

    def configure(self, options, updated):
        """
            Sets up internal state from configuration
        """
        self.options = options
        if "server_replay" in updated:
            self.clear()
            if options.server_replay:
                try:
                    flows = io.read_flows_from_paths(options.server_replay)
                except exceptions.FlowReadException as ex:
                    raise exceptions.OptionsError(str(ex))
                self.load(flows)

    def tick(self):
        """
            Checks internal state to determine whether to stop replaying
        """
        if self.stop and not self.final_flow.live:
            ctx.master.shutdown()

    def request(self, f):
        """
            Gets the next response corresponding to a request
        """
        if self.flowmap:
            rflow = self.next_flow(f)
            if rflow:
                response = rflow.response.copy()
                response.is_replay = True
                if self.options.refresh_server_playback:
                    response.refresh()
                f.response = response
                if not self.flowmap and not self.options.keepserving:
                    self.final_flow = f
                    self.stop = True
            elif self.options.replay_kill_extra:
                message = "server_playback: killed non-replay request {}".format(f.request.url)
                logging.debug(message)
                ctx.log.warn(message)
                f.reply.kill()
