from dataclasses import dataclass


# lies!  But some servers won't respond to untrusted user agents
USER_AGENT = 'curl/7.68.0'


class HttpParseException(Exception): pass


@dataclass
class HttpResponse:
    response_code: int
    response_message: str
    header_lines: list
    body_lines: list

    def get_body(self):
        return '\r\n'.join(self.body_lines)

    def get_full_response(self):
        return '\r\n'.join(header_lines) + '\r\n' + self.get_body()


def parse_http_url(url):
    if url.startswith('http://'):
        url = url[len('http://'):]
    host, slash, path = url.partition('/')
    host, colon, port = host.partition(':')

    if not port:
        port = 80
    else:
        port = int(port)

    path = slash + path
    if not path:
        path = '/index.html'

    return host, port, path


def build_http_request(host, port, path, use_agent=USER_AGENT):
    http_request_lines = [
        f'GET {path} HTTP/1.1',
        f'Host: {host}' if port == 80 else f'Host: {host}:{port}',
        f'User-Agent: {USER_AGENT}',
        f'Accept: */*'
    ]
    return '\r\n'.join(http_request_lines) + '\r\n\r\n'
    

def receive_http_response(tcp_connection):
    payload_line_iterator = _yield_payload_lines(tcp_connection)
    response_code = None
    response_message = None
    content_length = None
    header_lines = []
    body_lines = []

    first_line = next(payload_line_iterator)
    if not first_line.startswith('HTTP/1'):
        raise HttpParseException(f'Got unexpected first line: {first_line}')
    else:
        first_line_fields = first_line.split()
        response_code = first_line_fields[1]
        response_message = first_line_fields[2]
        header_lines.append(first_line)

    for current_line in payload_line_iterator:
        # this will cause us to skip over the empty line separating the header
        # from the body of the response
        if len(current_line) == 0:
            break
        header_lines.append(current_line)
        if current_line.startswith('Content-length:'):
            content_length = int(current_line.split()[1])

    content_length_so_far = 0
    for current_line in payload_line_iterator:
        if content_length_so_far >= content_length:
            break
        body_lines.append(current_line)
        content_length_so_far += len(current_line) + 1  # +1 for the newline

    return HttpResponse(
        response_code, response_message, header_lines, body_lines,
    )


def _yield_payload_lines(tcp_connection):
    payload_iterator = tcp_connection.receive()
    payload = next(payload_iterator)
    print('iterating over empty payloads')
    print(f'first payload = {payload}')
    while len(payload) == 0:
        print(f'skipping payload {payload}')
        payload = next(payload_iterator)

    print('done iterating over empty payloads')

    # after the start, don't accept empty payloads (this is probably technically
    # valid, but it simplifies things)

    # hold on to ends of payloads until we see the next newline
    leftover_line = ''

    for payload in payload_iterator:
        print(f'considering payload {payload}')
        payload = payload.decode('utf-8')
        while '\r\n' in payload:
            line, payload = payload.split('\r\n', 1)
            if leftover_line:
                line = leftover_line + line
                leftover_line = ''
            print (f'yielding {line}')
            yield line
        leftover_line = payload

    if leftover_line:
        print(f'yielding leftover line {line}')
        yield leftover_line
