from dataclasses import dataclass

@dataclass
class HttpRequest:
    method: str
    url: str
    http_version: str
    headers: dict
    body: str

def parse_http_request(request_string):
    lines = request_string.split('\r\n')
    method, url, http_version = lines[0].split(' ')
    headers = {}
    for line in lines[1:]:
        if line == '':
            break
        header_name, header_value = line.split(': ')
        headers[header_name] = header_value
    body = '\r\n'.join(lines[len(headers) + 2:])
    return HttpRequest(method, url, http_version, headers, body)

@dataclass
class HttpResponse:
    http_version: str
    status_code: str
    reason_phrase: str
    headers: dict
    body: str

def parse_http_response(response_string):
    lines = response_string.split('\r\n')
    http_version, status_code, reason_phrase = lines[0].split(' ', 2)
    headers = {}
    for line in lines[1:]:
        if line == '':
            break
        header_name, header_value = line.split(': ')
        headers[header_name] = header_value
    body = '\r\n'.join(lines[len(headers) + 2:])
    return HttpResponse(http_version, status_code, reason_phrase, headers, body)
