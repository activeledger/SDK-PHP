<?php

declare(strict_types=1);

/**
 * A scripted HTTP server on 127.0.0.1, for tests of the client's transport.
 *
 * Run as `php loopback-server.php`. It binds a free port itself, prints
 * `127.0.0.1:<port>` as its first line of stdout and serves until its stdin
 * closes, so it cannot outlive the process that started it.
 *
 * What it answers depends on the request path (a trailing slash is ignored):
 *
 *   /committed       200, a committed reply that created stream "stream-1"
 *   /rejected        200, a reply whose $summary.errors is non-empty
 *   /status/<code>   <code>, a ledger-style error body
 *   /plain/<code>    <code>, a non-JSON body
 *   /close           accepts the connection and closes it without replying
 *   /hang            reads the request and never replies
 *   /sse             200 event stream: two events, then the connection closes
 *   /sse-hold        200 event stream: one event, then silence
 *   /__last          200, JSON describing the previous request that was not
 *                    for /__last: method, path, content type, accept and body
 *
 * Single process, no threads: connections are multiplexed with stream_select
 * so a held connection never blocks the next request.
 */

$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "cannot listen: $errstr\n");
    exit(1);
}
fwrite(STDOUT, stream_socket_get_name($server, false) . "\n");
fflush(STDOUT);

/** @var array<int, array{socket: resource, buffer: string}> $clients */
$clients = [];
/** @var list<resource> $held connections deliberately left open */
$held = [];
$last = null;

while (true) {
    $read = [$server, STDIN];
    foreach ($clients as $client) {
        $read[] = $client['socket'];
    }
    $write = $except = null;

    if (stream_select($read, $write, $except, null) === false) {
        break;
    }

    foreach ($read as $stream) {
        if ($stream === STDIN) {
            // Readable with nothing to read is end of file: the owner is gone.
            $input = fread(STDIN, 1024);
            if ($input === '' || $input === false) {
                exit(0);
            }
            continue;
        }

        if ($stream === $server) {
            $socket = stream_socket_accept($server, 0);
            if ($socket !== false) {
                $clients[(int) $socket] = ['socket' => $socket, 'buffer' => ''];
            }
            continue;
        }

        $id = (int) $stream;
        $chunk = fread($stream, 65536);
        if ($chunk === '' || $chunk === false) {
            fclose($stream);
            unset($clients[$id]);
            continue;
        }

        $clients[$id]['buffer'] .= $chunk;
        $request = parseRequest($clients[$id]['buffer']);
        if ($request === null) {
            continue;
        }

        unset($clients[$id]);
        respond($stream, $request, $last, $held);
    }
}

/**
 * @return array{method: string, path: string, contentType: string, accept: string, body: string}|null
 *         null until the whole request has arrived
 */
function parseRequest(string $buffer): ?array
{
    $split = strpos($buffer, "\r\n\r\n");
    if ($split === false) {
        return null;
    }

    $head = substr($buffer, 0, $split);
    $body = substr($buffer, $split + 4);
    $length = preg_match('/^content-length:\s*(\d+)/mi', $head, $m) ? (int) $m[1] : 0;
    if (strlen($body) < $length) {
        return null;
    }

    [$method, $path] = explode(' ', strtok($head, "\r\n"), 3);
    $contentType = preg_match('/^content-type:\s*(.*?)\s*$/mi', $head, $m) ? $m[1] : '';
    $accept = preg_match('/^accept:\s*(.*?)\s*$/mi', $head, $m) ? $m[1] : '';

    return [
        'method' => $method,
        'path' => $path,
        'contentType' => $contentType,
        'accept' => $accept,
        'body' => substr($body, 0, $length),
    ];
}

/**
 * @param resource $socket
 * @param array{method: string, path: string, contentType: string, accept: string, body: string} $request
 * @param list<resource> $held
 */
function respond($socket, array $request, ?array &$last, array &$held): void
{
    $path = '/' . trim($request['path'], '/');

    if ($path === '/__last') {
        send($socket, 200, 'application/json', json_encode($last));
        return;
    }

    $last = $request;

    if ($path === '/close') {
        fclose($socket);
        return;
    }

    if ($path === '/hang') {
        $held[] = $socket;
        return;
    }

    if ($path === '/sse' || $path === '/sse-hold') {
        $events = "event: first\ndata: {\"n\":1}\n\ndata: {\"n\":2}\n\n";
        if ($path === '/sse-hold') {
            $events = "data: {\"n\":1}\n\n";
        }
        $head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
        fwrite($socket, $head . $events);
        if ($path === '/sse-hold') {
            $held[] = $socket;
        } else {
            fclose($socket);
        }
        return;
    }

    if ($path === '/committed') {
        send($socket, 200, 'application/json', '{"$streams":{"new":[{"id":"stream-1"}],"updated":[]},"$summary":{"total":1,"vote":1,"commit":true}}');
        return;
    }

    if ($path === '/rejected') {
        send($socket, 200, 'application/json', '{"$summary":{"errors":["1220 : Signature Incorrect"]}}');
        return;
    }

    if (preg_match('#^/status/(\d{3})$#', $path, $m)) {
        send($socket, (int) $m[1], 'application/json', '{"$summary":{"errors":["node said ' . $m[1] . '"]}}');
        return;
    }

    if (preg_match('#^/plain/(\d{3})$#', $path, $m)) {
        send($socket, (int) $m[1], 'text/plain', 'not json');
        return;
    }

    send($socket, 404, 'text/plain', 'no such scripted route');
}

/** @param resource $socket */
function send($socket, int $status, string $type, string $body): void
{
    fwrite($socket, sprintf(
        "HTTP/1.1 %d Scripted\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        $status,
        $type,
        strlen($body),
        $body
    ));
    fclose($socket);
}
