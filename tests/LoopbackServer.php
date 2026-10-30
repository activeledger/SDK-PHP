<?php

declare(strict_types=1);

namespace Activeledger\Tests;

/**
 * Starts tests/fixtures/loopback-server.php and stops it again.
 *
 * The server picks its own port and reports it, so there is no free-port race,
 * and it exits when its stdin closes, so a test run that dies without reaching
 * stop() still leaves nothing behind.
 */
final class LoopbackServer
{
    /** @var resource */
    private $process;

    /** @var array<int, resource> */
    private array $pipes;

    private function __construct(public readonly string $url)
    {
    }

    public static function start(): self
    {
        $process = proc_open(
            [PHP_BINARY, __DIR__ . '/fixtures/loopback-server.php'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        if ($process === false) {
            throw new \RuntimeException('Could not start the loopback server');
        }

        // Blocks until the server has bound its port and printed it.
        $address = fgets($pipes[1]);
        if ($address === false) {
            proc_terminate($process);
            throw new \RuntimeException('Loopback server did not report an address: ' . stream_get_contents($pipes[2]));
        }

        $server = new self('http://' . trim($address));
        $server->process = $process;
        $server->pipes = $pipes;

        return $server;
    }

    public function stop(): void
    {
        // Closing stdin is the server's cue to exit; terminate covers a
        // server that is somehow stuck.
        fclose($this->pipes[0]);
        proc_terminate($this->process);
        fclose($this->pipes[1]);
        fclose($this->pipes[2]);
        proc_close($this->process);
    }

    /**
     * The previous request the server saw, other than this lookup itself.
     *
     * @return array{method: string, path: string, contentType: string, accept: string, body: string}
     */
    public function lastRequest(): array
    {
        $json = file_get_contents($this->url . '/__last');
        if ($json === false) {
            throw new \RuntimeException('Could not read the last request from the loopback server');
        }

        return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    }
}
