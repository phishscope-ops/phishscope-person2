<?php
declare(strict_types=1);
use P2\{Config, Engines, Fetcher, IntelHub, Scanner, Store, Api};

const PUBLIC_IP = '93.184.216.34';

function cfg(array $o = []): Config {
    $c = new Config();
    $c->dbPath = ':memory:';
    foreach ($o as $k => $v) $c->$k = $v;
    return $c;
}

/** resolver: map host => ip or list or null (fails). Anything else answers PUBLIC_IP. */
function resolver(array $map = []): callable {
    return function (string $host, int $port) use ($map) {
        $v = array_key_exists($host, $map) ? $map[$host] : PUBLIC_IP;
        if ($v === null) throw new RuntimeException('nx');
        return is_array($v) ? $v : [$v];
    };
}

/** fake web: routes[url] = [status, location] ; default answers 200. Records the URLs it was asked for. */
final class FakeWeb {
    public array $calls = [];
    public function __construct(public array $routes = [], public int $default = 200, public ?string $failWith = null) {}
    public function __invoke(string $url, string $host, int $port, string $ip, float $remaining): array {
        $this->calls[] = ['url' => $url, 'host' => $host, 'ip' => $ip, 'port' => $port];
        if ($this->failWith) throw new P2\FetchError($this->failWith);
        $r = $this->routes[$url] ?? null;
        return $r ? [$r[0], $r[1] ?? '', 'text/html', false] : [$this->default, '', 'text/html', false];
    }
}

function scanner(array $o = [], ?FakeWeb $web = null, ?array $res = null, ?callable $post = null, ?array $intel = []): Scanner {
    $c = cfg($o);
    $web ??= new FakeWeb();
    $s = new Scanner($c, new Engines($c, $post), new IntelHub($c, $intel), new Fetcher($c, resolver($res ?? []), $web));
    $s->web = $web;
    return $s;
}

function api(array $o = [], ?Scanner $sc = null): Api {
    $c = cfg($o);
    $sc ??= scanner($o);
    $sc->cfg = $c;
    return new Api($c, $sc, new Store(':memory:'));
}

function call(Api $a, string $method, string $path, $body = null, array $headers = []): array {
    return $a->handle($method, $path, $headers, $body === null ? '' : (is_string($body) ? $body : json_encode($body)), '1.1.1.1');
}
