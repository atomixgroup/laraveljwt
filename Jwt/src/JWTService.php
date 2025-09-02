<?php

namespace Aramin\Jwt;

class JWTService
{
    protected $algo;
    protected $secret;
    protected $privateKeyPath;
    protected $publicKeyPath;
    protected $ttl; // minutes

    public function __construct()
    {
        $cfg = config('jwt');
        $this->algo = $cfg['algo'] ?? 'HS256';
        $this->secret = $cfg['secret'] ?? env('APP_KEY');
        $this->privateKeyPath = $cfg['private_key_path'] ?? null;
        $this->publicKeyPath = $cfg['public_key_path'] ?? null;
        $this->ttl = $cfg['ttl'] ?? 15;
    }

    public function encode(array $claims): string
    {
        $header = ['typ' => 'JWT', 'alg' => $this->algo];

        $now = time();
        $payload = array_merge($claims, [
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + ($this->ttl * 60),
        ]);

        $bHeader = $this->base64UrlEncode(json_encode($header));
        $bPayload = $this->base64UrlEncode(json_encode($payload));
        $signature = $this->sign($bHeader . '.' . $bPayload);
        $bSignature = $this->base64UrlEncode($signature);

        return $bHeader . '.' . $bPayload . '.' . $bSignature;
    }

    public function decode(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;

        [$bHeader, $bPayload, $bSignature] = $parts;

        $header = json_decode($this->base64UrlDecode($bHeader), true);
        $payload = json_decode($this->base64UrlDecode($bPayload), true);
        if (! $header || ! $payload) return null;

        // alg check (optional)
        if (($header['alg'] ?? '') !== $this->algo) {
            return null;
        }

        // verify signature
        $expected = $this->sign($bHeader . '.' . $bPayload);
        if (! hash_equals($this->base64UrlEncode($expected), $bSignature)) {
            return null;
        }

        $now = time();
        if (isset($payload['nbf']) && $payload['nbf'] > $now) return null;
        if (isset($payload['exp']) && $payload['exp'] < $now) return null;

        return $payload;
    }

    protected function sign(string $data): string
    {
        if ($this->algo === 'HS256') {
            return hash_hmac('sha256', $data, $this->secret, true);
        }

        if ($this->algo === 'RS256') {
            $pkey = openssl_pkey_get_private('file://' . $this->privateKeyPath);
            if (! $pkey) {
                throw new \RuntimeException('Private key not found for RS256.');
            }
            $sig = '';
            openssl_sign($data, $sig, $pkey, OPENSSL_ALGO_SHA256);
            openssl_free_key($pkey);
            return $sig;
        }

        throw new \RuntimeException('Unsupported JWT alg: ' . $this->algo);
    }

    protected function base64UrlEncode($data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    protected function base64UrlDecode($data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) $data .= str_repeat('=', 4 - $remainder);
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
