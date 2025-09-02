<?php

return [
    // الگوریتم: 'HS256' یا 'RS256'
    'algo' => env('JWT_ALGO', 'HS256'),

    // برای HS256
    'secret' => env('JWT_SECRET', env('APP_KEY')),

    // برای RS256 (در صورت استفاده)
    'private_key_path' => env('JWT_PRIVATE_KEY_PATH', storage_path('app/jwt_private.pem')),
    'public_key_path'  => env('JWT_PUBLIC_KEY_PATH', storage_path('app/jwt_public.pem')),

    // TTL به دقیقه (مثلاً 15 => 15 دقیقه)
    'ttl' => (int) env('JWT_TTL', 15),

    // آیا توکن در Cookie قرار بگیرد؟ (پیشنهادی: true)
    'use_cookie' => (bool) env('JWT_USE_COOKIE', true),
    'cookie_name' => env('JWT_COOKIE_NAME', 'access_token'),
];
