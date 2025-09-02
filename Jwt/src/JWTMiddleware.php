<?php

namespace Aramin\Jwt;

use Closure;
use Illuminate\Http\Request;

class JWTMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();

        if (! $token && config('jwt.use_cookie')) {
            $token = $request->cookie(config('jwt.cookie_name'));
        }

        if (! $token) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $jwt = app(JWTService::class);
        $payload = $jwt->decode($token);

        if (! $payload) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        if (isset($payload['sub'])) {
            $user = \App\Models\User::find($payload['sub']);
            if ($user) {
                $request->setUserResolver(fn() => $user);
            }
        }

        $request->attributes->set('jwt_payload', $payload);

        return $next($request);
    }
}
