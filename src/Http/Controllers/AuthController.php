<?php

namespace Aramin\Jwt\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Aramin\Jwt\JWTService;

class AuthController extends Controller
{
    protected $jwt;

    public function __construct(JWTService $jwt)
    {
        $this->jwt = $jwt;
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);

        $user = \App\Models\User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        // payload: sub => user id
        $token = $this->jwt->encode([
            'sub' => $user->id,
            'email' => $user->email, // اختیاری
            'role' => $user->role ?? null // اگر داری
        ]);

        if (config('jwt.use_cookie')) {
            $cookieName = config('jwt.cookie_name');
            $minutes = (int) config('jwt.ttl', 120);
            $cookie = cookie($cookieName, $token, $minutes, '/', null, true, true, false, 'Strict');
            return response()->json(['message' => 'Logged in'])->withCookie($cookie);
        }

        return response()->json(['access_token' => $token, 'expires_in' => config('jwt.ttl') * 60]);
    }

    public function logout(Request $request)
    {
        // با توجه به اینکه ری‌فریش نداریم، برای logout فقط کوکی را پاک می‌کنیم
        $response = response()->json(['message' => 'Logged out']);
        if (config('jwt.use_cookie')) {
            $response->withCookie(cookie()->forget(config('jwt.cookie_name')));
        }
        return $response;
    }
}
