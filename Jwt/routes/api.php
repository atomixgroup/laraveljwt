<?php

use Illuminate\Support\Facades\Route;
use Aramin\Jwt\Http\Controllers\AuthController;

Route::prefix('api')->group(function () {
    Route::post('jwt/login', [AuthController::class, 'login'])->middleware('throttle:10,1');
    Route::post('jwt/logout', [AuthController::class, 'logout'])->middleware('jwt.auth');

    // مثال یک route محافظت‌شده
    Route::middleware('jwt.auth')->get('jwt/profile', function (\Illuminate\Http\Request $request) {
        return response()->json([
            'user' => $request->user(),
            'jwt_payload' => $request->attributes->get('jwt_payload'),
        ]);
    });
});
