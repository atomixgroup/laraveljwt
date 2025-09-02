<?php

namespace Aramin\Jwt;

use Illuminate\Support\ServiceProvider;

class JwtServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/jwt.php', 'jwt');

        $this->app->singleton(JWTService::class, function ($app) {
            return new JWTService();
        });
    }

    public function boot()
    {
        // publish config
        $this->publishes([
            __DIR__ . '/../config/jwt.php' => config_path('jwt.php'),
        ], 'config');

        // load routes from package (فایل routes/api.php را می‌سازیم پایین)
        if (file_exists(__DIR__ . '/../routes/api.php')) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/api.php');
        }

        // middleware alias
        $this->app['router']->aliasMiddleware('jwt.auth', JWTMiddleware::class);
    }
}
