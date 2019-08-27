<?php

namespace Cartrabbit\Validator;

use Illuminate\Support\ServiceProvider;

class ValidationServiceProvider extends ServiceProvider
{
    /**
     * Register service
     */
    public function register()
    {
        $this->app->singleton('validation', function () {
            return new ValidationBuilder();
        });
    }
}
