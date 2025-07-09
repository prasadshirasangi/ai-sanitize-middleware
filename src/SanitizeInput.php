<?php

namespace Ai\SanitizeMiddleware;

use Closure;
use Illuminate\Support\Facades\Log;

class SanitizeInput
{
    public function handle($request, Closure $next)
    {
        $inputs = array_merge_recursive($request->all(), $request->query());

        $flatInputs = $this->flattenInputs($inputs);

        foreach ($flatInputs as $key => $value) {
            if ($this->hasXSS($value)) {
                return $this->block("XSS attack", $key, $value);
            }

            if ($this->hasSQLInjection($value)) {
                return $this->block("SQL injection", $key, $value);
            }

            if ($this->hasDangerousPattern($value)) {
                return $this->block("Malicious pattern", $key, $value);
            }
        }

        return $next($request);
    }

    private function flattenInputs($input, $prefix = '')
    {
        $flat = [];

        foreach ($input as $key => $value) {
            $name = $prefix ? $prefix . '.' . $key : $key;

            if (is_array($value)) {
                $flat += $this->flattenInputs($value, $name);
            } else {
                $flat[$name] = is_string($value) ? $value : json_encode($value);
            }
        }

        return $flat;
    }

    private function block($type, $key, $value)
    {
        Log::warning("Blocked $type in [$key]:", ['value' => $value]);

        return response()->json([
            'error' => "Blocked request: $type detected in '$key'."
        ], 400);
    }

    protected function hasXSS($value)
    {
        return preg_match('/(<script\b[^>]*>.*?<\/script>|on\w+\s*=|javascript:|<\s*img\b[^>]*src\s*=\s*[\'"]?javascript:)/i', $value);
    }

    protected function hasSQLInjection($value)
    {
        return preg_match('/(\b(select|insert|update|delete|drop|union|alter|create)\b\s+.+|\bor\b\s+\d+=\d+|--|#|\/\*|\bexec\b|\btruncate\b)/i', $value);
    }

    protected function hasDangerousPattern($value)
    {
        return strlen($value) > 10000 || preg_match('/(.)\1{100,}/', $value);
    }
}
