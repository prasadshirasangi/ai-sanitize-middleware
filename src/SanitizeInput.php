<?php
namespace Ai\Sanitize;

use Closure;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpKernel\Exception\HttpException;

class SanitizeInput
{
    public function handle($request, Closure $next)
    {
        $inputs = array_merge_recursive($request->all(), $request->query());
        $flatInputs = $this->flattenInputs($inputs);

        foreach ($flatInputs as $key => $value) {
            if ($this->hasXSS($value)) {
                $this->block("XSS attack", $key, $value);
            }

            if ($this->hasSQLInjection($value)) {
                $this->block("SQL injection", $key, $value);
            }

            if ($this->hasDangerousPattern($value)) {
                $this->block("Malicious pattern", $key, $value);
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

        // Throw Laravel's default 403 Forbidden exception
        throw new HttpException(403, "Forbidden: $type detected in '$key'");
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
