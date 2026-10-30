#!/usr/bin/env bash
#
# Installs this package the way a consumer would and exercises it.
#
#   tests/smoke/run.sh
#
# A scratch project requires activeledger/sdk through a path repository that
# holds a COPY of this working tree (not a symlink, and without vendor/, .git
# or tests/), so only files that would ship are visible to the autoloader.
# Packagist is disabled; the runtime dependencies are copied from this
# checkout's vendor/ at the versions installed there, so no network is used.
# Run `composer install` in the repository first.
#
# smoke.php then generates each key type, builds and signs a transaction,
# verifies it, and submits to a loopback server twice: a committed reply, and
# a rejection answered with HTTP 200.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ ! -f "$repo/vendor/composer/installed.json" ]; then
    echo "run 'composer install' in $repo first: the smoke test reuses its dependencies" >&2
    exit 2
fi

# The package, as a consumer would receive it.
mkdir "$work/sdk" "$work/app"
tar -C "$repo" --exclude=./vendor --exclude=./.git --exclude=./tests -cf - . | tar -C "$work/sdk" -xf -

# The consumer's composer.json: the package plus a path repository for each
# non-dev dependency the package pulls in, pinned to the installed version.
php -r '
    [, $repo, $work] = $argv;
    $installed = json_decode(file_get_contents("$repo/vendor/composer/installed.json"), true);
    $dev = $installed["dev-package-names"] ?? [];

    $repositories = [[
        "type" => "path",
        "url" => "$work/sdk",
        "options" => ["symlink" => false, "versions" => ["activeledger/sdk" => "1.0.0"]],
    ]];
    foreach ($installed["packages"] as $package) {
        if (in_array($package["name"], $dev, true)) {
            continue;
        }
        $target = "$work/deps/" . str_replace("/", "-", $package["name"]);
        mkdir($target, 0777, true);
        passthru("cp -R " . escapeshellarg("$repo/vendor/{$package["name"]}/.") . " " . escapeshellarg($target));
        $repositories[] = [
            "type" => "path",
            "url" => $target,
            "options" => ["symlink" => false, "versions" => [$package["name"] => ltrim($package["version"], "v")]],
        ];
    }
    $repositories[] = ["packagist.org" => false];

    file_put_contents("$work/app/composer.json", json_encode([
        "name" => "smoke/consumer",
        "require" => ["activeledger/sdk" => "1.0.0"],
        "repositories" => $repositories,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
' "$repo" "$work"

composer --working-dir="$work/app" install --no-interaction --no-progress --no-cache --quiet

cp "$repo/tests/fixtures/loopback-server.php" "$work/app/loopback-server.php"
cp "$repo/tests/smoke/smoke.php" "$work/app/smoke.php"
php "$work/app/smoke.php"
