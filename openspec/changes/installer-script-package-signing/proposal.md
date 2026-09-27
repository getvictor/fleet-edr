# Report the signature of the package an installer script belongs to

## Why

Installing any `.pkg` raises `suspicious_exec`, because PackageKit runs a package's preinstall and postinstall under Apple's own `package_script_service`, out of a temporary sandbox (issue #1161). The process chain the rule judges names Apple's installer and never the vendor whose package it is, so an operator can only silence it by trusting every package on the fleet, which is the technique the rule is best placed to catch.

Investigated on edr-dev: the identity is reachable. PackageKit hands each script the path of its package as the first argument (Apple's documented script interface), and `pkgutil --check-signature` reads that package's signature locally in about 0.2 s. There is no public Security API for a flat package's signature.

## What changes

The agent attaches `package_signing` (`signed`, `notarized`, `team_id`) to an installer script's exec, reading the package named by the script's first argument. It does so only when the exec's parent is `package_script_service`, because the argument is anyone's to write and a script run from a shell could otherwise borrow a signed vendor package's identity. An unreadable package leaves the field absent.

This change is the producer only. The rule that consumes it follows separately: it lets an operator trust one vendor's installers by team without trusting every package.

## Not changed

No detection decision changes here. An event from an agent without this change simply carries no `package_signing`.
