# Report activation outcomes to the operator, not only to a redacted log

## Why

`edr activate` can fail and print nothing at all. Measured on edr-dev: exit code 1, zero bytes on stdout, zero bytes on stderr. The reason exists only in the unified log, and there it reads `<private>`.

Two independent causes, both in the host app's `OSSystemExtensionRequestDelegate` conformance:

- **The extension-request path never wrote to stdout or stderr.** Every outcome went to `logger` alone, while the enable path immediately below it used `print` for both success and failure. So the two halves of one command had opposite visibility, and the invisible half is the one that runs first and can abort the whole command.
- **The log line redacted the reason.** Interpolating non-literals into an os_log message defaults them to `privacy: .private`. Neither an extension identifier nor an `OSSystemExtensionError` description is sensitive, and the same file already uses an explicit public annotation elsewhere; this path just did not.

This is diagnosability, not function, but it has already cost real time. The pkg-upgrade investigation for issue #684 stalled on it twice: the command failed silently, and going to the log produced a redacted answer. The install path invokes this same command through the activation LaunchAgent, where `last exit code = 1` is the entire available signal. A customer whose extensions fail to activate gets a host with no telemetry, no explanation, and a support conversation that starts from a sysdiagnose.

## What changes

- **Activation outcomes are reported to the operator.** Request submitted, awaiting user approval, completed, will complete after reboot, unknown result, and failure now reach stdout or stderr as appropriate, instead of only the log.
- **Failures go to stderr**, so a caller that captures or pipes normal output still sees them separately.
- **The mirrored log lines are explicitly public**, so the reason is readable in the log rather than `<private>`.
- **The awaiting-approval case is reported too.** On an unmanaged Mac that is the expected state and the process deliberately stays alive while the request is pending, so silence there is indistinguishable from a hang.
