# windows-event-collection Specification

## Purpose

The Windows agent collects process telemetry from the Microsoft-Windows-Kernel-Process ETW provider without a kernel driver, emitting platform-stamped `exec` and `exit` envelopes that carry DOS image paths and a `create_time_ns` pid epoch (the Windows analogue of macOS pid_version) to disambiguate PID reuse.

## Requirements

### Requirement: Windows process telemetry via ETW

The Windows agent SHALL collect process telemetry by consuming the Microsoft-Windows-Kernel-Process ETW provider without a kernel driver. It SHALL emit a process start as an `exec` event and a process stop as an `exit` event, each stamped with the `windows` platform. It SHALL report the process image path as a DOS path (converted from the NT device path ETW provides) and SHALL carry the process creation time as `create_time_ns`, the platform-neutral pid_epoch that disambiguates PID reuse (the Windows analogue of macOS pid_version), so an exit can be paired with the exec of the same process generation.

#### Scenario: A process start becomes an exec envelope

- **GIVEN** the Windows sensor observes a process-start event
- **WHEN** it maps the event
- **THEN** it produces an `exec` envelope stamped platform `windows` carrying the process id, parent process id, and image path

#### Scenario: A process stop becomes an exit envelope

- **GIVEN** the Windows sensor observes a process-stop event
- **WHEN** it maps the event
- **THEN** it produces an `exit` envelope stamped platform `windows` carrying the process id and exit code

#### Scenario: The process create time is carried as the pid epoch

- **GIVEN** a process-start event with a kernel creation time
- **WHEN** the sensor maps it
- **THEN** the envelope carries the creation time as `create_time_ns` in Unix nanoseconds

#### Scenario: An NT device image path is reported as a DOS path

- **GIVEN** an image path expressed as an NT device path (for example a HarddiskVolume path)
- **WHEN** the sensor maps the event using the host's device-to-drive map
- **THEN** the reported path is the DOS-drive form (for example a C: path)
