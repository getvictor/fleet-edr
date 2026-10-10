## Why

The app and both extensions were built for macOS 26.2 while the installer accepted macOS 13. A Mac on 13 through 26.1 installed the package, reported success, and then could not launch the app or activate the extensions, so the endpoint sent nothing and nothing said why.

## What changes

- The app and both extensions are built for macOS 26.0, and the installer refuses any Mac older than 26.0 with a message naming the requirement.
- A test fails the build if the installer minimum and the deployment target disagree again.

## Not changed

Supported hardware is unchanged: Apple Silicon only. Macs already on macOS 26 install and upgrade exactly as before.
