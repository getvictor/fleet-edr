## Why

A login item registered through `SMAppService` (MITRE T1547.015) reaches the server unjudgeable. Captured on a VM, Background Task Management reports such an item relative to the app that registered it (`Contents/Library/LoginItems/Helper.app`, with the app as a separate `app_url`) and reports no executable path. The extension forwarded only the relative item, so the agent had nothing to sign-check, and a persistence rule could neither say where the item lives nor judge who signed it (issue #1167).

## What changes

- The extension sends the registering app's bundle as `app_url` on `btm_launch_item_add`.
- The agent resolves an item path reported relative to that app into an absolute `file://` URL before upload.
- For a login item, which has no executable path, the agent evaluates the code signing of the helper app bundle the item names and sends it as `executable_code_signing`, as it does for a launch daemon's or agent's executable.

## Not changed

Launch daemon and agent registrations with an absolute item path and an executable path are sent as before. No server rule judges login items yet; that follows as its own change, once hosts send what it needs.
