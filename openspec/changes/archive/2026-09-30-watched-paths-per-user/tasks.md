## 1. Extension

- [x] 1.1 Accept `~/` entries, judged below the home
- [x] 1.2 Expand them into root's and every person's home, read from the directory service, dropping an expansion that would not be watched
- [x] 1.3 Re-read the accounts every five minutes and re-apply the set when they change
- [x] 1.4 Unit tests for acceptance, account selection and expansion

## 2. Server and UI

- [x] 2.1 Validate `~/` entries in the operator's set
- [x] 2.2 The watched-path editor, the OpenAPI description and the operations guide name the form

## 3. Validation

- [x] 3.1 On edr-dev, push `~/.ssh/authorized_keys`, write the file in an existing home and in one added after the push, and confirm both writes are uploaded
- [ ] 3.2 Before RC, confirm on edr-qa (SIP on) that the sandboxed extension reads the account list
