# Changelog

All notable changes to this project will be documented in this file.

## [0.3.2] - 2025-02-21

### 🐛 Bug Fixes

- Uninstall command removes dispatcher not the entire package
- Use includestr for template files and dont rely on path

<!-- generated by git-cliff -->
## [0.3.1] - 2025-02-20

### 🐛 Bug Fixes

- Use XDG path for logging

<!-- generated by git-cliff -->
## [0.2.14] - 2025-02-20

### 💼 Other

- 0.3.0

<!-- generated by git-cliff -->
## [0.2.13] - 2025-02-20

### 🚀 Features

- Remove openssl dep and use rustls for emails

<!-- generated by git-cliff -->
## [0.2.12] - 2025-02-20

### ⚙️ Miscellaneous Tasks

- Enable git release on release-plz and add libssl dep

<!-- generated by git-cliff -->
## [0.2.11] - 2025-02-20

### 🚀 Features

- Add footer to IP email

### ⚙️ Miscellaneous Tasks

- Switch to {{ version }}

<!-- generated by git-cliff -->
## [0.2.10] - 2025-02-20

### 🚀 Features

- Update email style

<!-- generated by git-cliff -->
## [0.2.9] - 2025-02-19

### 🐛 Bug Fixes

- Update release.yml

### ⚙️ Miscellaneous Tasks

- Disabled github release for release-plz
- Release v0.2.8

<!-- generated by git-cliff -->
## [0.2.8] - 2025-02-19

### ⚙️ Miscellaneous Tasks

- Disabled github release for release-plz

<!-- generated by git-cliff -->
## [0.2.7] - 2025-02-19

### 🚀 Features

- Update readme

### ⚙️ Miscellaneous Tasks

- Update release.yml

<!-- generated by git-cliff -->
## [0.2.6] - 2025-02-19

### 🚀 Features

- Add alternate approach to ip notification without polling

### 🐛 Bug Fixes

- Use network-manager dispatcher instead of wpa_cli action script
- Ignore AP connections while emailing IP

### ⚙️ Miscellaneous Tasks

- Updated release-plz workflow

<!-- generated by git-cliff -->
## [0.2.5] - 2025-02-17

### 🐛 Bug Fixes

- Rename release-plz and cargo-dist workflows

### ⚙️ Miscellaneous Tasks

- Switch to PAT instead of default github actions token
- Fixed typo on tokens

<!-- generated by git-cliff -->
## [0.2.4] - 2025-02-17

### 🚀 Features

- Added support for multiple email recipients.
- Add cargo-dist for building and shipping binaries

### 🐛 Bug Fixes

- Removed rate limiter as it prevented initial boot up email
- Split email recepients properly within install-service function

### 💼 Other

- Added 5 sec wait before forcing ip notification.

<!-- generated by git-cliff -->
## [0.2.3](https://github.com/neurobionics/robonet/compare/v0.2.2...v0.2.3) - 2025-02-13

### Other

- Switching to release-plz instead of cargo-release.
- Adding pre-release hooks to cargo-release.

## 2025-02-12

### 💼 Other

- Initial commit
- Update README.md
- Adding connection files for nm
- Create .gitignore
- Added rust-cli example to get started.
- Added some template connections for nm
- Added EAP connection template.
- Added functions to receive user input to generate connection files.
- Added network manager connection reload to identify newly added connections.
- Moving network configuration functions to a separate module.
- Added autoconnect and priority to network configs.
- Added services.
- Mailer works! Added a way to install the service with env variables.
- Added get_env method to fetch env variables properly and added a manual command to send status emails. Merged send_ip_email and send_status_email together into one func.
- Renamed & organized modules, added logging, and a command to view logs.
- Organized template files and added them to build. Modified email subject.
- Added uninstall command and renamed robot-network-manager to robonet-monitor.
- Fixed path bug for email template.
- Added error codes for network, service, email, system, and misc errors.
- Removed env_logger from deps.
- Fixed AP connection bug.
- Added connectivity test command.
- Fixed connectivity test command.
- Added command to map networks.
- Updated parameters.
- Added rust workflow
- Added more manifest data.
- Added description to toml file.
- Updated license field.
- Added security fixes, validation, and some error handling. Bumped version to 0.2.0
- Fixed email bug and added deb package tag in toml.
- Fixed setting up log before previlege check.
- Reduced max log file size to 25mb
- Updated rust workflow to create and attach deb release.

<!-- generated by git-cliff -->
