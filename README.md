# SARIF support for Radare2

![ci](https://github.com/radareorg/r2sarif/actions/workflows/ci.yml/badge.svg?branch=main)

Static Analysis Results Interchange Format (SARIF) Version 2.0

--pancake

## Description

This plugin for radare2 adds the `sarif` command to the r2 shell which allows
to import and export SARIF documents (JSON files) into the current session,
allowing the analyst to report and visualize the reported vulnerabilities in
a binary using a standard file format.

## Installation

This is the recommended way to install r2sarif nowadays, in your home and symlinked.

```
$ make && make user-symstall
```

For distro packaging reasons you may want to use make install instead.

Use the classic `user-uninstall` and `uninstall` targets to get rid of it.

## Usage

```
[0x00000000]> sarif?
sarif add [L] [id] [M]  - add a new result with selected driver
sarif alias [newalias]  - create an alias for the sarif command
sarif export            - export added rules as sarif json
sarif help              - show this help message (-h)
sarif list [help]       - list drivers, rules and results
sarif load [file]       - import sarif info from given file
sarif r2                - generate r2 script to import current doc results
sarif reset             - unload all documents
sarif select [N]        - select the nth driver
sarif unload [N]        - unload the nth document
sarif version           - show plugin version
[0x00000000]>
```

First you need to load the drivers with their rules, so you can load them as
flags and comments into your r2 session and use them to create your

```
[0x00000000]> sarif load rules.json
```

Those can be listed with `sarif list [what]` and use `sarif select` to pick
which document you want the rest of commands to use.

## Creating your own sarif document

* Seek to the offset where the vulnerability is spotted
  * `s 0x802180490`
* Add a warning note in the current offset associated with a comment
  * `sarif addw SF01010 Do not use this API`

You can now export the sarif file in json using the following command:

```
[0x00000000]> sarif dump > sarif.report.json
[0x00000000]> sarif r2 > sarif.script.r2
```

Alternatively you can combine multiple finding documents and load that info inside r2:

```
[0x00000000]> sarif load report0.json
[0x00000000]> sarif load report1.json
[0x00000000]> .sarif r2
```

You will have flags prefixed with `sarif.` to spot them in the binary. `f~^sarif`

## Reference Links

* https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
* https://github.com/microsoft/sarif-tutorials/
* https://docs.oasis-open.org/sarif/sarif/v2.0/sarif-v2.0.html
* https://sarifweb.azurewebsites.net/#Specification
* https://github.blog/2024-02-14-fixing-security-vulnerabilities-with-ai/
