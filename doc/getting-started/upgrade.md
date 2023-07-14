---
title: "Upgrade"
slug: "upgrade"
excerpt: "Upgrade to the latest stable releases without interruption."
hidden: false
createdAt: "2022-11-18T14:32:58.821Z"
updatedAt: "2023-01-25T10:54:43.810Z"
---
Upgrading your Core Lightning node is the same as installing it. So if you previously installed it using a release binary, download the latest binary in the same directory as before. If you previously built it from the source, fetch the latest source and build it again.

> 🚧 
> 
> Upgrades to Core Lightning often change the database: once this is done, downgrades are not generally possible. By default, Core Lightning will exit with an error rather than upgrade, unless this is an official released version. 
> 
> If you really want to upgrade to a non-release version, you can set `database-upgrade=true` in your configuration file, or start `lightningd` with `--database-upgrade=true`(or set to false to never allow a non-reversible upgrade!)