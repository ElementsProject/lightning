---
title: "Advanced DB Backup"
slug: "advanced-db-backup"
excerpt: "Learn the various DB backup techniques."
hidden: false
---

To recover in-channel funds, you need to use one or more of the backup strategies below.


## SQLITE3 `--wallet=${main}:${backup}` And Remote NFS Mount


> 📘 Who should do this:
> 
> Casual users.


> 🚧 
> 
> This technique is only supported after the version v0.10.2 (not included) or later.
> 
> On earlier versions, the `:` character is not special and will be considered part of the path of the database file.


When using the SQLITE3 backend (the default), you can specify a second database file to replicate to, by separating the second file with a single `:` character in the `--wallet` option, after the main database filename.

For example, if the user running `lightningd` is named `user`, and you are on the Bitcoin mainnet with the default `${LIGHTNINGDIR}`, you can specify in your `config` file:

```shell
wallet=sqlite3:///home/user/.lightning/bitcoin/lightningd.sqlite3:/my/backup/lightningd.sqlite3
```

Or via command line:

```
lightningd --wallet=sqlite3:///home/user/.lightning/bitcoin/lightningd.sqlite3:/my/backup/lightningd.sqlite3
```

If the second database file does not exist but the directory that would contain it does exist, the file is created.  
If the directory of the second database file does not exist, `lightningd` will fail at startup.  
If the second database file already exists, on startup it will be overwritten with the main database.  
During operation, all database updates will be done on both databases.

The main and backup files will **not** be identical at every byte, but they will still contain the same data.

It is recommended that you use **the same filename** for both files, just on different directories.

This has the advantage compared to the `backup` plugin below of requiring exactly the same amount of space on both the main and backup storage. The `backup` plugin will take more space on the backup than on the main storage.  
It has the disadvantage that it will only work with the SQLITE3 backend and is not supported by the PostgreSQL backend, and is unlikely to be supported on any future database backends.

You can only specify _one_ replica.

It is recommended that you use a network-mounted filesystem for the backup destination.  
For example, if you have a NAS you can access remotely. Note you need to mount the network filesystem using NFS version 4.

At the minimum, set the backup to a different storage device.  
This is no better than just using RAID-1 (and the RAID-1 will probably be faster) but this is easier to set up --- just plug in a commodity USB flash disk (with metal casing, since a lot of writes are done and you need to dissipate the heat quickly) and use it as the backup location, without  
repartitioning your OS disk, for example.


> 📘 
> 
> Do note that files are not stored encrypted, so you should really not do this with rented space ("cloud storage").


To recover, simply get **all** the backup database files.  
Note that SQLITE3 will sometimes create a `-journal` or `-wal` file, which is necessary to ensure correct recovery of the backup; you need to copy those too, with corresponding renames if you use a different filename for the backup database, e.g. if you named the backup `backup.sqlite3` and when you recover you find `backup.sqlite3` and `backup.sqlite3-journal` files, you rename `backup.sqlite3` to `lightningd.sqlite3` and  
`backup.sqlite3-journal` to `lightningd.sqlite3-journal`.  
Note that the `-journal` or `-wal` file may or may not exist, but if they _do_, you _must_ recover them as well (there can be an `-shm` file as well in WAL mode, but it is unnecessary;  
it is only used by SQLITE3 as a hack for portable shared memory, and contains no useful data; SQLITE3 will ignore its contents always).  
It is recommended that you use **the same filename** for both main and backup databases (just on different directories), and put the backup in its own directory, so that you can just recover all the files in that directory without worrying about missing any needed files or correctly  
renaming.

If your backup destination is a network-mounted filesystem that is in a remote location, then even loss of all hardware in one location will allow you to still recover your Lightning funds.

However, if instead you are just replicating the database on another storage device in a single location, you remain vulnerable to disasters like fire or computer confiscation.


## `backup` Plugin And Remote NFS Mount


> 📘 Who should do this:
> 
> Casual users.


You can find the full source for the `backup` plugin here:  
<https://github.com/lightningd/plugins/tree/master/backup>

The `backup` plugin requires Python 3.

- Download the source for the plugin.
  - `git clone https://github.com/lightningd/plugins.git`
- `cd` into its directory and install requirements.
  - `cd plugins/backup`
  - `pip3 install -r requirements.txt`
- Figure out where you will put the backup files.
  - Ideally you have an NFS or other network-based mount on your system, into which you will put the backup.
- Stop your Lightning node.
- `/path/to/backup-cli init --lightning-dir ${LIGHTNINGDIR} file:///path/to/nfs/mount/file.bkp`.  
  This creates an initial copy of the database at the NFS mount.
- Add these settings to your `lightningd` configuration:
  - `important-plugin=/path/to/backup.py`
- Restart your Lightning node.

It is recommended that you use a network-mounted filesystem for the backup destination.  
For example, if you have a NAS you can access remotely.


> 📘 
> 
> Do note that files are not stored encrypted, so you should really not do this with rented space ("cloud storage").


Alternately, you _could_ put it in another storage device (e.g. USB flash disk) in the same physical location.

To recover:

- Re-download the `backup` plugin and install Python 3 and the  
  requirements of `backup`.
- `/path/to/backup-cli restore file:///path/to/nfs/mount ${LIGHTNINGDIR}`

If your backup destination is a network-mounted filesystem that is in a remote location, then even loss of all hardware in one location will allow you to still recover your Lightning funds.

However, if instead you are just replicating the database on another storage device in a single location, you remain vulnerable to disasters like fire or computer confiscation.


## Filesystem Redundancy


> 📘 Who should do this:
> 
> Filesystem nerds, data hoarders, home labs, enterprise users.


You can set up a RAID-1 with multiple storage devices, and point the `$LIGHTNINGDIR` to the RAID-1 setup. That way, failure of one storage device will still let you recover funds.

You can use a hardware RAID-1 setup, or just buy multiple commodity storage media you can add to your machine and use a software RAID, such as (not an exhaustive list!):

- `mdadm` to create a virtual volume which is the RAID combination of multiple physical media.
- BTRFS RAID-1 or RAID-10, a filesystem built into Linux.
- ZFS RAID-Z, a filesystem that cannot be legally distributed with the Linux kernel, but can be distributed in a BSD system, and can be installed on Linux with some extra effort, see  
  [ZFSonLinux](https://zfsonlinux.org).

RAID-1 (whether by hardware, or software) like the above protects against failure of a single storage device, but does not protect you in case of certain disasters, such as fire or computer confiscation.

You can "just" use a pair of high-quality metal-casing USB flash devices (you need metal-casing since the devices will have a lot of small writes, which will cause a lot of heating, which needs to dissipate very fast, otherwise the flash device firmware will internally disconnect the flash device from your computer, reducing your reliability) in RAID-1, if you have enough USB ports.


### Example: BTRFS on Linux

On a Linux system, one of the simpler things you can do would be to use BTRFS RAID-1 setup between a partition on your primary storage and a USB flash disk.

The below "should" work, but assumes you are comfortable with low-level Linux administration.  
If you are on a system that would make you cry if you break it, you **MUST** stop your Lightning node and back up all files before doing the below.

- Install `btrfs-progs` or `btrfs-tools` or equivalent.
- Get a 32Gb USB flash disk.
- Stop your Lightning node and back up everything, do not be stupid.
- Repartition your hard disk to have a 30Gb partition.
  - This is risky and may lose your data, so this is best done with a brand-new hard disk that contains no data.
- Connect the USB flash disk.
- Find the `/dev/sdXX` devices for the HDD 30Gb partition and the flash disk.
  - `lsblk -o NAME,TYPE,SIZE,MODEL` should help.
- Create a RAID-1 `btrfs` filesystem.
  - `mkfs.btrfs -m raid1 -d raid1 /dev/${HDD30GB} /dev/${USB32GB}`
  - You may need to add `-f` if the USB flash disk is already formatted.
- Create a mountpoint for the `btrfs` filesystem.
- Create a `/etc/fstab` entry.
  - Use the `UUID` option instad of `/dev/sdXX` since the exact device letter can change across boots.
  - You can get the UUID by `lsblk -o NAME,UUID`. Specifying _either_ of the devices is sufficient.
  - Add `autodefrag` option, which tends to work better with SQLITE3 databases.
  - e.g. `UUID=${UUID} ${BTRFSMOUNTPOINT} btrfs defaults,autodefrag 0 0`
- `mount -a` then `df` to confirm it got mounted.
- Copy the contents of the `$LIGHTNINGDIR` to the BTRFS mount point.
  - Copy the entire directory, then `chown -R` the copy to the user who will run the `lightningd`.
  - If you are paranoid, run `diff -r` on both copies to check.
- Remove the existing `$LIGHTNINGDIR`.
- `ln -s ${BTRFSMOUNTPOINT}/lightningdirname ${LIGHTNINGDIR}`.
  - Make sure the `$LIGHTNINGDIR` has the same structure as what you originally had.
- Add `crontab` entries for `root` that perform regular `btrfs` maintenance tasks.
  - `0 0 * * * /usr/bin/btrfs balance start -dusage=50 -dlimit=2 -musage=50 -mlimit=4 ${BTRFSMOUNTPOINT}`  
    This prevents BTRFS from running out of blocks even if it has unused space _within_ blocks, and is run at midnight everyday. You may need to change the path to the `btrfs` binary.
  - `0 0 * * 0 /usr/bin/btrfs scrub start -B -c 2 -n 4 ${BTRFSMOUNTPOINT}`  
    This detects bit rot (i.e. bad sectors) and auto-heals the filesystem, and is run on Sundays at midnight.
- Restart your Lightning node.

If one or the other device fails completely, shut down your computer, boot on a recovery disk or similar, then:

- Connect the surviving device.
- Mount the partition/USB flash disk in `degraded` mode:
  - `mount -o degraded /dev/sdXX /mnt/point`
- Copy the `lightningd.sqlite3` and `hsm_secret` to new media.
  - Do **not** write to the degraded `btrfs` mount!
- Start up a `lightningd` using the `hsm_secret` and `lightningd.sqlite3` and close all channels and move all funds to onchain cold storage you control, then set up a new Lightning node.

If the device that fails is the USB flash disk, you can replace it using BTRFS commands.  
You should probably stop your Lightning node while doing this.

- `btrfs replace start /dev/sdOLD /dev/sdNEW ${BTRFSMOUNTPOINT}`.
  - If `/dev/sdOLD` no longer even exists because the device is really really broken, use `btrfs filesystem show` to see the number after `devid` of the broken device, and use that number instead of `/dev/sdOLD`.
- Monitor status with `btrfs replace status ${BTRFSMOUNTPOINT}`.

More sophisticated setups with more than two devices are possible. Take note that "RAID 1" in `btrfs` means "data is copied on up to two devices", meaning only up to one device can fail.  
You may be interested in `raid1c3` and `raid1c4` modes if you have three or four storage devices. BTRFS would probably work better if you were purchasing an entire set  
of new storage devices to set up a new node.


## PostgreSQL Cluster


> 📘 Who should do this:
> 
> Enterprise users, whales.


`lightningd` may also be compiled with PostgreSQL support.

PostgreSQL is generally faster than SQLITE3, and also supports running a PostgreSQL cluster to be used by `lightningd`, with automatic replication and failover in case an entire node of the PostgreSQL cluster fails.

Setting this up, however, is more involved.

By default, `lightningd` compiles with PostgreSQL support **only** if it finds `libpq` installed when you `./configure`. To enable it, you have to install a developer version of `libpq`. On most Debian-derived systems that would be `libpq-dev`. To verify you have it properly installed on your system, check if the following command gives you a path:

```shell
pg_config --includedir
```

Versioning may also matter to you.  
For example, Debian Stable ("buster") as of late 2020 provides PostgreSQL 11.9 for the `libpq-dev` package, but Ubuntu LTS ("focal") of 2020 provides PostgreSQL 12.5.  
Debian Testing ("bullseye") uses PostgreSQL 13.0 as of this writing. PostgreSQL 12 had a non-trivial change in the way the restore operation is done for replication.

You should use the same PostgreSQL version of `libpq-dev` as what you run on your cluster, which probably means running the same distribution on your cluster.

Once you have decided on a specific version you will use throughout, refer as well to the "synchronous replication" document of PostgreSQL for the **specific version** you are using:

- [PostgreSQL 11](https://www.postgresql.org/docs/11/runtime-config-replication.html)
- [PostgreSQL 12](https://www.postgresql.org/docs/12/runtime-config-replication.html)
- [PostgreSQL 13](https://www.postgresql.org/docs/13/runtime-config-replication.html)

You then have to compile `lightningd` with PostgreSQL support.

- Clone or untar a new source tree for `lightning` and `cd` into it.
  - You _could_ just use `make clean` on an existing one, but for the avoidance of doubt (and potential bugs in our `Makefile` cleanup rules), just create a fresh source tree.
- `./configure`
  - Add any options to `configure` that you normally use as well.
- Double-check the `config.vars` file contains `HAVE_POSTGRES=1`.
  - `grep 'HAVE_POSTGRES' config.vars`
- `make`
- If you install `lightningd`, `sudo make install`.

If you were not using PostgreSQL before but have compiled and used `lightningd` on your system, the resulting `lightningd` will still continue supporting and using your current SQLITE3 database; it just gains the option to use a PostgreSQL database as well.

If you just want to use PostgreSQL without using a cluster (for example, as an initial test without risking any significant funds), then after setting up a PostgreSQL database, you just need to add  
`--wallet=postgres://${USER}:${PASSWORD}@${HOST}:${PORT}/${DB}` to your `lightningd` config or invocation.

To set up a cluster for a brand new node, follow this (external) [guide by @gabridome](https://github.com/gabridome/docs/blob/master/c-lightning_with_postgresql_reliability.md)

The above guide assumes you are setting up a new node from scratch. It is also specific to PostgreSQL 12, and setting up for other versions **will** have differences; read the PostgreSQL manuals linked above.


> 🚧 
> 
> If you want to continue a node that started using an SQLITE3 database, note that we do not support this. You should set up a new PostgreSQL node, move funds from the SQLITE3 node to the PostgreSQL node, then shut down the SQLITE3 node permanently.


There are also more ways to set up PostgreSQL replication.  
In general, you should use [synchronous replication](https://www.postgresql.org/docs/13/warm-standby.html#SYNCHRONOUS-REPLICATION), since `lightningd` assumes that once a transaction is committed, it is saved in all permanent storage. This can be difficult to create remote replicas due to the latency.


## SQLite Litestream Replication


> 🚧 
> 
> Previous versions of this document recommended this technique, but we no longer do so.  
> According to [issue 4857](https://github.com/ElementsProject/lightning/issues/4857), even with a 60-second timeout that we added in 0.10.2, this leads to 
constant crashing of `lightningd` in some situations. This section will be removed completely six months after 0.10.3. Consider using `--wallet=sqlite3://${main}:${backup}` above instead.


One of the simpler things on any system is to use Litestream to replicate the SQLite database. It continuously streams SQLite changes to file or external storage - the cloud storage option should not be used.  

Backups/replication should not be on the same disk as the original SQLite DB.

You need to enable WAL mode on your database.  
To do so, first stop `lightningd`, then:

```shell
$ sqlite3 lightningd.sqlite3
sqlite3> PRAGMA journal_mode = WAL;
sqlite3> .quit
```

Then just restart `lightningd`.

/etc/litestream.yml :

```shell
dbs:
 - path: /home/bitcoin/.lightning/bitcoin/lightningd.sqlite3
   replicas:
     - path: /media/storage/lightning_backup
```

 and start the service using systemctl:

```shell
$ sudo systemctl start litestream
```

Restore:

```shell
$ litestream restore -o /media/storage/lightning_backup  /home/bitcoin/restore_lightningd.sqlite3
```

Because Litestream only copies small changes and not the entire database (holding a read lock on the file while doing so), the 60-second timeout on locking should not be reached unless something has made your backup medium very very slow.

Litestream has its own timer, so there is a tiny (but non-negligible) probability that `lightningd` updates the  
database, then irrevocably commits to the update by sending revocation keys to the counterparty, and _then_ your main storage media crashes before Litestream can replicate the update. 

Treat this as a superior version of "Database File Backups" section below and prefer recovering via other backup methods first.


## Database File Backups


> 📘 Who should do this:
> 
> Those who already have at least one of the other backup methods, those who are #reckless.


This is the least desirable backup strategy, as it _can_ lead to loss of all in-channel funds if you use it.  
However, having _no_ backup strategy at all _will_ lead to loss of all in-channel funds, so this is still better than nothing.

This backup method is undesirable, since it cannot recover the following channels:

- Channels with peers that do not support `option_dataloss_protect`.
  - Most nodes on the network already support `option_dataloss_protect` as of November 2020.
  - If the peer does not support `option_dataloss_protect`, then the entire channel funds will be revoked by the peer.
  - Peers can _claim_ to honestly support this, but later steal funds from you by giving obsolete state when you recover.
- Channels created _after_ the copy was made are not recoverable.
  - Data for those channels does not exist in the backup, so your node cannot recover them.

Because of the above, this strategy is discouraged: you _can_ potentially lose all funds in open channels.

However, again, note that a "no backups #reckless" strategy leads to _definite_ loss of funds, so you should still prefer _this_ strategy rather than having _no_ backups at all.

Even if you have one of the better options above, you might still want to do this as a worst-case fallback, as long as you:

- Attempt to recover using the other backup options above first. Any one of them will be better than this backup option.
- Recover by this method **ONLY** as a **_last_** resort.
- Recover using the most recent backup you can find. Take time to look for the most recent available backup.

Again, this strategy can lead to only **_partial_** recovery of funds, or even to complete failure to recover, so use the other methods first to recover!


### Offline Backup

While `lightningd` is not running, just copy the `lightningd.sqlite3` file in the `$LIGHTNINGDIR` on backup media somewhere.

To recover, just copy the backed up `lightningd.sqlite3` into your new `$LIGHTNINGDIR` together with the `hsm_secret`.

You can also use any automated backup system as long as it includes the `lightningd.sqlite3` file (and optionally `hsm_secret`, but note that as a secret key, thieves getting a copy of your backups may allow them to steal your funds, even in-channel funds) and as long as it copies the file while `lightningd` is not running.


### Backing Up While `lightningd` Is Running

Since `sqlite3` will be writing to the file while `lightningd` is running, `cp`ing the `lightningd.sqlite3` file while `lightningd` is running may result in the file not being copied properly if `sqlite3` happens to be committing database transactions at that time, potentially leading to a corrupted backup file that cannot be recovered from.

You have to stop `lightningd` before copying the database to backup in order to ensure that backup files are not corrupted, and in particular, wait for the `lightningd` process to exit.  
Obviously, this is disruptive to node operations, so you might prefer to just perform the `cp` even if the backup potentially is corrupted. As long as you maintain multiple backups sampled at different times, this may be more acceptable than stopping and restarting `lightningd`; the corruption only exists in the backup, not in the original file.

If the filesystem or volume manager containing `$LIGHTNINGDIR` has a snapshot facility, you can take a snapshot of the filesystem, then mount the snapshot, copy `lightningd.sqlite3`, unmount the snapshot, and then delete the snapshot.  
Similarly, if the filesystem supports a "reflink" feature, such as `cp -c` on an APFS on MacOS, or `cp --reflink=always` on an XFS or BTRFS on Linux, you can also use that, then copy the reflinked copy to a different storage medium; this is equivalent to a snapshot of a single file.  
This _reduces_ but does not _eliminate_ this race condition, so you should still maintain multiple backups.

You can additionally perform a check of the backup by this command:

```shell
echo 'PRAGMA integrity_check;' | sqlite3 ${BACKUPFILE}
```

This will result in the string `ok` being printed if the backup is **likely** not corrupted.  
If the result is anything else than `ok`, the backup is definitely corrupted and you should make another copy.

In order to make a proper uncorrupted backup of the SQLITE3 file while `lightningd` is running, we would need to have `lightningd` perform the backup itself, which, as of the version at the time of this writing, is not yet implemented.

Even if the backup is not corrupted, take note that this backup strategy should still be a last resort; recovery of all funds is still not assured with this backup strategy.

`sqlite3` has `.dump` and `VACUUM INTO` commands, but note that those lock the main database for long time periods, which will negatively affect your `lightningd` instance.
