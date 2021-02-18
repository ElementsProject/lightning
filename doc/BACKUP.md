# Backing Up Your C-Lightning Node

Lightning Network channels get their scalability and privacy benefits
from the very simple technique of *not telling anyone else about your
in-channel activity*.
This is in contrast to onchain payments, where you have to tell everyone
about each and every payment and have it recorded on the blockchain,
leading to scaling problems (you have to push data to everyone, everyone
needs to validate every transaction) and privacy problems (everyone knows
every payment you were ever involved in).

Unfortunately, this removes a property that onchain users are so used
to, they react in surprise when learning about this removal.
Your onchain activity is recorded in all archival fullnodes, so if you
forget all your onchain activity because your storage got fried, you
just go redownload the activity from the nearest archival fullnode.

But in Lightning, since *you* are the only one storing all your
financial information, you ***cannot*** recover this financial
information from anywhere else.

This means that on Lightning, **you have to** responsibly back up your
financial information yourself, using various processes and automation.

The discussion below assumes that you know where you put your
`$LIGHTNINGDIR`, and you know the directory structure within.
By default your `$LIGHTNINGDIR` will be in `~/.lightning/${COIN}`.
For example, if you are running `--mainnet`, it will be
`~/.lightning/bitcoin`.

## `hsm_secret`

`/!\` WHO SHOULD DO THIS: Everyone.

You need a copy of the `hsm_secret` file regardless of whatever backup
strategy you use.

The `hsm_secret` is created when you first create the node, and does
not change.
Thus, a one-time backup of `hsm_secret` is sufficient.

This is just 32 bytes, and you can do something like the below and
write the hexadecimal digits a few times on a piece of paper:

    cd $LIGHTNINGDIR
    xxd hsm_secret

You can re-enter the hexdump into a text file later and use `xxd` to
convert it back to a binary `hsm_secret`:

    cat > hsm_secret_hex.txt <<HEX
    00: 30cc f221 94e1 7f01 cd54 d68c a1ba f124
    10: e1f3 1d45 d904 823c 77b7 1e18 fd93 1676
    HEX
    xxd -r hsm_secret_hex.txt > hsm_secret
    chmod 0400 hsm_secret

Notice that you need to ensure that the `hsm_secret` is only readable by
the user, and is not writable, as otherwise `lightningd` will refuse to
start.
Hence the `chmod 0400 hsm_secret` command.

Alternately, if you are deploying a new node that has no funds and
channels yet, you can generate BIP39 words using any process, and
create the `hsm_secret` using the `hsmtool generatehsm` command.
If you did `make install` then `hsmtool` is installed as
`lightning-hsmtool`, else you can find it in the `tools/` directory
of the build directory.

    lightning-hsmtool generatehsm hsm_secret

Then enter the BIP39 words, plus an optional passphrase.

You can regenerate the same `hsm_secret` file using the same BIP39
words, which again, you can back up on paper.

Recovery of the `hsm_secret` is sufficient to recover any onchain
funds.
Recovery of the `hsm_secret` is necessary, but insufficient, to recover
any in-channel funds.
To recover in-channel funds, you need to use one or more of the other
backup strategies below.

## `backup` Plugin And Remote NFS Mount

`/!\` WHO SHOULD DO THIS: Casual users.

You can get the `backup` plugin here:
https://github.com/lightningd/plugins/tree/master/backup

The `backup` plugin requires Python 3.

* `cd` into its directory and install requirements.
  * `pip3 install -r requirements.txt`
* Figure out where you will put the backup files.
  * Ideally you have an NFS or other network-based mount on your system,
    into which you will put the backup.
* Stop your Lightning node.
* `/path/to/backup-cli init ${LIGHTNINGDIR} file:///path/to/nfs/mount`.
  This creates an initial copy of the database at the NFS mount.
* Add these settings to your `lightningd` configuration:
  * `important-plugin=/path/to/backup.py`
* Restart your Lightning node.

It is recommended that you use a network-mounted filesystem for the backup
destination.
For example, if you have a NAS you can access remotely.

Do note that files are not stored encrypted, so you should really not do
this with rented space ("cloud storage").

Alternately, you *could* put it in another storage device (e.g. USB flash
disk) in the same physical location.

To recover:

* Re-download the `backup` plugin and install Python 3 and the
  requirements of `backup`.
* `/path/to/backup-cli restore file:///path/to/nfs/mount ${LIGHTNINGDIR}`

If your backup destination is a network-mounted filesystem that is in a
remote location, then even loss of all hardware in one location will allow
you to still recover your Lightning funds.

However, if instead you are just replicating the database on another
storage device in a single location, you remain vulnerable to disasters
like fire or computer confiscation.

## Filesystem Redundancy

`/!\` WHO SHOULD DO THIS: Filesystem nerds, data hoarders, home labs,
enterprise users.

You can set up a RAID-1 with multiple storage devices, and point the
`$LIGHTNINGDIR` to the RAID-1 setup.
That way, failure of one storage device will still let you recover
funds.

You can use a hardware RAID-1 setup, or just buy multiple commodity
storage media you can add to your machine and use a software RAID,
such as (not an exhaustive list!):

* `mdadm` to create a virtual volume which is the RAID combination
  of multiple physical media.
* BTRFS RAID-1 or RAID-10, a filesystem built into Linux.
* ZFS RAID-Z, a filesystem that cannot be legally distributed with the Linux
  kernel, but can be distributed in a BSD system, and can be installed 
  on Linux with some extra effort, see
  [ZFSonLinux](https://zfsonlinux.org).

RAID-1 (whether by hardware, or software) like the above protects against
failure of a single storage device, but does not protect you in case of
certain disasters, such as fire or computer confiscation.

You can "just" use a pair of high-quality metal-casing USB flash devices
(you need metal-casing since the devices will have a lot of small writes,
which will cause a lot of heating, which needs to dissipate very fast,
otherwise the flash device firmware will internally disconnect the flash
device from your computer, reducing your reliability) in RAID-1, if you
have enough USB ports.

### Example: BTRFS on Linux

On a Linux system, one of the simpler things you can do would be to use
BTRFS RAID-1 setup between a partition on your primary storage and a USB
flash disk.
The below "should" work, but assumes you are comfortable with low-level
Linux administration.
If you are on a system that would make you cry if you break it, you **MUST**
stop your Lightning node and back up all files before doing the below.

* Install `btrfs-progs` or `btrfs-tools` or equivalent.
* Get a 32Gb USB flash disk.
* Stop your Lightning node and back up everything, do not be stupid.
* Repartition your hard disk to have a 30Gb partition.
  * This is risky and may lose your data, so this is best done with a
    brand-new hard disk that contains no data.
* Connect the USB flash disk.
* Find the `/dev/sdXX` devices for the HDD 30Gb partition and the flash disk.
  * `lsblk -o NAME,TYPE,SIZE,MODEL` should help.
* Create a RAID-1 `btrfs` filesystem.
  * `mkfs.btrfs -m raid1 -d raid1 /dev/${HDD30GB} /dev/${USB32GB}`
  * You may need to add `-f` if the USB flash disk is already formatted.
* Create a mountpoint for the `btrfs` filesystem.
* Create a `/etc/fstab` entry.
  * Use the `UUID` option instad of `/dev/sdXX` since the exact device letter
    can change across boots.
  * You can get the UUID by `lsblk -o NAME,UUID`.
    Specifying *either* of the devices is sufficient.
  * Add `autodefrag` option, which tends to work better with SQLITE3
    databases.
  * e.g. `UUID=${UUID} ${BTRFSMOUNTPOINT} btrfs defaults,autodefrag 0 0`
* `mount -a` then `df` to confirm it got mounted.
* Copy the contents of the `$LIGHTNINGDIR` to the BTRFS mount point.
  * Copy the entire directory, then `chown -R` the copy to the user who will
    run the `lightningd`.
  * If you are paranoid, run `diff -R` on both copies to check.
* Remove the existing `$LIGHTNINGDIR`.
* `ln -s ${BTRFSMOUNTPOINT}/lightningdirname ${LIGHTNINGDIR}`.
  * Make sure the `$LIGHTNINGDIR` has the same structure as what you
    originally had.
* Add `crontab` entries for `root` that perform regular `btrfs` maintenance
  tasks.
  * `0 0 * * * /usr/bin/btrfs balance start -dusage=50 -dlimit=2 -musage=50 -mlimit=4 ${BTRFSMOUNTPOINT}`
    This prevents BTRFS from running out of blocks even if it has unused
    space *within* blocks, and is run at midnight everyday.
    You may need to change the path to the `btrfs` binary.
  * `0 0 * * 0 /usr/bin/btrfs scrub start -B -c 2 -n 4 ${BTRFSMOUNTPOINT}`
    This detects bit rot (i.e. bad sectors) and auto-heals the filesystem,
    and is run on Sundays at midnight.
* Restart your Lightning node.

If one or the other device fails completely, shut down your computer, boot
on a recovery disk or similar, then:

* Connect the surviving device.
* Mount the partition/USB flash disk in `degraded` mode:
  * `mount -o degraded /dev/sdXX /mnt/point`
* Copy the `lightningd.sqlite3` and `hsm_secret` to new media.
  * Do **not** write to the degraded `btrfs` mount!
* Start up a `lightningd` using the `hsm_secret` and `lightningd.sqlite3`
  and close all channels and move all funds to onchain cold storage you
  control, then set up a new Lightning node.

If the device that fails is the USB flash disk, you can replace it using
BTRFS commands.
You should probably stop your Lightning node while doing this.

* `btrfs replace start /dev/sdOLD /dev/sdNEW ${BTRFSMOUNTPOINT}`.
  * If `/dev/sdOLD` no longer even exists because the device is really
    really broken, use `btrfs filesystem show` to see the number after
    `devid` of the broken device, and use that number instead of
    `/dev/sdOLD`.
* Monitor status with `btrfs replace status ${BTRFSMOUNTPOINT}`.

More sophisticated setups with more than two devices are possible.
Take note that "RAID 1" in `btrfs` means "data is copied on up to two
devices", meaning only up to one device can fail.
You may be interested in `raid1c3` and `raid1c4` modes if you have
three or four storage devices.
BTRFS would probably work better if you were purchasing an entire set
of new storage devices to set up a new node.

## PostgreSQL Cluster

`/!\` WHO SHOULD DO THIS: Enterprise users, whales.

`lightningd` may also be compiled with PostgreSQL support.
PostgreSQL is generally faster than SQLITE3, and also supports running a
PostgreSQL cluster to be used by `lightningd`, with automatic replication
and failover in case an entire node of the PostgreSQL cluster fails.

Setting this up, however, is more involved.

By default, `lightningd` compiles with PostgreSQL support **only** if it
finds `libpq` installed when you `./configure`.
To enable it, you have to install a developer version of `libpq`.
On most Debian-derived systems that would be `libpq-dev`.
To verify you have it properly installed on your system, check if the
following command gives you a path:

    pg_config --includedir

Versioning may also matter to you.
For example, Debian Stable ("buster") as of late 2020 provides PostgreSQL 11.9
for the `libpq-dev` package, but Ubuntu LTS ("focal") of 2020 provides
PostgreSQL 12.5.
Debian Testing ("bullseye") uses PostgreSQL 13.0 as of this writing.
PostgreSQL 12 had a non-trivial change in the way the restore operation is
done for replication.
You should use the same PostgreSQL version of `libpq-dev` as what you run
on your cluster, which probably means running the same distribution on
your cluster.

Once you have decided on a specific version you will use throughout, refer
as well to the "synchronous replication" document of PostgreSQL for the
**specific version** you are using:

* [PostgreSQL 11](https://www.postgresql.org/docs/11/runtime-config-replication.html)
* [PostgreSQL 12](https://www.postgresql.org/docs/12/runtime-config-replication.html)
* [PostgreSQL 13](https://www.postgresql.org/docs/13/runtime-config-replication.html)

You then have to compile `lightningd` with PostgreSQL support.

* Clone or untar a new source tree for `lightning` and `cd` into it.
  * You *could* just use `make clean` on an existing one, but for the
    avoidance of doubt (and potential bugs in our `Makefile` cleanup rules),
    just create a fresh source tree.
* `./configure`
  * Add any options to `configure` that you normally use as well.
* Double-check the `config.vars` file contains `HAVE_POSTGRES=1`.
  * `grep 'HAVE_POSTGRES' config.vars`
* `make`
* If you install `lightningd`, `sudo make install`.

If you were not using PostgreSQL before but have compiled and used
`lightningd` on your system, the resulting `lightningd` will still
continue supporting and using your current SQLITE3 database;
it just gains the option to use a PostgreSQL database as well.

If you just want to use PostgreSQL without using a cluster (for
example, as an initial test without risking any significant funds),
then after setting up a PostgreSQL database, you just need to add
`--wallet=postgresql://${USER}:${PASSWORD}@${HOST}:${PORT}/${DB}`
to your `lightningd` config or invocation.

To set up a cluster for a brand new node, follow this (external)
[guide by @gabridome][gabridomeguide].

[gabridomeguide]: https://github.com/gabridome/docs/blob/master/c-lightning_with_postgresql_reliability.md

The above guide assumes you are setting up a new node from scratch.
It is also specific to PostgreSQL 12, and setting up for other versions
**will** have differences; read the PostgreSQL manuals linked above.

If you want to continue a node that started using an SQLITE3 database,
note that we do not support this.
You should set up a new PostgreSQL node, move funds from the SQLITE3
node to the PostgreSQL node, then shut down the SQLITE3 node
permanently.

There are also more ways to set up PostgreSQL replication.
In general, you should use [synchronous replication (13)][pqsyncreplication],
since `lightningd` assumes that once a transaction is committed, it is
saved in all permanent storage.
This can be difficult to create remote replicas due to the latency.

[pqsyncreplication]: https://www.postgresql.org/docs/13/warm-standby.html#SYNCHRONOUS-REPLICATION

## Database File Backups

`/!\` WHO SHOULD DO THIS: Those who already have at least one of the
other backup methods, those who are #reckless.

This is the least desirable backup strategy, as it *can* lead to loss
of all in-channel funds if you use it.
However, having *no* backup strategy at all *will* lead to loss of all
in-channel funds, so this is still better than nothing.

This backup method is undesirable, since it cannot recover the following
channels:

* Channels with peers that do not support `option_dataloss_protect`.
  * Most nodes on the network already support `option_dataloss_protect`
    as of November 2020.
  * If the peer does not support `option_dataloss_protect`, then the entire
    channel funds will be revoked by the peer.
  * Peers can *claim* to honestly support this, but later steal funds
    from you by giving obsolete state when you recover.
* Channels created *after* the copy was made are not recoverable.
  * Data for those channels does not exist in the backup, so your node
    cannot recover them.

Because of the above, this strategy is discouraged: you *can* potentially
lose all funds in open channels.

However, again, note that a "no backups #reckless" strategy leads to
*definite* loss of funds, so you should still prefer *this* strategy rather
than having *no* backups at all.

Even if you have one of the better options above, you might still want to do
this as a worst-case fallback, as long as you:

* Attempt to recover using the other backup options above first.
  Any one of them will be better than this backup option.
* Recover by this method **ONLY** as a ***last*** resort.
* Recover using the most recent backup you can find.
  Take time to look for the most recent available backup.

Again, this strategy can lead to only ***partial*** recovery of funds,
or even to complete failure to recover, so use the other methods first to
recover!

### Offline Backup

While `lightningd` is not running, just copy the `lightningd.sqlite3` file
in the `$LIGHTNINGDIR` on backup media somewhere.

To recover, just copy the backed up `lightningd.sqlite3` into your new
`$LIGHTNINGDIR` together with the `hsm_secret`.

You can also use any automated backup system as long as it includes the
`lightningd.sqlite3` file (and optionally `hsm_secret`, but note that
as a secret key, thieves getting a copy of your backups may allow them
to steal your funds, even in-channel funds) and as long as it copies the
file while `lightningd` is not running.

### Backing Up While `lightningd` Is Running

Since `sqlite3` will be writing to the file while `lightningd` is running,
`cp`ing the `lightningd.sqlite3` file while `lightningd` is running may
result in the file not being copied properly if `sqlite3` happens to be
committing database transactions at that time, potentially leading to a
corrupted backup file that cannot be recovered from.

You have to stop `lightningd` before copying the database to backup in
order to ensure that backup files are not corrupted, and in particular,
wait for the `lightningd` process to exit.
Obviously, this is disruptive to node operations, so you might prefer
to just perform the `cp` even if the backup potentially is corrupted.
As long as you maintain multiple backups sampled at different times,
this may be more acceptable than stopping and restarting `lightningd`;
the corruption only exists in the backup, not in the original file.

If the filesystem or volume manager containing `$LIGHTNINGDIR` has a
snapshot facility, you can take a snapshot of the filesystem, then
mount the snapshot, copy `lightningd.sqlite3`, unmount the snapshot,
and then delete the snapshot.
Similarly, if the filesystem supports a "reflink" feature, such as
`cp -c` on an APFS on MacOS, or `cp --reflink=always` on an XFS or
BTRFS on Linux, you can also use that, then copy the reflinked copy
to a different storage medium; this is equivalent to a snapshot of
a single file.
This *reduces* but does not *eliminate* this race condition, so you
should still maintain multiple backups.

You can additionally perform a check of the backup by this command:

    echo 'PRAGMA integrity_check;' | sqlite3 ${BACKUPFILE}

This will result in the string `ok` being printed if the backup is
**likely** not corrupted.
If the result is anything else than `ok`, the backup is definitely
corrupted and you should make another copy.

In order to make a proper uncorrupted backup of the SQLITE3 file
while `lightningd` is running, we would need to have `lightningd`
perform the backup itself, which, as of the version at the time of
this writing, is not yet implemented.

Even if the backup is not corrupted, take note that this backup
strategy should still be a last resort; recovery of all funds is
still not assured with this backup strategy.

You might be tempted to use `sqlite3` `.dump` or `VACUUM INTO`.
Unfortunately, these commands exclusive-lock the database.
A race condition between your `.dump` or `VACUUM INTO` and
`lightningd` accessing the database can cause `lightningd` to
crash, so you might as well just cleanly shut down `lightningd`
and copy the file at rest.
