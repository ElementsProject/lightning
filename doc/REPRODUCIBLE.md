# Rusty's Unreliable Guide to The Terrible World of Reproducible Builds

1. The reproducible build system currently only supports Ubuntu 18.04.1.
2. It requires manual steps.
3. The input is a source zipfile, the output is a .tar.xz.

## Step 1: Creating a Build Machine

Download the Ubuntu Desktop ISO image for 18.04.1.  I got it from
http://old-releases.ubuntu.com/releases/18.04.1/ubuntu-18.04.1-desktop-amd64.iso

The `sha256sum` of this file should be
`5748706937539418ee5707bd538c4f5eabae485d17aa49fb13ce2c9b70532433`.

Do a standard install, but make sure to *uncheck* 'Download updates
while installing Ubuntu' in the installer (or simply deprive it of a
network connection as I do below).  I did the following to install under kvm:

	qemu-img create ubuntu-18.04.01.raw 10G
	kvm -m 2G -cdrom ~/Downloads/ubuntu-18.04.1-desktop-amd64.iso ubuntu-18.04.01.raw -nic none

You can choose a 'Minimal installation': it shouldn't matter.

Once the installation is over, it'll want to restart.  Then make sure you
disable updates:

1. Left-click on the bottom left 9-dots menu
2. Type "update"
3. Click on the "Software & Up.." box icon.
4. Click on the "Updates" tab at the top of that app.
5. Uncheck "Important security updates", "Recommended updates" and
   "Unsupported updates".  You'll have to re-enter your password.
6. Hit "Close".
7. If asked, hit "Reload".

If you didn't have a network connection, you'll want to add one for
the next steps; for me, this meant powering off the build machine and restarting:

	kvm -m 2G ubuntu-18.04.01.raw -nic user

And then ran `sudo apt-get update` after I'd logged in.

## Step 2: Create the Source Zipfile

Create the source zip that the Build Machine will need, using

	./tools/build-release.sh zipfile

For testing (ie. when you're not on a proper released version), you
can use --force-version=, --force-mtime= and even --force-unclean.

The will place a file into `release/`, eg. `clightning-v0.7.0rc2.zip`.

### Example

If you are on the git commit v0.7.0rc2 (1dcc4823507df177bf11ca60ab7da988205139b1):
```
$ sha256sum release/clightning-v0.7.0rc2.zip 
3c980858024b8b429333e7ee5a545c499ac6c25d0f1d11bb45fafce00c99ebba  release/clightning-v0.7.0rc2.zip
```

## Step 3: Put the Zipfile Onto The Build Machine

You can upload it somewhere and download it into the machine, or
various virtualization solutions or a USB stick for a physical machine.

I simply started a server on my host, like so:

	cd release && python3 -m http.server --bind 127.0.0.1 8888

Inside my KVM build machine I did:

	wget http://10.0.2.2:8888/clightning-v0.7.0rc2.zip


## Step 4: Do the Build

1. `unzip clightning-v0.7.0rc2.zip`
2. `cd clightning-v0.7.0rc2`
3. `tools/repro-build.sh` (use the same `--force-mtime` if testing).
   It will download the packages needed to build, check they're identitcal to the
   versions we expect, install them then build the binaries and create a tar.xz file.
4. The output will be in that top-level directory.

### Example:

If you built from our example zipfile:
```
$ sha256sum clightning-v0.7.0rc2-Ubuntu-18.04.tar.xz
c9b4d9530b9b41456f460c58e3ffaa779cdc1c11fb9e3eaeea0f364b62de3d96  clightning-v0.7.0rc2-Ubuntu-18.04.tar.xz
```


## Step 5: Get the Built Result Off the Build Machine

Again, there are many ways, but for my KVM settings the simplest was:

On the host:

	nc -l -p 8888 > clightning-v0.7.0rc2-Ubuntu-18.04.tar.xz

On the guest:

    nc -q0 10.0.2.2 8888 < clightning-v0.7.0rc2-Ubuntu-18.04.tar.xz 


## Step 5: Tell the World

You can find my example artifacts on https://ozlabs.org/~rusty/clightning-repro
if you want to see why your build produced a different result from mine.

Happy hacking!
Rusty.
