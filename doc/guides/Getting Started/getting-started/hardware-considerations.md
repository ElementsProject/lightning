---
title: "Hardware considerations"
slug: "hardware-considerations"
excerpt: "A lightning node requires reasonable amount of memory and storage. Learn what's suitable for your scenario."
hidden: true
createdAt: "2022-11-18T14:31:38.695Z"
updatedAt: "2023-04-01T00:09:20.148Z"
---
# Hobbyist

Off-the-shelf consumer computers

Single Board Computers

Raspberry Pi (thinking we should recommend against here)

For home users, laptops are the most suitable devices for running a Lightning node. This is because they include a built-in battery that can power your node in case of a power outage that otherwise could result in data corruption. Compared to desktop machines, laptops are more energy-efficient and quiet. In practically all cases, they have higher performance than SBCs like Raspberry Pis or Rock64s, and can even be cheaper to purchase. 

# Power User

More advanced users, with more demanding use cases, will need a platform better suited for their CLN nodes. We suggest the following hardware and software options to ensure high uptime and data resiliency. At a minimum, the node should have ECC memory and a storage mirror (typically RAID-1).

**ECC memory**

ECC memory protects your data from corruption due to bit flips and hardware errors. When working with sensitive Lightning related data, it's important to make sure there is no data corruption occurring, and ECC memory detects and corrects errors that happen in RAM.

**Solid State Drives**

SSDs are generally more reliable than their HDD counterparts since there are no moving parts that can degrade over time. SSDs have much better random IO performance than HDDs, consume less power, and are relatively cheap. 

**Storage mirroring **

Mirroring protects your node from a storage hardware failure that could potentially cause data loss and fund loss. Data is written simultaneously to two or more independent devices (ideally SSDs) so that if a device fails, there is an operational device with your data. 

**Checksumming filesystem**

A checksumming filesystem, such as BTRFS or ZFS, compliments ECC memory by computing a cryptographic hash of your data before writing both the checksum and data to storage. This allows your node to verify the checksum while reading your data and correct corruption at the storage hardware level. 

**Offsite replication**

Despite the data resiliency assurances we gain using ECC memory, storage mirroring, and filesystem-level checksumming, a Lightning node is still subject to other events such as fires or floods that could compromise the integrity of the node's data. Because of this, it's important to have offsite 

# Commercial Grade(?)