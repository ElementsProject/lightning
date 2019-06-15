#!/usr/bin/env python3
"""This plugin is used to check that forward_event calls are working correctly.
"""
from lightning import Plugin

plugin = Plugin()


def check(forward, dbforward):
    # After finding the corresponding notification record, this function will
    # make some changes on mutative fields of this record to make this record
    # same as the ideal format with given status.
    record = forward
    if record['status'] == 'offered':
        if dbforward['status'] == 'local_failed':
            record['failcode'] = dbforward['failcode']
            record['failreason'] = dbforward['failreason']
        elif dbforward['status'] != 'offered':
            record['resolved_time'] = dbforward['resolved_time']
    record['status'] = dbforward['status']
    if record == dbforward:
        return True
    else:
        return False


@plugin.init()
def init(configuration, options, plugin):
    plugin.forward_list = []


@plugin.subscribe("forward_event")
def notify_warning(plugin, forward_event):
    # One forward payment may have many notification records for different status,
    # but one forward payment has only one record in 'listforwards' eventrually.
    plugin.log("receive a forward recored, status: {}, payment_hash: {}".format(forward_event['status'], forward_event['payment_hash']))
    plugin.forward_list.append(forward_event)


@plugin.method('recordcheck')
def record_lookup(payment_hash, status, dbforward, plugin):
    # Check if we received all notifications when forward changed.
    # This check is based on the records of 'listforwards'
    plugin.log("recordcheck: payment_hash: {}, status: {}".format(payment_hash, status))
    for forward in plugin.forward_list:
        if forward['payment_hash'] == payment_hash and forward['status'] == status:
            plugin.log("record exists")
            check_result = check(forward, dbforward)
            return check_result
    plugin.log("no record")
    return False


plugin.run()
