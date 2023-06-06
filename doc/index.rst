Core Lightning Documentation
============================

.. toctree::
   :maxdepth: 1
   :caption: User Documentation

   INSTALL.md
   TOR.md
   FAQ <FAQ.md>
   Backups <BACKUP.md>

.. toctree::
   :maxdepth: 2
   :caption: Integrator Documentation

   Writing plugins <PLUGINS.md>

.. toctree::
   :maxdepth: 1
   :caption: Developer Documentation

   HACKING.md
   Coding Style Guideline <STYLE.md>
   MAKING-RELEASES.md
   CHANGELOG.md

.. toctree::
   :maxdepth: 1
   :caption: Manpages

 .. block_start manpages
   lightning-addgossip <lightning-addgossip.7.md>
   lightning-autoclean-once <lightning-autoclean-once.7.md>
   lightning-autoclean-status <lightning-autoclean-status.7.md>
   lightning-batching <lightning-batching.7.md>
   lightning-bkpr-channelsapy <lightning-bkpr-channelsapy.7.md>
   lightning-bkpr-dumpincomecsv <lightning-bkpr-dumpincomecsv.7.md>
   lightning-bkpr-inspect <lightning-bkpr-inspect.7.md>
   lightning-bkpr-listaccountevents <lightning-bkpr-listaccountevents.7.md>
   lightning-bkpr-listbalances <lightning-bkpr-listbalances.7.md>
   lightning-bkpr-listincome <lightning-bkpr-listincome.7.md>
   lightning-check <lightning-check.7.md>
   lightning-checkmessage <lightning-checkmessage.7.md>
   lightning-cli <lightning-cli.1.md>
   lightning-close <lightning-close.7.md>
   lightning-commando-blacklist <lightning-commando-blacklist.7.md>
   lightning-commando-listrunes <lightning-commando-listrunes.7.md>
   lightning-commando-rune <lightning-commando-rune.7.md>
   lightning-commando <lightning-commando.7.md>
   lightning-connect <lightning-connect.7.md>
   lightning-createinvoice <lightning-createinvoice.7.md>
   lightning-createonion <lightning-createonion.7.md>
   lightning-datastore <lightning-datastore.7.md>
   lightning-decode <lightning-decode.7.md>
   lightning-decodepay <lightning-decodepay.7.md>
   lightning-deldatastore <lightning-deldatastore.7.md>
   lightning-delexpiredinvoice <lightning-delexpiredinvoice.7.md>
   lightning-delforward <lightning-delforward.7.md>
   lightning-delinvoice <lightning-delinvoice.7.md>
   lightning-delpay <lightning-delpay.7.md>
   lightning-disableinvoicerequest <lightning-disableinvoicerequest.7.md>
   lightning-disableoffer <lightning-disableoffer.7.md>
   lightning-disconnect <lightning-disconnect.7.md>
   lightning-emergencyrecover <lightning-emergencyrecover.7.md>
   lightning-feerates <lightning-feerates.7.md>
   lightning-fetchinvoice <lightning-fetchinvoice.7.md>
   lightning-fundchannel <lightning-fundchannel.7.md>
   lightning-fundchannel_cancel <lightning-fundchannel_cancel.7.md>
   lightning-fundchannel_complete <lightning-fundchannel_complete.7.md>
   lightning-fundchannel_start <lightning-fundchannel_start.7.md>
   lightning-funderupdate <lightning-funderupdate.7.md>
   lightning-fundpsbt <lightning-fundpsbt.7.md>
   lightning-getinfo <lightning-getinfo.7.md>
   lightning-getlog <lightning-getlog.7.md>
   lightning-getroute <lightning-getroute.7.md>
   lightning-help <lightning-help.7.md>
   lightning-hsmtool <lightning-hsmtool.8.md>
   lightning-invoice <lightning-invoice.7.md>
   lightning-invoicerequest <lightning-invoicerequest.7.md>
   lightning-keysend <lightning-keysend.7.md>
   lightning-listchannels <lightning-listchannels.7.md>
   lightning-listclosedchannels <lightning-listclosedchannels.7.md>
   lightning-listconfigs <lightning-listconfigs.7.md>
   lightning-listdatastore <lightning-listdatastore.7.md>
   lightning-listforwards <lightning-listforwards.7.md>
   lightning-listfunds <lightning-listfunds.7.md>
   lightning-listhtlcs <lightning-listhtlcs.7.md>
   lightning-listinvoicerequests <lightning-listinvoicerequests.7.md>
   lightning-listinvoices <lightning-listinvoices.7.md>
   lightning-listnodes <lightning-listnodes.7.md>
   lightning-listoffers <lightning-listoffers.7.md>
   lightning-listpays <lightning-listpays.7.md>
   lightning-listpeerchannels <lightning-listpeerchannels.7.md>
   lightning-listpeers <lightning-listpeers.7.md>
   lightning-listsendpays <lightning-listsendpays.7.md>
   lightning-listsqlschemas <lightning-listsqlschemas.7.md>
   lightning-listtransactions <lightning-listtransactions.7.md>
   lightning-makesecret <lightning-makesecret.7.md>
   lightning-multifundchannel <lightning-multifundchannel.7.md>
   lightning-multiwithdraw <lightning-multiwithdraw.7.md>
   lightning-newaddr <lightning-newaddr.7.md>
   lightning-notifications <lightning-notifications.7.md>
   lightning-offer <lightning-offer.7.md>
   lightning-openchannel_abort <lightning-openchannel_abort.7.md>
   lightning-openchannel_bump <lightning-openchannel_bump.7.md>
   lightning-openchannel_init <lightning-openchannel_init.7.md>
   lightning-openchannel_signed <lightning-openchannel_signed.7.md>
   lightning-openchannel_update <lightning-openchannel_update.7.md>
   lightning-parsefeerate <lightning-parsefeerate.7.md>
   lightning-pay <lightning-pay.7.md>
   lightning-ping <lightning-ping.7.md>
   lightning-plugin <lightning-plugin.7.md>
   lightning-preapproveinvoice <lightning-preapproveinvoice.7.md>
   lightning-preapprovekeysend <lightning-preapprovekeysend.7.md>
   lightning-recoverchannel <lightning-recoverchannel.7.md>
   lightning-reserveinputs <lightning-reserveinputs.7.md>
   lightning-sendcustommsg <lightning-sendcustommsg.7.md>
   lightning-sendinvoice <lightning-sendinvoice.7.md>
   lightning-sendonion <lightning-sendonion.7.md>
   lightning-sendonionmessage <lightning-sendonionmessage.7.md>
   lightning-sendpay <lightning-sendpay.7.md>
   lightning-sendpsbt <lightning-sendpsbt.7.md>
   lightning-setchannel <lightning-setchannel.7.md>
   lightning-setconfig <lightning-setconfig.7.md>
   lightning-setpsbtversion <lightning-setpsbtversion.7.md>
   lightning-signinvoice <lightning-signinvoice.7.md>
   lightning-signmessage <lightning-signmessage.7.md>
   lightning-signpsbt <lightning-signpsbt.7.md>
   lightning-sql <lightning-sql.7.md>
   lightning-staticbackup <lightning-staticbackup.7.md>
   lightning-stop <lightning-stop.7.md>
   lightning-txdiscard <lightning-txdiscard.7.md>
   lightning-txprepare <lightning-txprepare.7.md>
   lightning-txsend <lightning-txsend.7.md>
   lightning-unreserveinputs <lightning-unreserveinputs.7.md>
   lightning-upgradewallet <lightning-upgradewallet.7.md>
   lightning-utxopsbt <lightning-utxopsbt.7.md>
   lightning-waitanyinvoice <lightning-waitanyinvoice.7.md>
   lightning-waitblockheight <lightning-waitblockheight.7.md>
   lightning-waitinvoice <lightning-waitinvoice.7.md>
   lightning-waitsendpay <lightning-waitsendpay.7.md>
   lightning-withdraw <lightning-withdraw.7.md>
   lightningd-config <lightningd-config.5.md>
   lightningd-rpc <lightningd-rpc.7.md>
   lightningd <lightningd.8.md>
   reckless <reckless.7.md>
.. block_end manpages
