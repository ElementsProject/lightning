from abc import ABC
from typing import Optional
from msggen import model


class Patch(ABC):
    """A patch that can be applied to an in-memory model

    This effectively post-processes the in-memory model to ensure the
    invariants are satisfied.

    """

    def visit(self, field: model.Field, parent: Optional[model.Field] = None) -> None:
        """Gets called for each node in the model."""
        pass

    def apply(self, service: model.Service) -> None:
        """Apply this patch to the model by calling `visit` in
        pre-order on each node in the schema tree.

        """

        def recurse(f: model.Field):
            # First recurse if we have further type definitions
            self.visit(f)

            if isinstance(f, model.ArrayField):
                self.visit(f.itemtype, f)
                recurse(f.itemtype)
            elif isinstance(f, model.CompositeField):
                for c in f.fields:
                    self.visit(c, f)
                    recurse(c)
            # Now visit ourselves

        for m in service.methods:
            recurse(m.request)
            recurse(m.response)
        for n in service.notifications:
            recurse(n.request)
            recurse(n.response)


class VersionAnnotationPatch(Patch):
    """Annotates fields with the version they were added or deprecated if not specified.

    A patch is used so we don't have to annotate all fields that
    existed prior to the introduction of the `added` and `deprecated`
    fields, and uses the `.msggen.json` file to remember which fields
    are known, and which ones are new. For existing fields we just
    want a default value, while for new fields we want to error if the
    author did not annotate them manually.

    """

    def __init__(self, meta) -> None:
        """Create a patch that can annotate `added` and `deprecated`"""
        self.meta = meta

    def visit(self, f: model.Field, parent: Optional[model.Field] = None) -> None:
        m = self.meta["model-field-versions"].get(f.path, {})

        # The following lines are used to backfill fields that predate
        # the introduction, so they need to use a default version to
        # mark. These are stored in `.msggen.json` only, and we use
        # the default value only on the first run. Code left commented
        # to show how it was done
        # if f.added is None and 'added' not in m:
        #    m['added'] = 'pre-v0.10.1'

        added = m.get("added", None)
        deprecated = m.get("deprecated", None)

        assert added or f.added, f"Field {f.path} does not have an `added` annotation"

        # We do not allow the added and deprecated flags to be
        # modified after the fact.
        if f.added and added and f.added != m["added"]:
            raise ValueError(
                f"Field {f.path} changed `added` annotation: {f.added} != {m['added']}"
            )

        if f.deprecated:
            # We don't care about finishing value.
            if isinstance(f.deprecated, list):
                assert len(f.deprecated) == 2
                f.deprecated = f.deprecated[0]
            # We may have already deprecated some things before backfilling them
            if f.deprecated is not None and deprecated is None:
                deprecated = f.deprecated
            if f.deprecated != deprecated:
                raise ValueError(
                    f"Field {f.path} changed `deprecated` annotation: {f.deprecated} vs {deprecated}"
                )

        if f.added is None:
            f.added = added
        if f.deprecated is None:
            f.deprecated = deprecated

        # Backfill the metadata using the annotation
        self.meta["model-field-versions"][f.path] = {
            "added": f.added,
            "deprecated": f.deprecated,
        }


class OptionalPatch(Patch):
    """Annotates fields with `.optional`

    Optional fields are either non-required fields, or fields that
    were not required in prior versions. This latter case covers the
    deprecation and addition for schema evolution
    """

    @staticmethod
    def version_to_number(version):
        # Dummy versions collecting all fields that predate the versioning.
        if version == "pre-v0.10.1":
            return 0
        assert version[0] == "v"
        parts = version[1:].split(".")

        # Months, plus 10 for minor versions.
        num = (int(parts[0]) * 12 + int(parts[1])) * 10
        if len(parts) == 3:
            num += int(parts[2])
        return num

    @staticmethod
    def supported():
        """Oldest supported version. Bump this if you no longer want
        to support older versions, and you want to make required
        fields more stringent.
        """

        return OptionalPatch.version_to_number("v0.10.1")

    def visit(self, f: model.Field, parent: Optional[model.Field] = None) -> None:
        # Return if the optional field has been set already
        if "optional" in dir(f):
            if f.optional is not None:
                return

        # Default to false, and then overwrite it if required.
        f.optional = False
        if not f.required:
            f.optional = True

        # Even if it's deprecated in future, reduce churn.
        if f.deprecated:
            f.optional = True

        # Set to optional if support has been added recently
        # This ensures generated code will run both on
        # newer and older versions of core lightning
        #
        # There is an exception though. If the entire struct
        # has been added we dont' treat subfields as optional
        if parent is not None:
            if parent.added == f.added:
                return

        added = self.version_to_number(f.added)
        if added >= self.supported():
            f.optional = True


class OverridePatch(Patch):
    """Allows omitting some fields and overriding the type of fields based on configuration."""

    omit = [
        "Decode.invoice_paths[]",
        "Decode.invoice_paths[].payinfo",
        "Decode.offer_paths[].path[]",
        "Decode.offer_recurrence",
        "Decode.unknown_invoice_request_tlvs[]",
        "Decode.unknown_invoice_tlvs[]",
        "Decode.unknown_offer_tlvs[]",
        "ListClosedChannels.closedchannels[].channel_type",
        "ListPeerChannels.channels[].channel_type",
        "ListPeerChannels.channels[].features[]",
        "ListPeerChannels.channels[].state_changes[]",
        "ListPeers.peers[].channels[].state_changes[]",
        "ListTransactions.transactions[].type[]",
    ]

    # Handcoded types to use instead of generating the types from the
    # schema. Useful for repeated types, and types that have
    # redundancies.
    overrides = {
        "ListClosedChannels.closedchannels[].closer": "ChannelSide",
        "ListClosedChannels.closedchannels[].opener": "ChannelSide",
        "ListFunds.channels[].state": "ChannelState",
        "ListPeerChannels.channels[].closer": "ChannelSide",
        "ListPeerChannels.channels[].opener": "ChannelSide",
        "ListPeers.peers[].channels[].closer": "ChannelSide",
        "ListPeers.peers[].channels[].features[]": "string",
        "ListPeers.peers[].channels[].opener": "ChannelSide",
        "ListPeers.peers[].channels[].state_changes[].cause": "ChannelStateChangeCause",
        "ListPeers.peers[].channels[].state_changes[].old_state": "ChannelState",
        "ListPeers.peers[].channels[].htlcs[].state": "HtlcState",
        "ListPeerChannels.channels[].htlcs[].state": "HtlcState",
        "ListHtlcs.htlcs[].state": "HtlcState",
        "FundChannel.channel_type.names[]": "ChannelTypeName",
        "FundChannel_Start.channel_type.names[]": "ChannelTypeName",
        "MultiFundChannel.channel_ids[].channel_type.names[]": "ChannelTypeName",
        "OpenChannel_Init.channel_type.names[]": "ChannelTypeName",
        "OpenChannel_Bump.channel_type.names[]": "ChannelTypeName",
        "OpenChannel_Update.channel_type.names[]": "ChannelTypeName",
        "AutoClean-Once.subsystem": "AutocleanSubsystem",
        "AutoClean-Status.subsystem": "AutocleanSubsystem",
        "Plugin.subcommand": "PluginSubcommand",
        "Plugin.command": "PluginSubcommand",
    }

    def visit(self, f: model.Field, parent: Optional[model.Field] = None) -> None:
        """For now just skips the fields we can't convert."""
        f.omitted = f.path in self.omit
        f.type_override = self.overrides.get(f.path, None)
