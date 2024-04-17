"""A drop-in replacement for the JSON-RPC LightningRpc
"""

import logging
from binascii import unhexlify
from typing import List, Optional, Tuple

import grpc
from pyln.testing import grpc2py

from pyln import grpc as clnpb

DUMMY_CA_PEM = b"""-----BEGIN CERTIFICATE-----
MIIBcTCCARigAwIBAgIJAJhah1bqO05cMAoGCCqGSM49BAMCMBYxFDASBgNVBAMM
C2NsbiBSb290IENBMCAXDTc1MDEwMTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAW
MRQwEgYDVQQDDAtjbG4gUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BPF4JrGsOsksgsYM1NNdUdLESwOxkzyD75Rnj/g7sFEVYXewcmyB3MRGCBx2a3/7
ft2Xu2ED6WigajaHlnSvfUyjTTBLMBkGA1UdEQQSMBCCA2NsboIJbG9jYWxob3N0
MB0GA1UdDgQWBBRcTjvqVodamGirO6sX1rOR02LwXzAPBgNVHRMBAf8EBTADAQH/
MAoGCCqGSM49BAMCA0cAMEQCICDvV5iFw/nmJdl6rlEEGAdBdZqjxD0tV6U/FvuL
7PycAiASEMtsFtpfiUvxveBkOGt7AN32GP/Z75l+GhYXh7L1ig==
-----END CERTIFICATE-----"""


DUMMY_CA_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqbU7LQsRcvmI5vE5
MBBNK3imhIU2jmAczgvLuBi/Ys+hRANCAATxeCaxrDrJLILGDNTTXVHSxEsDsZM8
g++UZ4/4O7BRFWF3sHJsgdzERggcdmt/+37dl7thA+looGo2h5Z0r31M
-----END PRIVATE KEY-----"""


DUMMY_CLIENT_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIEdQyKso8PaD1kiz
xxFEcKiTvTg+bej4Nc/GqnXipcGhRANCAARGoUNSnWx1qgt4RiVG8tOMX1vpKvhr
OLcUJ92T++kIFZchZvcTXwnlNiTAQg3ukL+RYyG5Q1PaYrYRVlOtl1T0
-----END PRIVATE KEY-----"""


DUMMY_CLIENT_PEM = b"""-----BEGIN CERTIFICATE-----
MIIBRDCB7KADAgECAgkA8SsXq7IZfi8wCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwL
Y2xuIFJvb3QgQ0EwIBcNNzUwMTAxMDAwMDAwWhgPNDA5NjAxMDEwMDAwMDBaMBox
GDAWBgNVBAMMD2NsbiBncnBjIFNlcnZlcjBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABEahQ1KdbHWqC3hGJUby04xfW+kq+Gs4txQn3ZP76QgVlyFm9xNfCeU2JMBC
De6Qv5FjIblDU9pithFWU62XVPSjHTAbMBkGA1UdEQQSMBCCA2NsboIJbG9jYWxo
b3N0MAoGCCqGSM49BAMCA0cAMEQCICTU/YAs35cb6DRdZNzO1YbEt77uEjcqMRca
Hh6kK99RAiAKOQOkGnoAICjBmBJeC/iC4/+hhhkWZtFgbC3Jg5JD0w==
-----END CERTIFICATE-----"""


def int2msat(amount: int) -> clnpb.Amount:
    return clnpb.Amount(msat=amount)


def int2amount_or_all(amount: Tuple[int, str]) -> clnpb.AmountOrAll:
    if amount == "all":
        return clnpb.AmountOrAll(all=True)
    else:
        assert isinstance(amount, int)
        return clnpb.AmountOrAll(amount=int2msat(amount))


def int2amount_or_any(amount: Tuple[int, str]) -> clnpb.AmountOrAny:
    if amount == "any":
        return clnpb.AmountOrAny(any=True)
    else:
        assert isinstance(amount, int)
        return clnpb.AmountOrAny(amount=int2msat(amount))


class LightningGrpc(object):
    def __init__(
        self,
        host: str,
        port: int,
        root_certificates: bytes = DUMMY_CA_PEM,
        private_key: bytes = DUMMY_CLIENT_KEY_PEM,
        certificate_chain: bytes = DUMMY_CLIENT_PEM,
    ):
        self.logger = logging.getLogger("LightningGrpc")
        self.credentials = grpc.ssl_channel_credentials(
            root_certificates=root_certificates,
            private_key=private_key,
            certificate_chain=certificate_chain,
        )
        self.logger.debug(f"Connecting to grpc interface at {host}:{port}")
        self.channel = grpc.secure_channel(
            f"{host}:{port}",
            self.credentials,
            options=(("grpc.ssl_target_name_override", "cln"),),
        )
        self.stub = clnpb.NodeStub(self.channel)

    def getinfo(self):
        return grpc2py.getinfo2py(self.stub.Getinfo(clnpb.GetinfoRequest()))

    def connect(self, peer_id, host=None, port=None):
        """
        Connect to {peer_id} at {host} and {port}.
        """
        payload = clnpb.ConnectRequest(id=peer_id, host=host, port=port)
        return grpc2py.connect2py(self.stub.ConnectPeer(payload))

    def listpeers(self, peerid=None, level=None):
        payload = clnpb.ListpeersRequest(
            id=unhexlify(peerid) if peerid is not None else None,
            level=level,
        )
        return grpc2py.listpeers2py(self.stub.ListPeers(payload))

    def getpeer(self, peer_id, level=None):
        """
        Show peer with {peer_id}, if {level} is set, include {log}s.
        """
        res = self.listpeers(peer_id, level)
        return res.get("peers") and res["peers"][0] or None

    def newaddr(self, addresstype=None):
        """Get a new address of type {addresstype} of the internal wallet."""
        enum = {
            None: 0,
            "BECH32": 0,
            "P2TR": 3,
            "ALL": 2
        }
        if addresstype is not None:
            addresstype = addresstype.upper()
        atype = enum.get(addresstype, None)
        if atype is None:
            raise ValueError(
                f"Unknown addresstype {addresstype}, known values are {enum.values()}"
            )

        payload = clnpb.NewaddrRequest(addresstype=atype)
        res = grpc2py.newaddr2py(self.stub.NewAddr(payload))

        # Need to remap the bloody spelling of p2sh-segwit to match
        # addresstype.
        if 'p2sh_segwit' in res:
            res['p2sh-segwit'] = res['p2sh_segwit']
            del res['p2sh_segwit']
        return res

    def listfunds(self, spent=None):
        payload = clnpb.ListfundsRequest(spent=spent)
        return grpc2py.listfunds2py(self.stub.ListFunds(payload))

    def fundchannel(
        self,
        node_id: str,
        amount: int,
        # TODO map the following arguments
        # feerate=None,
        announce: Optional[bool] = True,
        minconf: Optional[int] = None,
        # utxos=None,
        # push_msat=None,
        close_to: Optional[str] = None,
        # request_amt=None,
        compact_lease: Optional[str] = None,
    ):
        payload = clnpb.FundchannelRequest(
            id=unhexlify(node_id),
            amount=int2amount_or_all(amount * 1000),  # This is satoshis after all
            # TODO Parse and insert `feerate`
            announce=announce,
            utxos=None,
            minconf=minconf,
            close_to=close_to,
            compact_lease=compact_lease,
        )
        return grpc2py.fundchannel2py(self.stub.FundChannel(payload))

    def listchannels(self, short_channel_id=None, source=None, destination=None):
        payload = clnpb.ListchannelsRequest(
            short_channel_id=short_channel_id,
            source=unhexlify(source) if source else None,
            destination=unhexlify(destination) if destination else None,
        )
        return grpc2py.listchannels2py(self.stub.ListChannels(payload))

    def pay(
        self,
        bolt11: str,
        amount_msat: Optional[int] = None,
        label: Optional[str] = None,
        riskfactor: Optional[float] = None,
        maxfeepercent: Optional[float] = None,
        retry_for: Optional[int] = None,
        maxdelay: Optional[int] = None,
        exemptfee: Optional[int] = None,
        localofferid: Optional[str] = None,
        # TODO map the following arguments
        # exclude: Optional[List[str]] = None,
        # maxfee=None,
        description: Optional[str] = None,
        msatoshi: Optional[int] = None,
    ):
        payload = clnpb.PayRequest(
            bolt11=bolt11,
            amount_msat=int2msat(amount_msat),
            label=label,
            riskfactor=riskfactor,
            maxfeepercent=maxfeepercent,
            retry_for=retry_for,
            maxdelay=maxdelay,
            exemptfee=exemptfee,
            localofferid=localofferid,
            # Needs conversion
            # exclude=exclude,
            # maxfee=maxfee
            description=description,
        )
        return grpc2py.pay2py(self.stub.Pay(payload))

    def invoice(
            self,
            amount_msat: Optional[int] = None,
            label: str = None,
            description: str = None,
            expiry: Optional[int] = None,
            fallbacks: Optional[List[str]] = None,
            preimage: Optional[str] = None,
            exposeprivatechannels: Optional[bool] = None,
            cltv: Optional[int] = None,
            deschashonly: Optional[bool] = None,
            # msatoshi=None
    ):
        payload = clnpb.InvoiceRequest(
            amount_msat=int2amount_or_any(amount_msat),
            label=label,
            description=description,
            expiry=expiry,
            fallbacks=fallbacks,
            preimage=unhexlify(preimage) if preimage else None,
            exposeprivatechannels=exposeprivatechannels,
            cltv=cltv,
            deschashonly=deschashonly,
        )
        return grpc2py.invoice2py(self.stub.Invoice(payload))

    def stop(self):
        payload = clnpb.StopRequest()
        try:
            self.stub.Stop(payload)
        except Exception:
            pass

    def listnodes(self, node_id=None):
        payload = clnpb.ListnodesRequest(id=unhexlify(node_id) if node_id else None)
        return grpc2py.listnodes2py(self.stub.ListNodes(payload))

    def close(
            self,
            peer_id: str,
            unilateraltimeout: Optional[int] = None,
            destination: Optional[str] = None,
            fee_negotiation_step: Optional[str] = None,
            force_lease_closed: Optional[bool] = None,
            # TODO: not mapped yet
            # feerange: Optional[List[str]]=None
    ):
        payload = clnpb.CloseRequest(
            id=peer_id,
            unilateraltimeout=unilateraltimeout,
            destination=destination,
            fee_negotiation_step=fee_negotiation_step,
            # wrong_funding,
            force_lease_closed=force_lease_closed,
            # feerange,
        )
        return grpc2py.close2py(self.stub.Close(payload))

    def listinvoices(
            self,
            label=None,
            payment_hash=None,
            invstring=None,
            offer_id=None
    ):
        payload = clnpb.ListinvoicesRequest(
            label=label,
            invstring=invstring,
            payment_hash=unhexlify(payment_hash) if payment_hash else None,
            offer_id=offer_id,
        )
        return grpc2py.listinvoices2py(self.stub.ListInvoices(payload))
