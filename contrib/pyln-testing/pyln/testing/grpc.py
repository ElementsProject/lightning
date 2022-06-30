"""A drop-in replacement for the JSON-RPC LightningRpc
"""

from pyln.testing import node_pb2_grpc as pbgrpc
from pyln.testing import node_pb2 as pb
import grpc
import json
from google.protobuf.json_format import MessageToJson
from pyln.testing import grpc2py


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


class LightningGrpc(object):
    def __init__(
        self,
        host: str,
        port: int,
        root_certificates: bytes = DUMMY_CA_PEM,
        private_key: bytes = DUMMY_CLIENT_KEY_PEM,
        certificate_chain: bytes = DUMMY_CLIENT_PEM,
    ):
        self.credentials = grpc.ssl_channel_credentials(
            root_certificates=root_certificates,
            private_key=private_key,
            certificate_chain=certificate_chain,
        )
        self.channel = grpc.secure_channel(
            f"{host}:{port}",
            self.credentials,
            options=(("grpc.ssl_target_name_override", "cln"),),
        )
        self.stub = pbgrpc.NodeStub(self.channel)

    def getinfo(self):
        return grpc2py.getinfo2py(
            self.stub.Getinfo(pb.GetinfoRequest())
        )

    def connect(self, peer_id, host=None, port=None):
        """
        Connect to {peer_id} at {host} and {port}.
        """
        payload = pb.ConnectRequest(
            id=peer_id,
            host=host,
            port=port
        )
        return grpc2py.connect2py(self.stub.ConnectPeer(payload))
