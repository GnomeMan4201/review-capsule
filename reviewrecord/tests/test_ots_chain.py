# OTS mainnet preflight negative tests; Python 3.12+, OTS/bitcoin dependencies [needs Linux runner].
import unittest
from unittest.mock import patch

from opentimestamps.core.timestamp import DetachedTimestampFile,Timestamp
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.serialize import BytesSerializationContext
from rr.anchors import check


MAIN_GENESIS="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


class FakeRPC:
    chain="regtest"
    genesis=MAIN_GENESIS

    def __init__(self,**kw):
        pass
    def __enter__(self):
        return self
    def __exit__(self,*args):
        return False
    def call(self,method,*args):
        if method=="getblockchaininfo":
            return {"chain":self.chain}
        if method=="getblockhash" and args==(0,):
            return self.genesis
        raise AssertionError("Should fail before reading a block header")
    def getblockcount(self):
        raise AssertionError("Should reject network before trusting the tip")


class OTSChainPreflightTests(unittest.TestCase):
    def setUp(self):
        self.target="sha256:"+"01"*32
        timestamp=Timestamp(bytes.fromhex(self.target[7:]))
        timestamp.attestations.add(BitcoinBlockHeaderAttestation(500000))
        detached=DetachedTimestampFile(OpSHA256(),timestamp)
        context=BytesSerializationContext()
        detached.serialize(context)
        self.files={"proof.ots":context.getbytes()}
        self.desc={
            "type":"ots","proof":"proof.ots","target":self.target,
            "authority":"bitcoin","evidence_format":"ots-detached",
            "validation_backend":"Bitcoin Core",
            "confirmation_policy":{"min_confirmations":6}
        }

    def test_regtest_backend_cannot_confirm_bitcoin_anchor(self):
        with patch("bitcoin.rpc.Proxy",FakeRPC):
            status,detail=check(self.desc,self.files,network=True,bitcoin_rpc="http://not-real.invalid")
        self.assertEqual(status,"invalid",detail)
        self.assertIn("mainnet-genesis",detail)

    def test_wrong_genesis_even_if_node_claims_mainnet_is_rejected(self):
        class FakeMainRPC(FakeRPC):
            chain="main"
            genesis="00"*32
        with patch("bitcoin.rpc.Proxy",FakeMainRPC):
            status,detail=check(self.desc,self.files,network=True,bitcoin_rpc="http://not-real.invalid")
        self.assertEqual(status,"invalid",detail)
        self.assertIn("mainnet-genesis",detail)


if __name__=="__main__":
    unittest.main()
