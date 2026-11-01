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


    def _two_attestation_proof(self):
        timestamp=Timestamp(bytes.fromhex(self.target[7:]))
        timestamp.attestations.add(BitcoinBlockHeaderAttestation(500000))
        timestamp.attestations.add(BitcoinBlockHeaderAttestation(500001))
        detached=DetachedTimestampFile(OpSHA256(),timestamp)
        ctx=BytesSerializationContext()
        detached.serialize(ctx)
        self.files={"proof.ots":ctx.getbytes()}

    def test_invalid_second_attestation_blocks_earlier_valid_one(self):
        self._two_attestation_proof()
        from types import SimpleNamespace
        class MainRPC(FakeRPC):
            chain="main"
            def getblockcount(self):
                return 500010
            def getblockhash(self,height):
                return "fake-block-"+str(height)
            def getblockheader(self,block_hash):
                return SimpleNamespace(nTime=1690000000)
            def call(self,method,*args):
                if method=="getblockhash" and args!=(0,):
                    return "fake-block-"+str(args[0])
                return super().call(method,*args)
        def selective(self,message,header):
            if self.height==500001:
                raise ValueError("planted second attestation mismatch")
            return 1690000000
        with patch("bitcoin.rpc.Proxy",MainRPC),patch.object(
                BitcoinBlockHeaderAttestation,"verify_against_blockheader",selective):
            status,detail=check(self.desc,self.files,network=True,bitcoin_rpc="http://not-real.invalid")
        self.assertEqual(status,"invalid",detail)
        self.assertIn("At least one",detail)

    def test_mocked_two_valid_attestations_report_block_metadata(self):
        self._two_attestation_proof()
        from types import SimpleNamespace
        class MainRPC(FakeRPC):
            chain="main"
            def getblockcount(self):
                return 500010
            def getblockhash(self,height):
                return "fake-block-"+str(height)
            def getblockheader(self,block_hash):
                return SimpleNamespace(nTime=1690000000)
            def call(self,method,*args):
                if method=="getblockhash" and args!=(0,):
                    return "fake-block-"+str(args[0])
                return super().call(method,*args)
        with patch("bitcoin.rpc.Proxy",MainRPC),patch.object(
                BitcoinBlockHeaderAttestation,"verify_against_blockheader",lambda *args:1690000000):
            status,detail=check(self.desc,self.files,network=True,bitcoin_rpc="http://not-real.invalid")
        self.assertEqual(status,"confirmed",detail)
        self.assertIn("block_hash=fake-block-500000",detail)
        self.assertIn("confirmations=11",detail)
        self.assertIn("block_time=",detail)
        # This is a mocked RPC and patched header verifier, not live OTS evidence.


if __name__=="__main__":
    unittest.main()
