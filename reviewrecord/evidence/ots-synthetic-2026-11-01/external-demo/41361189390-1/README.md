# Explorer comparison and real synthetic FreeTSA responses

Evidence run: https://github.com/GnomeMan4201/review-capsule/actions/runs/41361189390
Source snapshot: c38738a2c843c81292e08bc5cfa8f527c74c7170. Pinned verifier: d54432f3e4c67f11ea53c16ebb383c1aec1f9224.

Both Blockstream and mempool.space APIs returned block hash 000000000000000000006e38ea42eeb0dbba4966108924968274723f69d2bc84 at height 974172, displayed Merkle root a817138c148fa55b74a3b620cef66321d2dc6fd3507d24cf35351d0a95fb2b24, and tip height 974190 (reported depth 19). The 80-byte header hashes and its Merkle root bytes also matched. Raw responses are under explorers/. These are explorer-operator observations. They do not satisfy the configured-node gate, establish proof-of-work chain selection, or prove two operators have distinct failure assumptions. No node or RPC was selected.

The OTS internal Merkle bytes are little-endian: 242bfb950a1d3535cf247d50d36fdcd22163f6ce20b6a3745ba58f148c1317a8. Reversing their byte order yields the explorer display root above. All three retained proof files stayed unchanged during this run.

Under tsa/<target>/, request.tsq is the real original nonce-bearing RFC3161 request and response.tsr is the real service response. Each request and signed TSTInfo imprint matched the exact target. OpenSSL accepted the request/signature/path/nonce check under CA material downloaded from the same FreeTSA HTTPS service. Wrong digest and different-nonce controls were rejected. results.json retains every command and result. The returned policy OID was 1.2.3.4.1. Neither this OID nor the signer/CA has been accepted as a production pin profile by the author. Certificates and SHA-256 fingerprints are recorded under service-sourced-certificates and results.json; they are outside the portable bundle's trust inputs.

Historical correction: earlier root-level report.json runs used explicit placeholder TSA bytes, not real FreeTSA tokens. Calling that only 'no CA supplied' was incomplete. Those reports remain byte-exact historical output; they are not evidence of an actual token. This run's bundle/anchors contains the real responses and original requests. If a request fails, the demo builder removes the fixture placeholder and reports an explicit no-token input rather than presenting it as a real response.

report.json here is literal output of the unchanged pinned verifier over the new derived bundle. It deliberately receives no production TSA policy or Bitcoin RPC. It exits 2: 158 pass, 0 fail, 0 missing, 3 pending, 6 unverifiable, 2 not checked. The separate OpenSSL demo results must not be read as a promotion of the portable anchor gate. No production pin governance, revocation or clock qualification was performed. These tokens were obtained after this already completed synthetic round; they cannot establish pre-review packet release order.

The OTS follow-up task remains paused for a chosen Bitcoin backend. PR #2 remains draft/unmerged, main is unchanged and all inputs are synthetic. The comparison and UI branches were not merged or changed.
