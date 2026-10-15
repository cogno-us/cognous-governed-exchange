from concurrent.futures import ThreadPoolExecutor
from experiments.odex_gax_imx_reference.gax_ref_runtime import TransactionalExchangeStore


def test_effect_ownership_is_persistent_and_serialized(tmp_path):
    path=tmp_path/'exchange.sqlite'
    store=TransactionalExchangeStore(path)
    messages=[dict(message_id=str(i),message_digest='digest'+str(i)) for i in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda m:store.claim_effect(m,'effect'),messages))
    assert results.count(None)==1
    owner=messages[results.index(None)]
    reopened=TransactionalExchangeStore(path)
    assert reopened.claim_effect(owner,'effect') is None
    other=dict(message_id='other',message_digest='different')
    assert reopened.claim_effect(other,'effect')==owner['message_id']
    changed=dict(owner,message_digest='altered')
    assert reopened.claim_effect(changed,'effect')==owner['message_id']
