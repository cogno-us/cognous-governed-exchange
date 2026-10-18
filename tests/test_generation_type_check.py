"""Input validation: the lineage generation must be a plain int (no float, no bool, no int subclass).

Previously a float with an integral value was accepted and a non-integral float was truncated by ``int()``.
"""
from __future__ import annotations

import pytest

from experiments.odex_gax_imx_reference import gax_ref as base
from experiments.odex_gax_imx_reference import gax_ref_runtime as runtime
from experiments.odex_gax_imx_reference.generation_fence import GenerationFenceClaim
from test_exchange_input_and_source_repairs import EVAL, governed, registry, stub_proposal  # noqa: F401


class IntSubclass(int):
    pass


BAD = [5.0, 4.9, True, False, -1, "5", IntSubclass(5), float("nan")]


@pytest.mark.parametrize("value", BAD)
def test_claim_refuses_non_int_generation(value):
    with pytest.raises(ValueError, match="generation must be a non-negative integer"):
        GenerationFenceClaim("conv", "effect", value)


@pytest.mark.parametrize("value", [0, 3, 2**40])
def test_claim_accepts_plain_int_generation(value):
    assert GenerationFenceClaim("conv", "effect", value).generation == value


@pytest.mark.parametrize("value", [5.0, 4.9, True, "5", IntSubclass(5), -1])
def test_run_exchange_refuses_non_int_generation_with_a_typed_reason(tmp_path, stub_proposal, value):
    store_path = tmp_path / "exchange.sqlite"
    result = runtime.run_exchange(
        governed("msg-refund-001"), {}, registry(), object(), evaluation_time=EVAL, manifest={}, store_path=store_path,
        resolver=object(), execution_policy_factory=lambda op: None, observation_policy=object(),
        generation_fence=object(), lineage_generation=value)
    assert result["execution"] == {"attempted": False, "reason": "lineage_generation_invalid"}
    assert "GAX-EXECUTION-LINEAGE-GENERATION-INVALID" in result["assessment"]["errors"]
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {}


def test_control_plain_int_generation_is_not_refused_for_its_type(tmp_path, stub_proposal):
    result = runtime.run_exchange(
        governed("msg-refund-001"), {}, registry(), object(), evaluation_time=EVAL, manifest={},
        store_path=tmp_path / "exchange.sqlite", resolver=None, generation_fence=object(), lineage_generation=5)
    assert result["execution"]["reason"] == "trusted_resolver_required"
