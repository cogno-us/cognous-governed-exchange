import os
import pytest

@pytest.fixture(scope='session',autouse=True)
def exact_candidate_dependencies():
    assert os.environ.get('GAX_RUNTIME_COMPATIBILITY_PROFILE')=='typed-refusal-candidate-20261015'
    from experiments.odex_gax_imx_reference.gax_ref_runtime import load_executor_runtime
    load_executor_runtime()
