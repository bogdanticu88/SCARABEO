"""pytest configuration and shared fixtures.

boto3 / pyOpenSSL note
----------------------
The system pyOpenSSL has a binary incompatibility with the installed libssl
(``_lib.OpenSSL_add_all_algorithms`` is missing).  boto3 → botocore →
urllib3.contrib.pyopenssl → OpenSSL crashes on first import in this environment.

We pre-stub ``boto3`` in sys.modules here so that any service module that does
``import boto3`` at import time gets a MagicMock instead of crashing.  Unit
tests that actually need real S3 should be run in an environment with a
compatible OpenSSL (or against LocalStack) and are marked with
``@pytest.mark.integration``.
"""

import sys
from unittest.mock import MagicMock

# Only stub when boto3 has not already been successfully imported.
if "boto3" not in sys.modules:
    # services/ingest/storage.py does:
    #   import boto3
    #   from botocore.config import Config
    #   from botocore.exceptions import ClientError
    # All three need to be stubbed.
    _mock_boto3 = MagicMock()
    _mock_botocore = MagicMock()
    sys.modules["boto3"] = _mock_boto3
    sys.modules["botocore"] = _mock_botocore
    sys.modules["botocore.config"] = _mock_botocore.config
    sys.modules["botocore.exceptions"] = _mock_botocore.exceptions
