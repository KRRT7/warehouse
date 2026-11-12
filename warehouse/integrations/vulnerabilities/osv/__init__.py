# SPDX-License-Identifier: Apache-2.0

from warehouse import integrations
from warehouse.integrations import vulnerabilities


class OSVPublicKeyAPIError(vulnerabilities.InvalidVulnerabilityReportError):
    pass


OSV_PUBLIC_KEYS_URL = "https://osv.dev/public_keys/pypa"
DEFAULT_PUBLIC_KEYS_CACHE_SECONDS = 60 * 30  # 30 minutes
DEFAULT_PUBLIC_KEYS_CACHE = integrations.PublicKeysCache(
    cache_time=DEFAULT_PUBLIC_KEYS_CACHE_SECONDS
)


class VulnerabilityReportVerifier(vulnerabilities.VulnerabilityVerifier):
    public_key_api_error = OSVPublicKeyAPIError
    _public_key_api_name = "OSV"

    def __init__(
        self,
        session,
        metrics,
        public_keys_api_url: str = OSV_PUBLIC_KEYS_URL,
        public_keys_cache=DEFAULT_PUBLIC_KEYS_CACHE,
    ):
        super().__init__(
            metrics=metrics, source="osv", public_keys_cache=public_keys_cache
        )
        self._session = session
        self._metrics = metrics
        self._public_key_url = public_keys_api_url
