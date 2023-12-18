from pathlib import Path
from typing import Optional

from splunk_appinspect.python_analyzer.trustedlibs import trusted_data_collector, utilities


class TrustedLibsManager:
    def __init__(
        self,
        trusted_checks_and_libs_file: Path = trusted_data_collector.TRUSTED_CHECK_AND_LIBS_FILE,
        untrusted_check_and_libs_file: Path = trusted_data_collector.UNTRUSTED_CHECK_AND_LIBS_FILE,
    ):
        self.libs_data: trusted_data_collector.TrustedDataCollector = trusted_data_collector.TrustedDataCollector(
            trusted_checks_and_libs_file, untrusted_check_and_libs_file
        )

    def check_if_lib_is_trusted(
        self,
        check_name: str,
        lib: Optional[bytes] = None,
        content_hash: Optional[str] = None,
    ) -> bool:
        """check the (checkname, lib) is trusted or not."""
        if lib is not None:
            assert isinstance(lib, bytes)
            lib_hash = utilities.get_hash_file(lib)
        else:
            lib_hash = content_hash
        if (check_name, lib_hash) in self.libs_data.get_untrusted_check_and_libs():
            return False
        if (check_name, lib_hash) in self.libs_data.get_trusted_check_and_libs():
            return True
        return False
