from dataclasses import dataclass
from typing import List, Dict
import yaml

@dataclass
class ScanConfig:
    target_url: str
    depth: int = 3
    max_urls: int = 500
    threads: int = 5
    rate_limit: int = 10
    enabled_plugins: List[str] = None
    exclusions: Dict = None
    output_formats: List[str] = None
    output_directory: str = "./scan_results"

    client_name: str = "Unknown Client"


    @classmethod
    def from_yaml(cls, config_path: str):
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        return cls(
            target_url=config['target']['url'],
            depth=config.get('scan', {}).get('depth', 3),
            max_urls=config.get('scan', {}).get('max_urls', 500),
            threads=config.get('scan', {}).get('threads', 5),
            rate_limit=config.get('scan', {}).get('rate_limit', 10),
            enabled_plugins=config.get('plugins', {}).get('enabled', []),
            exclusions=config.get('exclusions', {}),
            output_formats=config.get('output', {}).get('formats', ['json']),
            output_directory=config.get('output', {}).get('directory', './scan_results'),
            client_name=config.get('client', {}).get('name', 'Unknown Client')
        )

    @classmethod
    def from_target(cls, target_url: str, plugins: List[str] = None):
        return cls(
            target_url=target_url,
            enabled_plugins=plugins or ['security_headers', 'sensitive_files']
        )
