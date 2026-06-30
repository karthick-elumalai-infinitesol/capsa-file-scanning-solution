import requests
import os
from typing import List, Optional
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PublicDatasetFetcher:
    def __init__(self):
        self.sources = {
            "eicar": "https://www.eicar.org/download/eicar.com",
            "malware_hashes": "https://raw.githubusercontent.com/fabrimagic72/malware-samples/master/README.md",
        }

    def fetch_eicar(self, output_path: str = "./data/eicar.bin") -> bool:
        """
        Download EICAR test file.
        """
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            response = requests.get(self.sources["eicar"], timeout=10)
            if response.status_code == 200:
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                logger.info(f"Downloaded EICAR to {output_path}")
                return True

        except Exception as e:
            logger.error(f"Error downloading EICAR: {str(e)}")

        return False

    def list_available_datasets(self) -> dict:
        """
        List available public datasets for malware/clean samples.
        """
        return {
            "aws_open_data": {
                "url": "https://registry.opendata.aws/",
                "description": "AWS Open Data Registry with various datasets",
            },
            "github_datasets": {
                "url": "https://github.com/topics/malware-dataset",
                "description": "GitHub repositories tagged with malware-dataset",
            },
            "virusshare": {
                "url": "https://virusshare.com/",
                "description": "VirusShare - large malware sample repository",
            },
            "coco_dataset": {
                "url": "https://cocodataset.org/",
                "description": "Common Objects in Context - clean image dataset",
            },
        }

    def fetch_dataset_info(self, dataset_name: str) -> Optional[dict]:
        """
        Get information about a specific dataset.
        """
        datasets = self.list_available_datasets()
        if dataset_name in datasets:
            return datasets[dataset_name]
        return None
