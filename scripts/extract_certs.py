import json
import base64
import os
from pathlib import Path
from typing import Dict, List


def extract_certificates_for_domain(
    acme_json_path: str,
    output_dir: str,
    domains: List[str],
    resolver_name: str = "myresolver"
) -> None:
    with open(acme_json_path, "r") as file:
        data: Dict[str, Dict] = json.load(file)
        certificates = data[resolver_name]["Certificates"]
        domain_matched: List[str] = []
        for cert in certificates:
            if domain in cert["domain"]["main"]:
                # only extract for specified domain
                if cert["domain"]["main"] not in domains:
                    continue
                cert_b64 = cert["certificate"]
                key_b64 = cert["key"]
                cert_decoded = base64.b64decode(cert_b64).decode("utf-8")
                key_decoded = base64.b64decode(key_b64).decode("utf-8")
                # splitting server certificate
                # and intermediate certificates associated with domain
                certs = cert_decoded.split('-----END CERTIFICATE-----\n')
                server_cert = certs[0] + '-----END CERTIFICATE-----\n'
                _intermediates = '-----BEGIN CERTIFICATE-----\n'.join(certs[1:])
                Path(f"{output_dir}/{domain}/").mkdir(
                    parents=True,
                    exist_ok=True
                )
                # writing the full chain (server + intermediates)
                # - contains all certificates associated with domain
                with open(
                    f"{output_dir}/{domain}/fullchain.pem",
                    "w"
                ) as cert_file:
                    cert_file.write(cert_decoded)
                # writing the server certificate only
                with open(
                    f"{output_dir}/{domain}/cert.pem",
                    "w"
                ) as server_cert_file:
                    server_cert_file.write(server_cert)
                # writing the private key
                with open(
                    f"{output_dir}/{domain}/privkey.pem",
                    "w"
                ) as key_file:
                    key_file.write(key_decoded)
                # append domain name on successful extraction
                domain_matched.append(cert["domain"]["main"])
        if len(domain_matched) != 0:
            print(f"Extracted for: {domain_matched}")
            return
        
        print("Extracted nothing, no match found at specified acme.json file")


if __name__ == "__main__":
    # Environment variables:
    #   'DOMAIN'
    #   'RESOLVER_NAME'
    #   'ACME_JSON_PATH'
    #   'OUT_DIR' 
    # -> should be set
    domain: str         = os.environ["DOMAIN"]
    resolver: str       = os.environ["RESOLVER_NAME"]
    acme_path: str      = os.environ["ACME_JSON_PATH"]
    out_certs_dir: str  = os.environ["OUT_DIR"]

    extract_certificates_for_domain(
        acme_json_path=acme_path,
        domains=[domain],
        output_dir=out_certs_dir,
        resolver_name=resolver
    )
