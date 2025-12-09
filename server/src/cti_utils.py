import stix2
from typing import List, Dict, Optional
from datetime import datetime


# ------------------------------------------------------------------
# CTI Utils
# Note: Might be removed since its just a wrapper around STIX2 objects
# ------------------------------------------------------------------

def create_vulnerability(name, description, external_references=None):
    return stix2.Vulnerability(
        name=name,
        description=description,
        external_references=external_references or []
    )

def create_ipv4_address(value, object_marking_refs=None):
    return stix2.IPv4Address(
        value=value,
        object_marking_refs=object_marking_refs
    )

def create_process(pid, path, cmdline):
    return stix2.Process(
        type="process",
        pid=pid,
        cwd=path,
        command_line=cmdline
    )

def create_network_traffic(src_ref, dst_ref, src_port, dst_port, protocol):
    return stix2.NetworkTraffic(
        src_ref=src_ref,
        dst_ref=dst_ref,
        src_port=src_port,
        dst_port=dst_port,
        protocols=protocol
    )

def create_observed_data(first_observed, last_observed, number_observed, objects):
    return stix2.ObservedData(
        first_observed=first_observed,
        last_observed=last_observed,
        number_observed=number_observed,
        objects=objects
    )

def create_relationship(source_ref, target_ref, relationship_type):
    return stix2.Relationship(
        source_ref=source_ref,
        target_ref=target_ref,
        relationship_type=relationship_type
    )

def create_identity(name, identity_class="individual"):
    return stix2.Identity(
        name=name,
        identity_class=identity_class
    )

def create_file(name, size, ctime, mtime, atime, hashes):
    return stix2.File(
        name=name,
        size=size,
        ctime=ctime,
        mtime=mtime,
        atime=atime,
        hashes=hashes
    )

def create_software(name, version, vendor):
    return stix2.Software(
        name=name,
        version=version,
        vendor=vendor
    )