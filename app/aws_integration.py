"""
AWS Security Group Integration - Week 3 Day 3
Uses boto3 to modify AWS Security Group rules to block malicious IPs.
Falls back to simulation mode if AWS credentials are not configured.
"""

import logging
import os
from typing import Optional

logger = logging.getLogger("soar.aws")

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
AWS_SECURITY_GROUP_ID = os.getenv("AWS_SECURITY_GROUP_ID", "")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")

_aws_blocked_ips = {}


def _is_aws_configured() -> bool:
    return all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SECURITY_GROUP_ID])


async def block_ip_in_security_group(ip_address: str, alert_id: str, description: str = "Blocked by SOAR engine") -> dict:
    if _is_aws_configured():
        return await _real_aws_block(ip_address, alert_id, description)
    else:
        logger.warning("[AWS] AWS credentials not configured. Running in simulation mode.")
        return await _simulate_aws_block(ip_address, alert_id, description)


async def _real_aws_block(ip_address: str, alert_id: str, description: str) -> dict:
    try:
        import boto3
        ec2 = boto3.client(
            "ec2",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        )
        response = ec2.revoke_security_group_ingress(
            GroupId=AWS_SECURITY_GROUP_ID,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": f"{ip_address}/32", "Description": f"{description} | alert_id={alert_id}"}],
            }],
        )
        _aws_blocked_ips[ip_address] = {
            "alert_id": alert_id,
            "security_group_id": AWS_SECURITY_GROUP_ID,
            "region": AWS_REGION,
            "mode": "real_aws",
        }
        logger.warning(f"[AWS] *** REAL AWS BLOCK *** | ip={ip_address} | sg={AWS_SECURITY_GROUP_ID}")
        return {
            "success": True, "mode": "real_aws", "ip_address": ip_address,
            "security_group_id": AWS_SECURITY_GROUP_ID, "region": AWS_REGION,
            "message": f"IP {ip_address} blocked in AWS Security Group {AWS_SECURITY_GROUP_ID}",
        }
    except ImportError:
        logger.error("[AWS] boto3 not installed. Run: pip install boto3")
        return {"success": False, "mode": "real_aws", "ip_address": ip_address, "message": "boto3 not installed."}
    except Exception as e:
        logger.error(f"[AWS] Failed to block {ip_address}: {e}")
        return {"success": False, "mode": "real_aws", "ip_address": ip_address, "message": str(e)}


async def _simulate_aws_block(ip_address: str, alert_id: str, description: str) -> dict:
    import asyncio
    await asyncio.sleep(0.1)
    _aws_blocked_ips[ip_address] = {
        "alert_id": alert_id, "security_group_id": "sg-simulated",
        "region": AWS_REGION, "mode": "simulation",
    }
    logger.info(f"[AWS] SIMULATION | Would block {ip_address} in Security Group.")
    return {
        "success": True, "mode": "simulation", "ip_address": ip_address,
        "security_group_id": "sg-simulated", "region": AWS_REGION,
        "message": f"SIMULATION: IP {ip_address} would be blocked. Configure AWS credentials to enable real blocking.",
    }


async def unblock_ip_in_security_group(ip_address: str) -> dict:
    if ip_address not in _aws_blocked_ips:
        return {"success": False, "message": f"IP {ip_address} is not in the AWS block list."}
    if not _is_aws_configured():
        del _aws_blocked_ips[ip_address]
        return {"success": True, "mode": "simulation", "message": f"SIMULATION: IP {ip_address} would be unblocked."}
    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=AWS_REGION,
                           aws_access_key_id=AWS_ACCESS_KEY_ID,
                           aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        ec2.authorize_security_group_ingress(
            GroupId=AWS_SECURITY_GROUP_ID,
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": f"{ip_address}/32"}]}],
        )
        del _aws_blocked_ips[ip_address]
        return {"success": True, "mode": "real_aws", "message": f"IP {ip_address} unblocked."}
    except Exception as e:
        return {"success": False, "message": str(e)}


def get_aws_blocked_ips() -> dict:
    return dict(_aws_blocked_ips)