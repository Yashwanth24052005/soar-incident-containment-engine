# ─── Week 2 Day 2: VirusTotal Hash Lookup ────────────────────────────────────

from app.virustotal import lookup_hash, HashReputation

@router.post(
    "/alerts/{alert_id}/scan-hash",
    response_model=HashReputation,
    summary="Scan alert file hash against VirusTotal"
)
async def scan_hash_endpoint(alert_id: str):
    """
    Queries VirusTotal for the reputation of the file hash in a malware alert.
    Returns detection ratio, threat label, and risk level.
    Requires VIRUSTOTAL_API_KEY to be set in the .env file.
    Only works for alerts that contain a file_hash field.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found."
        )

    if not alert.file_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Alert '{alert_id}' does not contain a file hash. Only malware alerts have hashes."
        )

    result = await lookup_hash(alert.file_hash)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="VirusTotal lookup failed. Check your API key in .env file."
        )

    return result