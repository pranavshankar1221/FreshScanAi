import os
from typing import Optional

import httpx
from fastapi import HTTPException

TURNSTILE_SECRET_KEY = os.environ.get('TURNSTILE_SECRET_KEY', '')

async def verify_turnstile_token(
    turnstile_token: Optional[str],
    remote_ip: Optional[str] = None,
) -> None:
    if not TURNSTILE_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail='Turnstile secret key is not configured. Set TURNSTILE_SECRET_KEY.',
        )

    if not turnstile_token:
        raise HTTPException(status_code=400, detail='Turnstile token is required.')

    payload = {
        'secret': TURNSTILE_SECRET_KEY,
        'response': turnstile_token,
    }
    if remote_ip:
        payload['remoteip'] = remote_ip

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                'https://challenges.cloudflare.com/turnstile/v0/siteverify',
                data=payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f'Turnstile verification failed: {exc}',
        )

    if not data.get('success'):
        errors = data.get('error-codes', [])
        raise HTTPException(
            status_code=400,
            detail=f"Turnstile verification failed: {', '.join(errors) or 'invalid token'}",
        )
