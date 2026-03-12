# Day 2 — LEARNING.md

## The Fake Asset Attack — What I Discovered

If someone creates a fake CloudAsset with is_crown_jewel=False
and replaces the real one in the graph, frozen=True alone
cannot stop it because frozen only prevents modifying existing
objects — it does not prevent creating new fake ones.

Vajra defends against this with three layers:
1. frozen=True — blocks modifying existing assets
2. integrity_hash() — detects when a fake replaces a real asset
3. ReportSigner HMAC — detects if the final report is tampered

This is called defense in depth — never rely on one control alone.

## Q1: frozen=True means once a CloudAsset is created no field can ever be changed
## Q2: Prevents silent modification of crown jewel status — security not style
## Q3: Modifying = blocked by frozen. Recreating = always allowed (new object)
## Q4: SHA-256 = fixed 64-char fingerprint. Deterministic, one-way, avalanche effect
## Q5: Stores hash at creation, recomputes later, different hash = tamper detected
## Q6: model_dump_json() is consistent JSON — str() format can change between versions
## Q7: Enum = fixed valid values. Typo caught immediately not months later in production
## Q8: AI_AGENT is IN the graph as an entry point — prompt inject agent = steal credentials
## Q9: CloudAsset = city. GraphEdge = road. Attack path = sequence of roads between cities
## Q10: frozen=True is a security decision because data integrity is the foundation
##      every finding and every report is built on. Tamper with the data = wrong decisions.
