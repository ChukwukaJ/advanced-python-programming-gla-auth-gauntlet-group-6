# ─────────────────────────────────────────────────────────────────────────────
# api/views.py — Authentication Gauntlet Lab
#
# Wrap-Up Comparison Table (Reporter fills this in at the end of the lab):
#
# # +-------------------+------------+-----------+-------------------+----------+
# | Method            | Stateful?  | DB Lookup?| Credentials sent  | Safe on  |
# |                   |            |           | every request?    | HTTP?    |
# +-------------------+------------+-----------+-------------------+----------+
# | Basic Auth        | No         | Yes*      | Yes               | No       |
# | Session Auth      | Yes        | Yes       | No                | No       |
# | Opaque Token Auth | No         | Yes       | No                | No       |
# | JWT               | No         | No**      | No                | No       |
# +-------------------+------------+-----------+-------------------+----------+
#
# * Basic Auth itself does not require a database; the server/application
#   decides how to verify the username and password.
#
# ** A self-contained JWT can be validated using its signature without
#    looking up the access token in a database. However, if the server implements a denylist #
# Discussion prompts:
# 1. Writing the raw Authorization header by hand in REST Client made it
#    clear what Postman was building for us automatically when we used its
#    Basic Auth tab.
# 2. JWT is the best fit for an offline mobile app since it's self contained
#    and doesn't need a server round trip or database lookup to validate.
# 3. None of these methods are safe on a network you don't control unless
#    HTTPS is used, since HTTP sends everything unencrypted. Of the four,
#    JWT and opaque tokens are relatively better than Basic Auth since they
#    don't resend the actual password on every request.

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import (
    BasicAuthentication,
    SessionAuthentication,
    TokenAuthentication,
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Basic Authentication
# ─────────────────────────────────────────────────────────────────────────────
@api_view(["GET"])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def basic_auth_view(request):
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    print(f"Incoming Header: {auth_header}")

    # Reporter — Phase 1 challenge answers:
    # Q1 answer (header format for admin:admin123):
    # Basic authentication uses the format "username:password", so it is:
    # admin:admin123
    # Q2 answer (HTTP vs HTTPS):
    # Even though the credentials are Base64 encoded instead of plaintext,
    # Base64 is just encoding, not encryption, so it's easy to reverse.
    # Over plain HTTP the header is sent unencrypted, so anyone intercepting
    # the traffic can decode it and get the username and password directly.

    return Response({"message": "Check your terminal!"})

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Session Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
def session_auth_view(request):
    # Reporter — Phase 2 challenge answers:
    # Q1 answer (effect of deleting the session cookie): After deleting the sessionid cookie and refreshing, the user is redirected to the login page because the browser no longer sends the session ID.The server-side session record may still exist in Django's session database, but without the sessionid cookie Django cannot associate the request with that authenticated session.
    # Synthesis answer (how session fixation works):# Session hijacking: if an attacker obtains a valid sessionid,
# they may be able to reuse it to impersonate the authenticated user.
# The session ID acts as the link between the browser and the
# authenticated server-side session.

    return Response({"message": "Session authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Token Authentication (Opaque)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def token_auth_view(request):
    # Team Challenge 1 answer:
    # The tampered token returned 401 Unauthorized. DRF's TokenAuthentication
    # couldn't find a matching token record in the database, so the request
    # failed authentication.

    # Django does not store admin123 as plain text.
# The password uses the PBKDF2-SHA256 hashing algorithm
# (pbkdf2_sha256$ prefix) with a salt, making the stored
# password much harder to recover if the database is exposed.

# An opaque token can be permanently invalidated by deleting or revoking the
# token record in the server-side database, which requires server/admin action.
# A JWT is self-contained and normally remains valid until its expiration time;
# revoking it requires additional server-side state, such as a denylist,
# token-version check, or short-lived access tokens with refresh-token revocation.

    return Response({"message": "Token authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — JSON Web Tokens (JWT)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def jwt_protected_view(request):
    # The JWT payload contains identifying information such as user_id,
# along with the exp timestamp that determines when the token expires.

# The server validates the JWT by verifying its cryptographic signature
# rather than looking up the access token in a database.
    # Synthesis answer (JWT revocation challenge and workaround): # The server returns 401 Unauthorized because changing user_id makes the JWT's
# signature invalid, even though the token remains structurally valid.
# The signature proves that the token payload has not been modified since it was issued.

    return Response({"message": "JWT authenticated.", "user": request.user.username})