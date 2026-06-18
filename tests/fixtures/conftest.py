import pytest

# Demo fixture for the leakproof walkthrough: a production-shaped Postgres DSN
# with embedded credentials, parked in a neutrally-named module global. A
# keyword scanner sees a var called "DB"; leakproof sees the live DSN in the
# value. Fake-but-valid-shaped on purpose — never a real credential.
DB = "postgres://svc_app:Pr0dPassw0rd!@db.prod.internal:5432/payments"
