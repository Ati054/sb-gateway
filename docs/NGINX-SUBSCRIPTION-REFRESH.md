# Subscription refresh proxy budget

The management proxy gives only `/api/v1/subscriptions/{id}/refresh` a 180-second
response read timeout. This accommodates the bounded download/admission and
catalogue-import stages. Ordinary API timeouts, body-size limits and administrator
session/CSRF authentication remain unchanged; the bootstrap bearer is not added.

Freshly generated configuration includes the scoped location. Startup also
upgrades saved schema-2/3 configurations without requiring Apply. Migration parses
inline blocks and preserves the generic API's saved headers and guards. Ambiguous
or custom regex/overlapping locations, authentication or includes are left unchanged
with a warning directing the administrator to Check and Apply. This proxy budget
does not extend backend stage deadlines or guarantee completion on exhausted
storage or memory.
