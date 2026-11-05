# Predecessor mount-list handoff

A legacy image handoff creates four owned mount rows and attaches their list
only to the exact stopped predecessor. The REST `mountlists` update sends the
single list name as a string. It does not alter the current container's mounts
or any execution setting.

An HTTP success response alone does not complete the handoff. Fresh inventory
must show the expected predecessor list, unchanged current mount fingerprint,
the same stopped predecessor and all four exact owned mount rows. An accepted
request with no effective property change remains a failed preparation; the
controller does not publish a completed compatibility contract.

A checked retry can reuse existing matching rows. Unexpected identities, mount
sources, row ownership or readback still prevent completion. Synthetic REST
regressions cover strict scalar payloads and HTTP 200 responses which leave the
property unchanged. Actual image/lifecycle qualification remains a separate
release check.

Image-update and rollback scripts use mount-list variable names distinct from
the RouterOS `list` property. Their `find` predicates select the requested list
rather than comparing the property to itself. The compatibility handoff still
requires exactly four matching mounts, and transfer recovery still rejects a
missing mount list before restoring or starting the predecessor.
