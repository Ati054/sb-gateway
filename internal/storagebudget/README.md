# Storage admission

`Check` compares requested bytes with filesystem space available to the calling
user. Linux uses `Bavail`, so filesystem reserve is not counted as application
capacity. Windows uses `GetDiskFreeSpaceEx`. Unsupported or unreadable paths fail
closed. This reserves no RAM or disk blocks and does not replace handling write
failures from concurrent filesystem users.
