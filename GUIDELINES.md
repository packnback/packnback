# Attitude

We are a mission critical data storage tool and people 
depend on us shouldn't be let down. Fun is still allowed.

# Programming

All rust code is run through rustfmt.

Try to follow rust community guidelines.

Keep the data write path as small as possible.

Focus on allowing data pipelining where latency may be an issue.

# Security

Be wary of making copies of secret key material.

# Testing

Keep the data write path 100 percent tested. This includes error paths.

# Git

Try to keep commit messages capitalized proper sentences.
If this is a problem, work in a branch until something describable is done.

# Documentation

Documentation priority:

1. Persistent state (disk, sqlite schemas) documented.
2. Network communications documented.
3. Top level design.
4. Crate/library/software interfaces.
5. Code.