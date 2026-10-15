"""A tiny stand-in for Threat Intel, the vulnerability intelligence service.

A real one would sit on a search index, a cache and daily NVD feeds. This one keeps
a few dozen CVEs in JSON files and answers the same questions over the same
routes, so the Platform API side can be exercised without any of that.
"""
