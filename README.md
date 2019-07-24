# sslchk

sslchk is a library inspired by the command line program [check-ssl](https://github.com/wycore/check-ssl). The code was _completely rewritten_ but that repository was used as an educational reference. I tried to preserve the authors original goals:

> Monitor SSL certificate validity for records with multiple IPs.
> ...
> We have several domains which are using DNS RR for loadbalancing/availability. 
> Such domains are especially sensitive, when SSL certificates are renewed. Some of them can easily be missed or deployment fails. It's often hard to discover, which particular service is misconfigured.

# Usage

There is a `CheckHost(string)` function that takes a host, and returns a `map[string]CheckReturn`, where `CheckReturn` is an exported struct with an `Out()` method for printing with `text/tabwriter`.
