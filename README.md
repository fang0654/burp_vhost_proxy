# burp_vhost_proxy
A simple Burp Suite plugin to let you create links that will resolve to IP/host pairs.

It's usage is pretty basic: Give it a domain in the format of <ip>.vhost-proxy.<domain>.vhost-proxy.<some-wildcard-domain>

The last wildcard domain part is necessary since Burp won't pass your request onto the HttpListener if it doesn't do a successful DNS query.

For example:

https://142.250.191.100.vhost-proxy.google.com.vhost-proxy.oastify.com will translate to https://142.250.191.100 with Host: google.com

Also, anywhere in the response that contains "://google.com" is replaced with "://142.250.191.100.vhost-proxy.google.com.vhost-proxy.oastify.com"
