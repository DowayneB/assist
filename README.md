My agent assist code.

This will test to see that all DNS records are in order for a domain.

I have thrown the below codes in my code:
100 - Pending
200 - OK
300 - warning
500 - error

I did not throw any 400 (fail) as I am unsure how to differentiate between fail and error when it comes to domains.

The below are some good domains to test out:

studysesh.co.za - All 200 (OK)

domainion.co.za - NS and hosting are 200, but MX is 300 (warning) as the domain routes through a spam filter, and the domains web content records are not the same as the server

trukru.co.za    - 500 on hosting checks, as the site gives a 403 error

afrihost.com	- Since this goes through cloudflare, the NS check will give a warning, but MX and hosting will fail. I will see why this is, but I first need to research how cloudflare works

tfcuytfvo.bleh  - all 500 (error) because there are no name servers, this domain probably doesn't exist either, but I haven't found a way of finding out whether a domain exists or not vs whether or not it has name servers

hostingtricks.co.za - All 500, because name servers are mixed
