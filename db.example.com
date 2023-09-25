$ORIGIN .
$TTL 604800	; 1 week
rusty-leipzig.com	IN SOA	ns1.rusty-leipzig.com. admin.rusty-leipzig.com. (
				2          ; serial
				604800     ; refresh (1 week)
				86400      ; retry (1 day)
				2419200    ; expire (4 weeks)
				604800     ; minimum (1 week)
				)
			NS	ns1.rusty-leipzig.com.
			NS	ns2.rusty-leipzig.com.
			A	157.230.106.145
$ORIGIN rusty-leipzig.com.
$TTL 86400	; 1 day
example			A	157.230.106.145
$TTL 604800	; 1 week
ns1			A	157.230.106.145
ns2			A	157.230.106.145
www			A	157.230.106.145
