
$TTL 86400 ; Default Time To Live for all records in this file
$ORIGIN example.com.

@       IN      SOA     ns1.example.com. admin.example.com. (
                        2023101301 ; Serial number, format: YYYYMMDDnn
                        3600       ; Refresh
                        1800       ; Retry
                        604800     ; Expire
                        86400      ; Minimum TTL
                        )

; Name Servers
        IN      NS      ns1.example.com.
        IN      NS      ns2.example.com.

; A (IPv4) and AAAA (IPv6) records
@       IN      A       192.0.2.1
        IN      AAAA    2001:0db8:85a3:0000:0000:8a2e:0370:7334

www     IN      A       192.0.2.2
        IN      AAAA    2001:0db8:85a3:0000:0000:8a2e:0370:7335

ns1     IN      A       192.0.2.10
ns2     IN      A       192.0.2.11

