; Zone file for target.com benchmark
; All subdomains point to nginx gateway 172.20.0.2

$TTL    300
@       IN      SOA     ns.target.com. admin.target.com. (
                        2026070901  ; Serial
                        3600        ; Refresh
                        900         ; Retry
                        604800      ; Expire
                        300 )       ; Minimum TTL

                IN      NS      ns.target.com.

ns              IN      A       172.20.0.53

; All services via gateway
@               IN      A       172.20.0.2
www             IN      A       172.20.0.2
admin           IN      A       172.20.0.2
api             IN      A       172.20.0.2
shop            IN      A       172.20.0.2
internal        IN      A       172.20.0.2
*               IN      A       172.20.0.2
