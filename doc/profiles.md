# Profiles and Customization

AutoReconR is highly customizable and supports different scanning and service
enumeration profiles. A *scanning profile* defines one or more command
sequences for the (nmap) port scanner. It must be prepended with the
`port-scan` instruction. 

If AutoReconR is started and no profile is explicitly referenced, the *default* profile (stored in the folder `config/default`)is selected. It performs a *quick* TCP scan of the most common 1,000 ports, a *full* TCP scan from port 1 to 65,535, and a scan of the most common 20 UDP ports.


```
   [port-scan.default.nmap-quick]

        [port-scan.default.nmap-quick.service-detection]
        command = '{applications.nmap} {nmap_extra} -sV -sC --version-all -oN "{scandir}/_quick_tcp_nmap.txt" -oX "{scandir}/xml/_quick_tcp_nmap.xml" {address}'
        pattern = '^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'

    [port-scan.default.nmap-full-tcp]

        [port-scan.default.nmap-full-tcp.service-detection]
        command = '{applications.nmap} {nmap_extra} -A --osscan-guess --version-all -p- -oN "{scandir}/_full_tcp_nmap.txt" -oX "{scandir}/xml/_full_tcp_nmap.xml" {address}'
        pattern = '^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'

    [port-scan.default.nmap-top-20-udp]

        [port-scan.default.nmap-top-20-udp.service-detection]
        command = '{applications.nmap} {nmap_extra} -sU -A --top-ports=20 --version-all -oN "{scandir}/_top_20_udp_nmap.txt" -oX "{scandir}/xml/_top_20_udp_nmap.xml" {address}'
        pattern = '^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'
```


Profiles can also be overwritten. Upon execution, AutoReconR searches the
specified configuration directory (as well as subdirectories) for any profile
that matches the specified name. For instance, for the scanning profile
*port-scan.quick* that is defined in `config/default/port-scan-profiles.toml`,
a variation is saved in the `config/default/custom/custom.toml` file. The
variation only scans the top 20 rather than the most common 1,000 ports and
does not attempt to determine the version of identified services to increase
speed. 

When AutoReconR is executed with the `, this adapted scanning profile is chosen.  

```
$ python3 autoreconr.py --profile=quick 10.11.1.5
```

In general, profiles that are detected *later* while examining the
configuration directory take precedence and overwrite other profiles that were
possibly defined previously. By this, users can easily adapt existing profiles
or add new ones according to their desires.

Please note that in the example above, the *quick* profile in the `config/default/` directory would *always* be overwritten and *never* be executed. To avoid this, the profile definition in the `config/default/custom` directory can be simply deleted. 

It is also possible copying the profile to an entirely new directory and specifying the alternative configuration path during startup as shown below. In this case, AutoReconR will search the specified directory for other required configuration files as well.

```
$ python3 autoreconr.py --config-dir=config/custom --profile=quick 10.11.1.5
```

