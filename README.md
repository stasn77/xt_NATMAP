# xt_NATMAP
xt_NATMAP iptables target module

rule format is: [@]+prenat_addr[/cidr]=postnat_from[-postnat_to | /cidr]
	    or: [@]+0xFWMARK=postnat_from[-postnat_to | /cidr]
	    or: [@]+MAJ:MIN=postnat_from[-postnat_to | /cidr]

