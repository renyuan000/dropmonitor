/*
 * Here's a sample kernel module showing the use of jprobes to dump
 * the arguments of do_fork().
 *
 * For more information on theory of operation of jprobes, see
 * Documentation/kprobes.txt
 *
 * Build and insert the kernel module as done in the kprobe example.
 * You will see the trace data in /var/log/messages and on the
 * console whenever do_fork() is invoked to create a new process.
 * (Some messages may be suppressed if syslogd is configured to
 * eliminate duplicate messages.)
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/udp.h>
#include <net/protocol.h>
#include <net/inetpeer.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <net/arp.h>
#include <net/dst.h>
#include <net/route.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <net/ip.h>
#include <linux/if_ether.h>
#include <net/tcp.h>
#include <linux/types.h>
#include <net/netlink.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/err.h>
#include <linux/ipv6.h>

/*
 * Jumper probe for do_fork.
 * Mirror principle enables access to arguments of the probed routine
 * from the probe handler.
 */
struct netlink_ring {
	void			**pg_vec;
	unsigned int		head;
	unsigned int		frames_per_block;
	unsigned int		frame_size;
	unsigned int		frame_max;

	unsigned int		pg_vec_order;
	unsigned int		pg_vec_pages;
	unsigned int		pg_vec_len;

	atomic_t		pending;
};
struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	u32			portid;
	u32			dst_portid;
	u32			dst_group;
	u32			flags;
	u32			subscriptions;
	u32			ngroups;
	unsigned long		*groups;
	unsigned long		state;
	wait_queue_head_t	wait;
	bool			cb_running;
	struct netlink_callback	cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
	void			(*netlink_rcv)(struct sk_buff *skb);
	void			(*netlink_bind)(int group);
	struct module		*module;
#ifdef CONFIG_NETLINK_MMAP
	struct mutex		pg_vec_lock;
	struct netlink_ring	rx_ring;
	struct netlink_ring	tx_ring;
	atomic_t		mapped;
#endif /* CONFIG_NETLINK_MMAP */
};
static inline struct netlink_sock *nlk_sk(struct sock *sk)
{
	return container_of(sk, struct netlink_sock, sk);
}

struct __type_model {
    unsigned char *type;
};
static struct __type_model sk_type[256] = 
{
    {
        .type = "NO"
    },
    {
        .type = "SOCK_STREAM"
    },
    {
        .type = "SOCK_DGRAM"
    },
    {
        .type = "SOCK_RAW"
    },
    {
        .type = "SOCK_RDM"
    },
    {
        .type = "SOCK_SEQPACKET"
    },
    {
        .type = "SOCK_DCCP"
    },
    {
        .type = "NO"
    },
    {
        .type = "NO"
    },
    {
        .type = "NO"
    },
    {
        .type = "SOCK_PACKET"
    }
};

static struct __type_model pkt_type[256] = 
{
    {
        .type = "PACKET_HOST"
    },
    {
        .type = "PACKET_BROADCAST"
    },
    {
        .type = "PACKET_MULTICAST"
    },
    {
        .type = "PACKET_OTHERHOST"
    },
    {
        .type = "PACKET_OUTGOING"
    },
    {
        .type = "PACKET_LOOPBACK"
    },
    {
        .type = "PACKET_FASTROUTE"
    }
};


static struct __type_model inet_proto[257] = 
{
    {
        .type = "IPPROTO_IP"
    },
    {
        .type = "IPPROTO_ICMP"
    },
    {
        .type = "IPPROTO_IGMP"
    },
    {
        .type = "003"
    },
    {
        .type = "IPPROTO_IPIP"
    },
    {
        .type = "005"
    },
    {
        .type = "IPPROTO_TCP" // 6
    },
    {
        .type = "007"
    },
    {
        .type = "IPPROTO_EGP"
    },{.type = "009"},{.type = "010"},{.type = "011"},
    {
        .type = "IPPROTO_PUP" //12
    },{.type = "013"},{.type = "014"},{.type = "015"},{.type = "016"},
    {
        .type = "IPPROTO_UDP" //17
    },{.type = "018"},{.type = "019"},{.type = "020"},{.type = "021"},
    {
        .type = "IPPROTO_IDP" //22
    },{ .type = "023"},{.type = "024"},{.type = "025"},{.type = "026"},{.type = "027"},{.type = "028"},
    {
        .type = "IPPROTO_TP" //29
    },{.type = "030"},{.type = "031"},{.type = "032"},
    {
        .type = "IPPROTO_DCCP" //33
    },{.type = "034"},{.type = "035"},{.type = "036"},{.type = "037"},{.type = "038"},{.type = "039"},{.type = "040"},
    {
        .type = "IPPROTO_IPV6" //41
    },{.type = "042"},{.type = "043"},{.type = "044"},{.type = "045"},
    {
        .type = "IPPROTO_RSVP"
    },
    {
        .type = "IPPROTO_GRE" //47
    },{.type = "048"},{.type = "049"},
    {
        .type = "IPPROTO_ESP" //50
    },
    {
        .type = "IPPROTO_AH" //51
    },{.type = "052"},{.type = "053"},{.type = "054"},{.type = "055"},{.type = "056"},{.type = "057"},{.type = "058"},{.type = "059"},
      {.type = "060"},{.type = "061"},{.type = "062"},{.type = "063"},{.type = "064"},{.type = "065"},{.type = "066"},{.type = "067"},
      {.type = "068"},{.type = "069"},{.type = "070"},{.type = "071"},{.type = "072"},{.type = "073"},{.type = "074"},{.type = "075"},
      {.type = "076"},{.type = "077"},{.type = "078"},{.type = "079"},{.type = "080"},{.type = "081"},{.type = "082"},{.type = "083"},
      {.type = "084"},{.type = "085"},{.type = "086"},{.type = "087"},{.type = "088"},{.type = "089"},{.type = "090"},{.type = "091"},
    {
        .type = "IPPROTO_MTP" //92
    },
    {
        .type = "093" 
    },
    {
        .type = "IPPROTO_BEETPH" //94
    },{.type = "095"},{.type = "096"},{.type = "097"},
    {
        .type = "IPPROTO_ENCAP" //98
    },{.type = "099"},{.type = "100"},{.type = "101"},{.type = "102"},
    {
        .type = "IPPROTO_PIM" //103 
    },{.type = "104"},{.type = "105"},{.type = "106"},{.type = "107"},
    {
        .type = "IPPROTO_COMP"  //108
    },{.type = "109"},{.type = "110"},{.type = "111"},{.type = "112"},{.type = "113"},{.type = "114"},{.type = "115"},{.type = "116"},
      {.type = "117"},{.type = "118"},{.type = "119"},{.type = "120"},{.type = "121"},{.type = "122"},{.type = "123"},{.type = "124"},
      {.type = "125"},{.type = "126"},{.type = "127"},{.type = "128"},{.type = "129"},{.type = "130"},{.type = "131"},
    {
        .type = "IPPROTO_SCTP" //132
    },{.type = "133"},{.type = "134"},{.type = "135"},
    {
        .type = "IPPROTO_UDPLITE"  //136
    },{.type = "137"},{.type = "138"},{.type = "HIP"},{.type = "140"},{.type = "141"},{.type = "142"},{.type = "143"},{.type = "144"},
      {.type = "145"},{.type = "146"},{.type = "147"},{.type = "148"},{.type = "149"},{.type = "150"},{.type = "151"},{.type = "152"},
      {.type = "153"},{.type = "154"},{.type = "155"},{.type = "156"},{.type = "157"},{.type = "158"},{.type = "159"},{.type = "160"},
      {.type = "161"},{.type = "162"},{.type = "163"},{.type = "164"},{.type = "165"},{.type = "166"},{.type = "167"},{.type = "168"},
      {.type = "169"},{.type = "170"},{.type = "171"},{.type = "172"},{.type = "173"},{.type = "174"},{.type = "175"},{.type = "176"},
      {.type = "177"},{.type = "178"},{.type = "179"},{.type = "180"},{.type = "181"},{.type = "182"},{.type = "183"},{.type = "184"},
      {.type = "185"},{.type = "186"},{.type = "187"},{.type = "188"},{.type = "189"},{.type = "190"},{.type = "191"},{.type = "192"},
      {.type = "193"},{.type = "194"},{.type = "195"},{.type = "196"},{.type = "197"},{.type = "198"},{.type = "199"},{.type = "200"},
      {.type = "201"},{.type = "202"},{.type = "203"},{.type = "204"},{.type = "205"},{.type = "206"},{.type = "207"},{.type = "208"},
      {.type = "209"},{.type = "210"},{.type = "211"},{.type = "212"},{.type = "213"},{.type = "214"},{.type = "215"},{.type = "216"},
      {.type = "217"},{.type = "218"},{.type = "219"},{.type = "220"},{.type = "221"},{.type = "222"},{.type = "223"},{.type = "224"},
      {.type = "225"},{.type = "226"},{.type = "227"},{.type = "228"},{.type = "229"},{.type = "230"},{.type = "231"},{.type = "232"},
      {.type = "233"},{.type = "234"},{.type = "235"},{.type = "236"},{.type = "237"},{.type = "238"},{.type = "239"},{.type = "240"},
      {.type = "241"},{.type = "242"},{.type = "243"},{.type = "244"},{.type = "245"},{.type = "246"},{.type = "246"},{.type = "248"},
      {.type = "249"},{.type = "250"},{.type = "251"},{.type = "252"},{.type = "253"},{.type = "254"},
    {
        .type = "IPPROTO_RAW" //255
    },
    {
        .type = "IPPROTO_MAX" 
    },
};

static struct __type_model protocol_family[256] = 
{
    {.type = "AF_UNSPEC"},{.type = "AF_UNIX" },{.type = "AF_INET" },{.type = "AF_AX25" },{.type = "AF_IPX" },
    {.type = "AF_APPLETALK"},{.type = "AF_NETROM"},{.type = "AF_BRIDGE"},{.type = "AF_ATMPVC"},{.type = "AF_X25"},
    {.type = "AF_INET6"},{.type = "AF_ROSE"},{.type = "AF_DECnet"},
    {.type = "AF_NETBEUI"},{.type = "AF_SECURITY"},{.type = "AF_KEY"},{.type = "AF_NETLINK"},{.type = "AF_PACKET"},{.type = "AF_ASH"},
    {.type = "AF_ECONET"},{.type = "AF_ATMSVC"},
    {.type = "AF_RDS"},{.type = "AF_SNA"},{.type = "AF_IRDA"},{.type = "AF_PPPOX"},{.type = "AF_WANPIPE"},{.type = "AF_LLC"},
    {.type = "AF_IB"},{.type = "AF_CAN"},
    {.type = "AF_TIPC"},{.type = "AF_BLUETOOTH"},{.type = "AF_IUCV"},{.type = "AF_RXRPC"},{.type = "AF_ISDN"},{.type = "AF_PHONET"},
    {.type = "AF_IEEE802154"},{.type = "AF_CAIF"},{.type = "AF_ALG"},{.type = "AF_NFC"},{.type = "AF_VSOCK"},{.type = "AF_MAX"}

};

static struct __type_model nlk_proto[] = 
{
    {
        .type = "NETLINK_ROUTE" //0
    },
    {
        .type = "NETLINK_UNUSED" 
    },
    {
        .type = "NETLINK_USERSOCK" 
    },
    {
        .type = "NETLINK_FIREWALL" 
    },
    {
        .type = "NETLINK_SOCK_DIAG" 
    },
    {
        .type = "NETLINK_NFLOG" //5
    },
    {
        .type = "NETLINK_XFRM" 
    },
    {
        .type = "NETLINK_SELINUX" 
    },
    {
        .type = "NETLINK_ISCSI" 
    },
    {
        .type = "NETLINK_AUDIT" 
    },
    {
        .type = "NETLINK_FIB_LOOKUP"  //10
    },
    {
        .type = "NETLINK_CONNECTOR" 
    },
    {
        .type = "NETLINK_NETFILTER" 
    },
    {
        .type = "NETLINK_IP6_FW" 
    },
    {
        .type = "NETLINK_DNRTMSG" //14
    },
    {
        .type = "NETLINK_KOBJECT_UEVENT" 
    },
    {
        .type = "NETLINK_GENERIC" 
    },
    {
        .type = "NETLINK_NO"  //17 no netlink
    },
    {
        .type = "NETLINK_SCSITRANSPORT" 
    },
    {
        .type = "NETLINK_ECRYPTFS" 
    },
    {
        .type = "NETLINK_RDMA" 
    },
    {
        .type = "NETLINK_CRYPTO" 
    },
    {
        .type = "NETLINK_INET_DIAG"  //21
    },
};


#define IPPROTO_HIP 139
static void jkfree_skb(struct sk_buff *skb)
{
        struct ethhdr *eh   = NULL;
	struct iphdr  *ih   = NULL;
	struct ipv6hdr *ih6 = NULL;
	struct tcphdr *th   = NULL;
	struct arphdr *ah   = NULL;
	struct icmphdr *imh = NULL;
	struct igmphdr *igh = NULL;
	struct nlmsghdr *nh      = NULL;
	struct sock *sk          = NULL;
	struct netlink_sock *nlk = NULL;
	struct task_struct  *c   = NULL;
	struct dst_entry    *dst = NULL;
	struct rtable       *rt  = NULL;
	//pid_t                pid = -1;
	int err			 = 0;
	
       
	if (unlikely(!skb))
	    goto out;

        
        
        
 	eh = eth_hdr(skb);
        if (eh == NULL)
            goto out;
	sk = skb->sk;
        switch (ntohs(skb->protocol)) {
            case ETH_P_IP:
	        ih  = ip_hdr(skb);
		dst = skb_dst(skb);
		if (dst) {
		    err =  dst->error;
		}
		// skb->protocol: ETH_P_IP....,if_ether.h; skb->pkt_type: PACKET_BROADCAST...., if_packet.h
                switch (ih->protocol) {
                    case IPPROTO_UDP: // in_interrupt()
/*
		        sk = skb->sk;
			pid = -1;
		        if (sk && sk->sk_peer_pid) {
			    pid = pid_nr(sk->sk_peer_pid);
			}
*/
                        th = tcp_hdr(skb);
			//if (ntohs(th->dest) != 137)
		            printk("UDP(%s:0x%x:%d): ip: %pI4:%d<=%pI4:%d err=%d\n", 
                                pkt_type[skb->pkt_type].type, ntohs(skb->protocol), ih->protocol,
                                &ih->daddr, ntohs(th->dest), &ih->saddr, ntohs(th->source), err);
/*
		        printk("UDP(%s:0x%x:%d:%d): mac: %pM<=%pM ip: %pI4:%d<=%pI4:%d\n", 
                            pkt_type[skb->pkt_type], ntohs(skb->protocol), ih->protocol, ntohs(skb->inner_protocol), eh->h_dest, eh->h_source,
                            &ih->daddr, ntohs(th->dest), &ih->saddr, ntohs(th->source));
*/
			break;
                    case IPPROTO_TCP:
                        th = tcp_hdr(skb);
		        printk("TCP(%s:0x%x:%d): ip: %pI4:%d<=%pI4:%d err=%d\n", 
                            pkt_type[skb->pkt_type].type, ntohs(skb->protocol), ih->protocol,
                            &ih->daddr, ntohs(th->dest), &ih->saddr, ntohs(th->source), err);
		//dump_stack();
			break;
                    case IPPROTO_ICMP:
			imh = icmp_hdr(skb);
			//if(!IS_ERR(ih) && !IS_ERR(imh)) 
			if(!IS_ERR(imh)) {
		            printk("ICMP(%s:0x%x:%d): mac: %pM<=%pM ip: %pI4<=%pI4 icmp_type=%d icmp_code=%d err=%d\n", 
                                    pkt_type[skb->pkt_type].type, ntohs(skb->protocol), ih->protocol, eh->h_dest, eh->h_source, 
                                    &ih->daddr, &ih->saddr, imh->type, imh->code, err);
			} else {
		            printk("ICMP(%s:0x%x:%d): mac: %pM<=%pM ip: %pI4<=%pI4 bad_icmp=%pK %ld\n", 
                                    pkt_type[skb->pkt_type].type, ntohs(skb->protocol), ih->protocol, eh->h_dest, eh->h_source, 
                                    &ih->daddr, &ih->saddr, imh, PTR_ERR(imh));
			}
			break;
                    case IPPROTO_IGMP:
			igh = igmp_hdr(skb);
			if (!IS_ERR(igh)) {
		            printk("IGMP(%s:0x%x:%d): mac: %pM<=%pM ip: %pI4<=%pI4 igmp_type=%d igmp_code=%d err=%d\n", 
                                    pkt_type[skb->pkt_type].type, ntohs(skb->protocol), ih->protocol, eh->h_dest, eh->h_source, 
                                    &ih->daddr, &ih->saddr, igh->type, igh->code, err);
			} else {
		            printk("IGMP(%s:0x%x:%d): mac: %pM<=%pM ip: %pI4<=%pI4 errno=%ld err=%d\n", 
                                    pkt_type[skb->pkt_type].type, ntohs(skb->protocol), ih->protocol, eh->h_dest, eh->h_source, 
                                    &ih->daddr, &ih->saddr, PTR_ERR(igh), err);
			}
			break;
                    case IPPROTO_HIP: 
		        printk("HIP(%s:0x%x:%d): mac: %pM<=%pM type=0x%x %pI4<=%pI4 err=%d\n", 
                                pkt_type[skb->pkt_type].type, ntohs(skb->protocol), ih->protocol, eh->h_dest, eh->h_source, 
                                ntohs(eh->h_proto), &ih->daddr, &ih->saddr, err);
			break;
                    default:
		        printk("IPV4_Unknown(%s:0x%x:%s): mac: %pM<=%pM type=0x%x %pI4<=%pI4 err=%d\n", 
                            pkt_type[skb->pkt_type].type, ntohs(skb->protocol), inet_proto[ih->protocol].type, eh->h_dest, eh->h_source, 
                            ntohs(eh->h_proto), &ih->daddr, &ih->saddr, err);
			
		dump_stack();
			break;
                } //switch
		
		break;
            case ETH_P_ARP:
		    ah = arp_hdr(skb);	// ah->ar_op: ARPOP_REQUEST..., if_arp.h
		    if (ntohs(ah->ar_pro) == ETH_P_IP) {
		        printk("ARP(%s:0x%x): mac: %pM<=%pM type=0x%x hwtype=%d proto=0x%x opcode=%d\n", 
                            pkt_type[skb->pkt_type].type, ntohs(skb->protocol), eh->h_dest, eh->h_source, ntohs(eh->h_proto),
                            ntohs(ah->ar_hrd) ,ntohs(ah->ar_pro), ntohs(ah->ar_op));
		    } else {
		        printk("ARP(%s:0x%x): mac: %pM<=%pM type=0x%x hwtype=%d proto=0x%x opcode=%d\n", 
                            pkt_type[skb->pkt_type].type, ntohs(skb->protocol), eh->h_dest, eh->h_source, ntohs(eh->h_proto),
                            ntohs(ah->ar_hrd) ,ntohs(ah->ar_pro), ntohs(ah->ar_op));
		    }
		break;
            case ETH_P_RARP:
		    ah = arp_hdr(skb);	// ah->ar_op: ARPOP_REQUEST..., if_arp.h
		   
		    printk("RARP(%s:0x%x): mac: %pM<=%pM type=0x%x hwtype=%d proto=0x%x opcode=%d\n", 
                        pkt_type[skb->pkt_type].type, ntohs(skb->protocol), eh->h_dest, eh->h_source, ntohs(eh->h_proto),
                        ntohs(ah->ar_hrd) ,ntohs(ah->ar_pro), ntohs(ah->ar_op));
		break;
            case ETH_P_IPV6:
		    ih6 = ipv6_hdr(skb);
		    printk("IPV6(%s:0x%x): mac: %pM<=%pM h_proto=0x%x ipv6: %pI6<=%pI6 nexthdr=%d\n", 
                        pkt_type[skb->pkt_type].type, ntohs(skb->protocol), eh->h_dest, eh->h_source, ntohs(eh->h_proto),
                        &ih6->daddr, &ih6->saddr, ih6->nexthdr);
		break;
            case ETH_P_8021Q:
		    printk("8021Q(%s:0x%x): mac: %pM<=%pM h_proto=0x%x\n", 
                        pkt_type[skb->pkt_type].type, ntohs(skb->protocol), eh->h_dest, eh->h_source, ntohs(eh->h_proto)
                        );
		break;
            case ETH_P_8021AD:
		    printk("8021AD(%s:0x%x): mac: %pM<=%pM h_proto=0x%x\n", 
                        pkt_type[skb->pkt_type].type, ntohs(skb->protocol), eh->h_dest, eh->h_source, ntohs(eh->h_proto)
                        );
		break;
	    default ://!sock_owned_by_user(skb->sk)
		c = current;
		if (sk && c->cred) {
		  //  printk("uid=%d sk_protocol=%d sk_type=%x sk_family=%d %d\n", 
                  //      current->cred->uid, sk->sk_protocol, sk->sk_type, sk->sk_family, in_interrupt()); 
                       // sock_i_uid(skb->sk), skb->sk->sk_protocol, skb->sk->sk_type, skb->sk->sk_family, in_interrupt()); 

		    //if ((sk->sk_family == PF_NETLINK) && (skb->len >= sizeof(struct nlmsghdr))) 
		    if ((sk->sk_family == PF_NETLINK)) {
			//nlk = nlk_sk(sk);
		        nh = nlmsg_hdr(skb);
		        //if (nh->nlmsg_len < NLMSG_HDRLEN || skb->len < nh->nlmsg_len) {
			//    goto out1;
			//}
			//  
		        printk("PF_NETLINK(%s:0x%x): pid=%d uid=%u execname=%s nlmsg_pid=%d nlmsg_type=0x%x sk_protocol=%s sk_type=%s sk_family=%s %lu\n",
                            pkt_type[skb->pkt_type].type, ntohs(skb->protocol), c->pid, c->cred->uid.val, 
                            c->comm, nh->nlmsg_pid, nh->nlmsg_type, 
                            nlk_proto[sk->sk_protocol].type, sk_type[sk->sk_type].type, protocol_family[sk->sk_family].type, in_interrupt());
			//dump_stack();
		    } else if (sk->sk_family == PF_UNIX) {
				//sk->sk_family == PF_UNIX, PF_XXXXXXXXXXXX....etc
		        printk("PF_UNIX(%s:0x%x): pid=%d uid=%u execname=%s sk_protocol=%d sk_type=%s sk_family=%s %lu\n", 
                            pkt_type[skb->pkt_type].type, ntohs(skb->protocol), c->pid, c->cred->uid.val, 
                            c->comm, sk->sk_protocol, sk_type[sk->sk_type].type, protocol_family[sk->sk_family].type, in_interrupt()); 
			//dump_stack();
		    } else if (sk->sk_family == PF_PACKET) {
		            printk("PF_PACKET(%s:0x%x): pid=%d uid=%u execname=%s sk_protocol=%d sk_type=%s sk_family=%s \n", 
                                pkt_type[skb->pkt_type].type, ntohs(skb->protocol), c->pid, c->cred->uid.val, c->comm, 
                                sk->sk_protocol, sk_type[sk->sk_type].type, protocol_family[sk->sk_family].type); 
			//dump_stack();
		    } else {
		        printk("Unknown(%s:0x%x): pid=%d uid=%u execname=%s sk_protocol=%d sk_type=%s sk_family=%s\n",
                            pkt_type[skb->pkt_type].type, ntohs(skb->protocol), c->pid, c->cred->uid.val, 
                            c->comm, sk->sk_protocol, sk_type[sk->sk_type].type, protocol_family[sk->sk_family].type);
			//dump_stack();
		    }
		    break;
		} // if (sk)
		printk("Unknown(%s:0x%x): pid=%d uid=%u execname=%s sk=%pK dst=%pK %lu it may be netlink(no receiver)!\n",
                    pkt_type[skb->pkt_type].type, ntohs(skb->protocol), c->pid, c->cred->uid.val, c->comm,
                    skb->sk, skb_dst(skb), in_interrupt());
out1:
		//dump_stack();
		break;
	}//switch
out:
	jprobe_return();
	return;
};

static struct jprobe my_jprobe = {
	.entry			= jkfree_skb,
	.kp = {
		.symbol_name	= "kfree_skb",
	},
};

/*
static struct jprobe my_jprobe1 = {
	.entry			= jkfree_skb,
	.kp = {
		.symbol_name	= "consume_skb",
	},
};
*/
static int __init jprobe_init(void)
{
	int ret;

	ret = register_jprobe(&my_jprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	printk(KERN_INFO "Dropwatch: Planted jprobe at %p, handler addr %p\n",
	       my_jprobe.kp.addr, my_jprobe.entry);
	return 0;
}

static void __exit jprobe_exit(void)
{
	unregister_jprobe(&my_jprobe);
	printk(KERN_INFO "Dropwatch: jprobe at %p unregistered\n", my_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
