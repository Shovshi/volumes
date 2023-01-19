#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int id;     //Used for identifying request
  unsigned short int seq;    //Sequence number
};

/* IP Header */
struct ipheader 
{
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
} ;

//we send out the new packet afrer spoofing the ip
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}


unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}



void got_packet_send(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

   //we access the fields of the packet to print the relevant data
   //by find where the ip header starts and so on 

   struct ipheader *ip = (struct ipheader *) (packet + 16);
   struct icmpheader *icmp = (struct icmpheader *) (packet + 16 + sizeof(struct ipheader));
    

  //we want to sniff only the request packets
  if(icmp->icmp_type == 8)
  {

    char new_packet [1500];
    memset(new_packet, 0, 1500);

    //construct the ip
    struct ipheader *newIP = (struct ipheader *) (new_packet + 14);
    newIP->iph_ver=ip->iph_ver;
    newIP->iph_ihl=ip->iph_ihl;
    newIP->iph_ttl=ip->iph_ttl;
    newIP->iph_protocol = IPPROTO_ICMP;
    //swapping between the ip source and dest 
    newIP->iph_destip= ip->iph_sourceip; 
    newIP->iph_sourceip = ip->iph_destip;
    newIP->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    struct icmpheader *newICMP = (struct icmpheader *) (new_packet + 14 + sizeof(struct ipheader));
    newICMP->icmp_type = 0;
    newICMP->icmp_chksum = 0;
    newICMP->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(icmp));
    newICMP->id = icmp->id;
    newICMP->seq = icmp->seq;

    send_raw_ip_packet(newIP);

  }

  }


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name lo
  handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet_send, NULL);   
   

  pcap_close(handle);  //Close the handle 
  return 0;
}