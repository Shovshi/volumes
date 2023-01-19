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

/* Ethernet Header */
struct ethheader
 {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
} ;


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

struct applicationheader
 {
    uint32_t timestamp;
    uint16_t total_length;
       union
    {
        uint16_t reserved:3,cache_flag:1,steps_flag:1,type_flag:1,status_code:10;
        uint16_t flags;
    };
    uint16_t cache_control;
    uint16_t padding;

};


void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
   FILE *file;
   file = fopen("211776356_316302934" , "a+");
   fprintf(file, "~~~~~~~~~~~\n");
   fprintf(file, "Got a packet- Details:\n");

   //we access the fields of the packet to print the relevant data
   //by find where the ip header starts and so on 
   
   struct ethheader *eth = (struct ethheader *) packet;
   struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));
   struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ethheader) + (ip->iph_ihl)*4);
   struct applicationheader *app = (struct applicationheader *) (packet + sizeof(struct ethheader ) + (ip->iph_ihl)*4 + (tcp->doff)*4);
   uint8_t *data = (uint8_t *) (packet + sizeof(struct ethheader) + (ip->iph_ihl)*4 + (tcp->doff)*4 + 12);

   app->flags = ntohs(app->flags);
   uint16_t cacheFlag = ((app->flags>>12) & 1);
   uint16_t stepsFlag = ((app->flags>>11) & 1);
   uint16_t typeFlag = ((app->flags>>10) & 1);

   if (tcp->psh != 1)
        return;

   fprintf(file, "source ip: %s\n" , inet_ntoa(ip->iph_sourceip));
   fprintf(file, "destination ip: %s\n" , inet_ntoa(ip->iph_destip));
   fprintf(file, "source_port: %hu\n" , ntohs(tcp->source));
   fprintf(file, "destination_port: %hu\n" , ntohs(tcp->dest));
   fprintf(file, "timestamp: %u\n" , ntohl(app->timestamp));
   fprintf(file, "total_length: %hu\n" ,ntohs(app->total_length));
   fprintf(file, "cache_flag: %hu\n" ,cacheFlag);
   fprintf(file, "steps_flag: %hu\n" ,stepsFlag);
   fprintf(file, "type_flag: %hu\n" ,typeFlag);
   fprintf(file, "status_code: %hu\n" ,app->status_code);
   fprintf(file, "cache_control: %hu\n" , ntohs(app->cache_control));

   //print the data in hexa 
   for (int i = 0; i < app->total_length; i++)
  {
    if (!(i & 15))
      fprintf(file, "\n%04X: ", i);

    fprintf(file, "%02X ", ((unsigned char *)data)[i]);
  }

  fprintf(file, "\n------------------\n");

  fclose(file); // Close fd
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name lo
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);   
   

  pcap_close(handle);  //Close the handle 
  return 0;
}