/*
  To compile:

    gcc -o nfqfw nfqfw.c -lnetfilter_queue -lcrypto


  Examples of some IPTables rules:

    iptables -A INPUT  -s <remote-ip-address>/32 -j NFQUEUE --queue-num 0
    iptables -A OUTPUT -d <remote-ip-address>/32 -j NFQUEUE --queue-num 0

    iptables -t mangle -A INPUT  -s <remote-ip-address>/32 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
    iptables -t mangle -A OUTPUT -d <remote-ip-address>/32 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400

    (if desired, use <remote-network-address>/<remote-network-cidr-netmask> above, or 0.0.0.0/0 for ALL traffic)

    NOTE: It's important to set mss (maximum segment size) to a small-enough value so that the modified IP packets
    don't exceed the minimum MTU (typically 1500) in the network path between client and server hosts.  The HMAC signatures
    used by this NFQUEUE processor add 16 bytes to the payload of ALL packets, so it's important to make extra room for them
    in order to avoid fragmentation of packets, especially for heavy TCP traffic.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>

/* # include <libnetfilter_queue/pktbuff.h> (broken) */
#ifndef _PKTBUFF_H_
#define _PKTBUFF_H_

struct pkt_buff;

struct pkt_buff *pktb_alloc(int family, void *data, size_t len, size_t extra);

void           pktb_free( struct pkt_buff *pktb );
uint8_t       *pktb_data( struct pkt_buff *pktb );
uint32_t       pktb_len(  struct pkt_buff *pktb );

void pktb_push( struct pkt_buff *pktb, unsigned int len );
void pktb_pull( struct pkt_buff *pktb, unsigned int len );
void pktb_put(  struct pkt_buff *pktb, unsigned int len );
void pktb_trim( struct pkt_buff *pktb, unsigned int len );

unsigned int   pktb_tailroom(         struct pkt_buff *pktb );
uint8_t       *pktb_mac_header(       struct pkt_buff *pktb );
uint8_t       *pktb_network_header(   struct pkt_buff *pktb );
uint8_t       *pktb_transport_header( struct pkt_buff *pktb );

int pktb_mangle(struct pkt_buff *pkt, unsigned int dataoff, unsigned int match_offset, unsigned int match_len, const char *rep_buffer, unsigned int rep_len);

// bool pktb_mangled(const struct pkt_buff *pktb);
#endif

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <string.h>
#include <openssl/sha.h>

#include <sys/types.h>
#include <fcntl.h>

#include <getopt.h>

char *hmacSecret;

unsigned int  verbose;
unsigned int  wanMode;
char          hmacSecretFilename[256];
unsigned int  hmacLengthInBytes;
unsigned int  queueNumber;

struct packet_main_info {
  u_int32_t    id;
  unsigned int hook;
  unsigned int indev;
  unsigned int outdev;
};

void readHmacSecretFromFile() {
  int hmacFd = -1;
  char buf;

  hmacFd = open(hmacSecretFilename, O_RDONLY);

  if (hmacFd < 0) {
    printf("\n  ERROR: Unable to open file %s\n\n", hmacSecretFilename);
    exit(1);
  }

  int i = 0;
  while (read(hmacFd, &buf, 1)) {
    i++;
    if (i == 1) {
      hmacSecret = (char *)malloc(i * sizeof(char));
    }
    else if (i > 1) {
      hmacSecret = realloc(hmacSecret, i * sizeof(char));
    }
    hmacSecret[i-1] = buf;
  }
  i++;
  hmacSecret = realloc(hmacSecret, i * sizeof(char));
  hmacSecret[i-1] = '\0';

  close(hmacFd);

  if (verbose >= 2) {
    printf("########## BEGIN HMAC SECRET FILE CONTENTS ##########\n");
    printf("%s", hmacSecret);
    printf("########## END   HMAC SECRET FILE CONTENTS ##########\n");
  }
}

void calc_sha256_hash_bytes(int dataLength, char *dataToHash, char hashAsBytes[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX sha256ctx;
  SHA256_Init(&sha256ctx);
  SHA256_Update(&sha256ctx, dataToHash, dataLength);
  SHA256_Update(&sha256ctx, hmacSecret, strlen(hmacSecret));
  SHA256_Final(hashAsBytes, &sha256ctx);
}

void hex_dump_bytes_to_hash(char *toHash, unsigned short dataLength) {
  printf("BEGIN HEX DUMP OF toHash\n");
  for (int i=0; i<dataLength; i++) {
    unsigned char uChar = *((unsigned char *)(((void *)toHash) + i));
    printf("%02x ", uChar);
    if (((i+1) % 16) == 0) {
      printf("\n");
    }
    else if (((i+1) % 8) == 0) {
      printf("  ");
    }
  }
  printf("\n");
  printf("END HEX DUMP OF toHash\n");
}

void hex_dump_ip_packet(
  struct iphdr *ip,
  unsigned short ipPacketTotalLength,
  unsigned short ihlOffset,
  unsigned short dataOffset,
  char *packetDescription) {
  printf("BEGIN HEX DUMP OF %s PACKET\n", packetDescription);
  for (int i=0; i<ipPacketTotalLength; i++) {
    unsigned char uChar = *((unsigned char *)(((void *)ip) + i));
    printf("%02x ", uChar);
    if (((i+1) % 4) == 0) {
      printf("\n");
    }
    if ((i+1) == 4*ihlOffset) {
      printf("-----------\n");
    }
    if ((i+1) == 4*(ihlOffset + dataOffset)) {
      printf("-----------\n");
    }
  }
  printf("\n");
  printf("END HEX DUMP OF %s PACKET\n", packetDescription);
}

void display_sha256_hash(char *hashAsBytes) {
  printf("BEGIN SHA256 HASH\n");
  for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
    unsigned char uChar = *((unsigned char *)(((void *)hashAsBytes) + i));
    printf("%02x", uChar);
  }
  printf("\n");
  printf("END SHA256 HASH\n");
}

char *buildToHash(int length, struct iphdr *ip, unsigned short ihlOffset, unsigned char isIcmp, unsigned char isTcp, unsigned char isUdp) {
  char *toHash = (char *)malloc(length * sizeof(char));
  memset(toHash, '\0', length);
  if (verbose >= 2) { printf("toHash array length = %d\n", length); }
  for (int i=0; i<length; i++) {
    if (
         (
           !wanMode ||
           (
             (i !=  1) && (i !=  8) &&                                   // IP tos, ttl
             (i != 12) && (i != 13) && (i != 14) && (i != 15) &&         // IP src addr
             (i != 16) && (i != 17) && (i != 18) && (i != 19) &&         // IP dst addr
             (
               !isTcp ||
               (
                 (i != 4*ihlOffset +  0) && (i != 4*ihlOffset +  1) &&   // TCP src port
                 (i != 4*ihlOffset +  2) && (i != 4*ihlOffset +  3)      // TCP dst port
               )
             ) &&
             (
               !isUdp ||
               ((i != 4*ihlOffset + 6) && (i != 4*ihlOffset + 7))        // UDP checksum
             ) &&
             (
               !isIcmp ||
               ((i != 4*ihlOffset + 6) && (i != 4*ihlOffset + 7))        // ICMP seq num
             )
           )
         ) &&
         (
           !isIcmp ||
           ((i != 4*ihlOffset + 2) && (i != 4*ihlOffset + 3))            // ICMP checksum
         ) &&
         (
           !isTcp ||
           ((i != 4*ihlOffset + 16) && (i != 4*ihlOffset + 17))          // TCP checksum
         ) &&
         (i != 10) && (i != 11)                                          // IP checksum
       ) {
      toHash[i] = ((char *)ip)[i];
    }
  }

  return toHash;
}

unsigned short compute_udp_checksum(struct iphdr *ip, struct udphdr *udp, unsigned short ipPacketTotalLength) {
  unsigned short ckMax         = 65535;
  unsigned int   myChecksumInt = 0;
  unsigned short myChecksum    = 0;
  unsigned short cksumData     = 0;

  // IPv4 Pseudo-Header Source IPv4 Address (bytes 1 and 2)
  cksumData = *((unsigned short *)((void *)ip + 12));
  if (verbose >= 2) { printf("computing myChecksum: cksumData = %02x %02x\n", (cksumData & 0xFF00) >> 8, cksumData & 0x00FF); }
  myChecksumInt += cksumData;
  if (myChecksumInt > ckMax) {
      myChecksumInt -= ckMax;
  }

  // IPv4 Pseudo-Header Source IPv4 Address (bytes 3 and 4)
  cksumData = *((unsigned short *)((void *)ip + 14));
  if (verbose >= 2) { printf("computing myChecksum: cksumData = %02x %02x\n", (cksumData & 0xFF00) >> 8, cksumData & 0x00FF); }
  myChecksumInt += cksumData;
  if (myChecksumInt > ckMax) {
      myChecksumInt -= ckMax;
  }

  // IPv4 Pseudo-Header Destination IPv4 Address (bytes 1 and 2)
  cksumData = *((unsigned short *)((void *)ip + 16));
  if (verbose >= 2) { printf("computing myChecksum: cksumData = %02x %02x\n", (cksumData & 0xFF00) >> 8, cksumData & 0x00FF); }
  myChecksumInt += cksumData;
  if (myChecksumInt > ckMax) {
      myChecksumInt -= ckMax;
  }

  // IPv4 Pseudo-Header Destination IPv4 Address (bytes 3 and 4)
  cksumData = *((unsigned short *)((void *)ip + 18));
  if (verbose >= 2) { printf("computing myChecksum: cksumData = %02x %02x\n", (cksumData & 0xFF00) >> 8, cksumData & 0x00FF); }
  myChecksumInt += cksumData;
  if (myChecksumInt > ckMax) {
      myChecksumInt -= ckMax;
  }

  // IPv4 Pseudo-Header Zeros and Protocol
  cksumData = *((unsigned short *)((void *)ip + 8));
  cksumData = cksumData & 0xFF00;
  if (verbose >= 2) { printf("computing myChecksum: cksumData = %02x %02x\n", (cksumData & 0xFF00) >> 8, cksumData & 0x00FF); }
  myChecksumInt += cksumData;
  if (myChecksumInt > ckMax) {
      myChecksumInt -= ckMax;
  }

  // IPv4 Pseudo-Header UDP Length
  cksumData = *((unsigned short *)((void *)ip + 24));
  if (verbose >= 2) { printf("computing myChecksum: cksumData = %02x %02x\n", (cksumData & 0xFF00) >> 8, cksumData & 0x00FF); }
  myChecksumInt += cksumData;
  if (myChecksumInt > ckMax) {
      myChecksumInt -= ckMax;
  }

  for (int i=0; i<(ipPacketTotalLength - 20)/2; i++) {
    cksumData = *((unsigned short *)((void *)udp + 2*i));
    if (i != 3) {
      if (verbose >= 2) { printf("computing myChecksum: cksumData = %02x %02x\n", (cksumData & 0xFF00) >> 8, cksumData & 0x00FF); }
      myChecksumInt += cksumData;
    }
    if (myChecksumInt > ckMax) {
      myChecksumInt -= ckMax;
    }
  }
  if (ipPacketTotalLength % 2 == 1) {
    cksumData = *((unsigned char *)((void *)udp + ipPacketTotalLength - 20 - 1));
    if (verbose >= 2) { printf("computing myChecksum: cksumData = %02x %02x\n", (cksumData & 0xFF00) >> 8, cksumData & 0x00FF); }
    myChecksumInt += cksumData;
    if (myChecksumInt > ckMax) {
      myChecksumInt -= ckMax;
    }
  }
  myChecksumInt = ((int)ckMax) - myChecksumInt;
  myChecksum = (unsigned short) myChecksumInt;

  return myChecksum;
}

static struct packet_main_info print_pkt (struct nfq_data *tb) {
  struct packet_main_info pktMainInfo;
  pktMainInfo.id     = 0;
  pktMainInfo.hook   = 0;
  pktMainInfo.indev  = 0;
  pktMainInfo.outdev = 0;

  int id = 0;
  struct nfqnl_msg_packet_hdr *ph;
  struct nfqnl_msg_packet_hw *hwph;
  u_int32_t mark, interfaceInfo;
  int ret;
  char *data;

  if (verbose >= 1) {
    printf("####################################################################################\n");
  }

  ph = nfq_get_msg_packet_hdr(tb);
  if (ph) {
    id = ntohl(ph->packet_id);
    if (verbose >= 1) {
      printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }
    pktMainInfo.id   = id;
    pktMainInfo.hook = ph->hook;
  }

  hwph = nfq_get_packet_hw(tb);
  if (hwph) {
    int i, hlen = ntohs(hwph->hw_addrlen);

    if (verbose >= 1) { printf("hw_src_addr="); }
    for (i=0; i<hlen-1; i++) {
      if (verbose >= 1) { printf("%02x:", hwph->hw_addr[i]); }
    }
    if (verbose >= 1) { printf("%02x ", hwph->hw_addr[hlen-1]); }
  }

  mark = nfq_get_nfmark(tb);
  if (mark) {
    if (verbose >= 1) { printf("mark=%u ", mark); }
  }

  interfaceInfo = nfq_get_indev(tb);
  if (interfaceInfo) {
    if (verbose >= 1) { printf("indev=%u ", interfaceInfo); }
    pktMainInfo.indev = interfaceInfo;
  }

  interfaceInfo = nfq_get_outdev(tb);
  if (interfaceInfo) {
    if (verbose >= 1) { printf("outdev=%u ", interfaceInfo); }
    pktMainInfo.outdev = interfaceInfo;
  }
  interfaceInfo = nfq_get_physindev(tb);
  if (interfaceInfo) {
    if (verbose >= 1) { printf("physindev=%u ", interfaceInfo); }
  }

  interfaceInfo = nfq_get_physoutdev(tb);
  if (interfaceInfo) {
    if (verbose >= 1) { printf("physoutdev=%u ", interfaceInfo); }
  }

  ret = nfq_get_payload(tb, (unsigned char **)&data);
  if (ret >= 0) {
    if (verbose >= 1) { printf("payload_len=%d ", ret); }
  }

  if (verbose >= 1) { fputc('\n', stdout); }

  return pktMainInfo;
}


static int processPacketCallback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
  struct packet_main_info pktMainInfo = print_pkt(nfa);
  u_int32_t     id     = pktMainInfo.id;
  unsigned int  hook   = pktMainInfo.hook;
  unsigned int  indev  = pktMainInfo.indev;
  unsigned int  outdev = pktMainInfo.outdev;

  if (verbose >= 1) {
    printf("entering processPacketCallback: id = %d, hook = %d, indev = %d, outdev = %d\n",
      id, hook, indev, outdev);
  }

  char acceptPacket = 0;

  int ihlOffset  = 0;  // Number of 4-byte double-words
  int dataOffset = 0;  // Number of 4-byte double-words

  unsigned char *rawData = NULL;
  int len = nfq_get_payload(nfa, &rawData);
  struct pkt_buff * pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
  struct iphdr *ip = nfq_ip_get_hdr(pkBuff);

  ihlOffset = ip->ihl;

  unsigned short totLen = ip->tot_len;
  unsigned short ipPacketTotalLength = ((totLen & 0xFF00) >> 8) | ((totLen & 0x00FF) << 8);

  struct in_addr src_addr;
  src_addr.s_addr = ip->saddr;
  char sAddrStr[16];
  memset(sAddrStr, '\0', 16);
  strncpy(sAddrStr, inet_ntoa(src_addr), 15);

  struct in_addr dst_addr;
  dst_addr.s_addr = ip->daddr;
  char dAddrStr[16];
  memset(dAddrStr, '\0', 16);
  strncpy(dAddrStr, inet_ntoa(dst_addr), 15);

  struct tcphdr *tcp;
  struct udphdr *udp;

  if (ip->protocol == IPPROTO_ICMP) {
    dataOffset = 2;
  }
  else if (ip->protocol == IPPROTO_TCP) {
    nfq_ip_set_transport_header(pkBuff, ip);
    tcp = (struct tcphdr *)((unsigned long)nfq_tcp_get_hdr(pkBuff));

    if (tcp != NULL) {
      dataOffset = tcp->doff;
    }
  }
  else if (ip->protocol == IPPROTO_UDP) {
    nfq_ip_set_transport_header(pkBuff, ip);
    udp = (struct udphdr *)((unsigned long)nfq_udp_get_hdr(pkBuff));

    if (udp != NULL) {
      dataOffset = 2;
    }
  }

  if (verbose >= 2) {
    hex_dump_ip_packet(ip, ipPacketTotalLength, ihlOffset, dataOffset, "IP");
  }

  if (verbose >= 2) {
    printf("IP Header: iphdrOffset    = %lu\n", ((unsigned long)ip) - ((unsigned long)pkBuff));
    printf("IP Header: version        = %d\n", ip->version);
    printf("IP Header: ihl            = %d\n", ip->ihl);
    printf("IP Header: tos            = %d\n", ip->tos);
    printf("IP Header: tot_len        = %d\n", ipPacketTotalLength);
    printf("IP Header: flags/frag_off = %d\n", ip->frag_off);
    printf("IP Header: ttl            = %d\n", ip->ttl);
    printf("IP Header: protocol       = %d\n", ip->protocol);
    printf("IP Header: checksum       = %d\n", ip->check);
    printf("IP Header: saddr          = %s\n", sAddrStr);
    printf("IP Header: daddr          = %s\n", dAddrStr);
  }

  char hashAsBytes[SHA256_DIGEST_LENGTH];
  memset(hashAsBytes, '\0', SHA256_DIGEST_LENGTH);

  if (ip->protocol == IPPROTO_ICMP) {
    if (verbose >= 2) { printf("This is an ICMP packet.\n"); }
    void * icmpHdrPtr = ((void *)ip) + 4*ihlOffset;
    unsigned char  icmpType = *((unsigned char *)icmpHdrPtr);
    unsigned char  icmpCode = *((unsigned char *)(icmpHdrPtr + 1));

    if ((icmpType == 8) || (icmpType == 0)) { // For now, we support only echo-request or echo-response ICMP types
      if ((outdev == 0) && (indev > 0)) {
        char *toHash = buildToHash(ipPacketTotalLength - hmacLengthInBytes, ip, ihlOffset, 1, 0, 0);
        if (verbose >= 2) { hex_dump_bytes_to_hash(toHash, ipPacketTotalLength - hmacLengthInBytes); }
        calc_sha256_hash_bytes(ipPacketTotalLength - hmacLengthInBytes, toHash, hashAsBytes);
        free(toHash);

        if (verbose >= 2) { display_sha256_hash(hashAsBytes); }

        int j = 0;
        int hashMatchCount = 0;
        for (int i=ipPacketTotalLength-hmacLengthInBytes; i<ipPacketTotalLength; i++) {
          unsigned char plChar = *((unsigned char *)(((void *)ip) + i));
          unsigned char hbChar = *((unsigned char *)(((void *)hashAsBytes) + j));
          if (verbose >= 2) { printf("%2d   %02x   %02x\n", j, plChar, hbChar); }
          if (plChar == hbChar) {
            hashMatchCount++;
          }
          j++;
        }
        if (verbose >= 2) { printf("hashMatchCount = %d\n", hashMatchCount); }
        if (hashMatchCount == hmacLengthInBytes) {
          acceptPacket = 1;
        }
      }
      else if ((indev == 0) && (outdev > 0)) {
        pktb_free(pkBuff);
        pkBuff = (struct pkt_buff *)((unsigned long)pktb_alloc(AF_INET, rawData, len + hmacLengthInBytes, 0x1000));
        ip = (struct iphdr *)((unsigned long)nfq_ip_get_hdr(pkBuff));
        icmpHdrPtr = ((void *)ip) + 4*ihlOffset;

        // Update the total length field in the IP header
        unsigned short ipPacketTotalLength2 = ipPacketTotalLength + hmacLengthInBytes;
        if (verbose >= 2) { printf("NEW tot_len = %d\n", ipPacketTotalLength2); }
        unsigned short totLen2 = ((ipPacketTotalLength2 & 0xFF00) >> 8) | ((ipPacketTotalLength2 & 0x00FF) << 8);
        ip->tot_len = totLen2;

        char *toHash = buildToHash(ipPacketTotalLength, ip, ihlOffset, 1, 0, 0);
        if (verbose >= 2) { hex_dump_bytes_to_hash(toHash, ipPacketTotalLength); }
        calc_sha256_hash_bytes(ipPacketTotalLength, toHash, hashAsBytes);
        free(toHash);

        if (verbose >= 2) { display_sha256_hash(hashAsBytes); }
        int j = 0;
        for (int i=ipPacketTotalLength; i<ipPacketTotalLength2; i++) {
          *((unsigned char *)(((void *)ip) + i)) = hashAsBytes[j];
          j++;
        }

        if (verbose >= 2) {
          hex_dump_ip_packet(ip, ipPacketTotalLength + hmacLengthInBytes, ihlOffset, dataOffset, "MODIFIED (APPENDED) ICMP/IP");
        }
      }
      else {
        printf("WARNING: Problem encountered while processing an ICMP/IP packet.\n");
      }

      unsigned short icmpChecksum   = *((unsigned short *)(icmpHdrPtr + 2));
      unsigned short icmpIdentifier = *((unsigned short *)(icmpHdrPtr + 4));
      unsigned short icmpSeqNumber  = *((unsigned short *)(icmpHdrPtr + 6));

      if (verbose >= 2) {
        printf("ICMP Header: icmpType       = %d\n", icmpType);
        printf("ICMP Header: icmpCode       = %d\n", icmpCode);
        printf("ICMP Header: icmpChecksum   = %d\n", icmpChecksum);
        printf("ICMP Header: icmpIdentifier = %d\n", ((icmpIdentifier & 0xFF00) >> 8) | ((icmpIdentifier & 0x00FF) << 8));
        printf("ICMP Header: icmpSeqNumber  = %d\n", ((icmpSeqNumber  & 0xFF00) >> 8) | ((icmpSeqNumber  & 0x00FF) << 8));
      }

      if ((indev == 0) && (outdev > 0)) {
        ipPacketTotalLength += hmacLengthInBytes;
        if (verbose >= 2) { printf("NEW tot_len = %d\n", ipPacketTotalLength); }
        totLen = ((ipPacketTotalLength & 0xFF00) >> 8) | ((ipPacketTotalLength & 0x00FF) << 8);
        ip->tot_len = totLen;

        unsigned short ckMax         = 65535;
        unsigned int   myChecksumInt = 0;
        unsigned short myChecksum    = 0;
        unsigned short cksumData     = 0;
        for (int i=0; i<(ipPacketTotalLength - 20)/2; i++) {
          cksumData = *((unsigned short *)(icmpHdrPtr + 2*i));
          if (i != 1) {
            myChecksumInt += cksumData;
          }
          if (myChecksumInt > ckMax) {
            myChecksumInt -= ckMax;
          }
        }
        if (ipPacketTotalLength % 2 == 1) {
          cksumData = *((unsigned char *)((void *)icmpHdrPtr + ipPacketTotalLength - 20 - 1));
          myChecksumInt += cksumData;
          if (myChecksumInt > ckMax) {
            myChecksumInt -= ckMax;
          }
        }
        myChecksumInt = ((int)ckMax) - myChecksumInt;
        myChecksum = (unsigned short) myChecksumInt;
        if (verbose >= 2) { printf("myChecksum           = %d\n", myChecksum); }

        // update the checksum to accommodate custom data
        *((unsigned short *)(icmpHdrPtr + 2)) = myChecksum;
        acceptPacket = 1;
      }
      else if ((outdev == 0) && (indev > 0)) {
      }
      else {
        printf("WARNING: Problem encountered while processing an ICMP/IP packet.\n");
      }
    }
    else {
      printf("WARNING: Unsupported icmpType = %d\n", icmpType);
      acceptPacket = 0;
    }
  }
  else if (ip->protocol == IPPROTO_TCP) {
    if (tcp != NULL) {
      unsigned short thSport = tcp->th_sport;
      unsigned short thDport = tcp->th_dport;
      unsigned int   thSeq   = tcp->th_seq;
      unsigned int   thAck   = tcp->th_ack;

      void *payload = nfq_tcp_get_payload(tcp, pkBuff);
      unsigned int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);
      payloadLen -= 4 * tcp->th_off;
      if (verbose >= 2) { printf("payloadLen = %u\n", payloadLen); }

      if (verbose >= 2) {
        printf("TCP Header: tcphdrOffset = %lu\n", ((unsigned long)tcp) - ((unsigned long)pkBuff));
        printf("TCP Header: th_sport     = %d\n", ((thSport & 0xFF00) >> 8) | ((thSport & 0x00FF) << 8));
        printf("TCP Header: th_dport     = %d\n", ((thDport & 0xFF00) >> 8) | ((thDport & 0x00FF) << 8));
        printf("TCP Header: th_seq       = %u\n", ((thSeq & 0xFF000000) >> 24) | ((thSeq & 0x00FF0000) >> 8) | ((thSeq & 0x0000FF00) << 8) | ((thSeq & 0x000000FF) << 24));
        printf("TCP Header: th_ack       = %u\n", ((thAck & 0xFF000000) >> 24) | ((thAck & 0x00FF0000) >> 8) | ((thAck & 0x0000FF00) << 8) | ((thAck & 0x000000FF) << 24));
        printf("TCP Header: th_flags     = %d\n", tcp->th_flags);
        printf("TCP Header: syn          = %d\n", tcp->syn);
        printf("TCP Header: ack          = %d\n", tcp->ack);
        printf("TCP Header: fin          = %d\n", tcp->fin);
        printf("TCP Header: th_off       = %d\n", tcp->th_off);
        printf("TCP Header: doff         = %d\n", tcp->doff);
        printf("TCP Header: payloadLen   = %u\n", payloadLen);
      }

      if ((payload != NULL) && (payloadLen > 0)) {
        if (verbose >= 2) {
          printf("BEGIN HEX DUMP OF TCP PAYLOAD\n");
          for (int i=0; i<payloadLen; i++) {
            unsigned char uChar = *((unsigned char *)(((void *)payload) + i));
            printf("%02x ", uChar);
            if (((i+1) % 16) == 0) {
              printf("\n");
            }
            else if (((i+1) % 8) == 0) {
              printf("  ");
            }
          }
          printf("\n");
          printf("END HEX DUMP OF TCP PAYLOAD\n");
        }

        if ((outdev == 0) && (indev > 0)) {
          char repBuff[2] = "0";
          memset(repBuff, '\0', 2);

          char *toHash = buildToHash(ipPacketTotalLength - hmacLengthInBytes, ip, ihlOffset, 0, 1, 0);
          if (verbose >= 2) { hex_dump_bytes_to_hash((char *)toHash, ipPacketTotalLength - hmacLengthInBytes); }
          calc_sha256_hash_bytes(ipPacketTotalLength - hmacLengthInBytes, (char *)toHash, hashAsBytes);
          free(toHash);
          if (verbose >= 2) { display_sha256_hash(hashAsBytes); }

          int hashMatchCount = 0;
          if (payloadLen >= hmacLengthInBytes) {
            int j = 0;
            for (int i=payloadLen-hmacLengthInBytes; i<payloadLen; i++) {
              unsigned char plChar = *((unsigned char *)(((void *)payload)     + i));
              unsigned char hbChar = *((unsigned char *)(((void *)hashAsBytes) + j));
              if (verbose >= 2) { printf("j = %2d   plChar = %02x   hbChar = %02x\n", j, plChar, hbChar); }
              if (plChar == hbChar) {
                hashMatchCount++;
              }
              j++;
            }
          }
          if (hashMatchCount == hmacLengthInBytes) {
            if (verbose >= 2) { printf("hashMatchCount = %d (good)\n", hmacLengthInBytes); }
            acceptPacket = 1;
            if (verbose >= 2) { printf("Setting acceptPacket = 1\n"); }

            int mangleRetVal = nfq_tcp_mangle_ipv4(pkBuff, payloadLen - hmacLengthInBytes, hmacLengthInBytes, repBuff, 0);
            if (verbose >= 2) { printf("mangleRetVal = %d\n", mangleRetVal); }

            ip = (struct iphdr *)((unsigned long)nfq_ip_get_hdr(pkBuff));
            totLen = ip->tot_len;
            ipPacketTotalLength = ((totLen & 0xFF00) >> 8) | ((totLen & 0x00FF) << 8);
            if (verbose >= 2) { printf("modified tcp/ip payloadLen = %d\n", payloadLen + hmacLengthInBytes); }
            if (verbose >= 2) { printf("modified tcp/ip tot_len    = %d\n", ipPacketTotalLength); }
          }
          else {
            if (verbose >= 2) { printf("hashMatchCount = %d (bad)\n", hashMatchCount); }
            acceptPacket = 0;
            if (verbose >= 2) { printf("Setting acceptPacket = 0\n"); }
          }
        }
        else if ((indev == 0) && (outdev > 0)) { // we are sending a packet out
          char repBuff[SHA256_DIGEST_LENGTH + 1];
          memset(repBuff, '\0', SHA256_DIGEST_LENGTH + 1);

          // Fragment the packet if it would be too long with hmacLengthInBytes extra HMAC bytes in the payload
          unsigned short choppedLength = 0;
          if (ipPacketTotalLength > 1500 - hmacLengthInBytes) {
            choppedLength = ipPacketTotalLength - (1500 - hmacLengthInBytes);
            ipPacketTotalLength = 1500 - hmacLengthInBytes;
          }

          char *toHash = buildToHash(ipPacketTotalLength, ip, ihlOffset, 0, 1, 0);
          unsigned short ipPacketTotalLength2 = ipPacketTotalLength + hmacLengthInBytes;
          unsigned short totLen2 = ((ipPacketTotalLength2 & 0xFF00) >> 8) | ((ipPacketTotalLength2 & 0x00FF) << 8);
          toHash[2] =  totLen2 & 0x00FF;
          toHash[3] = (totLen2 & 0xFF00) >> 8;
          if (verbose >= 2) { hex_dump_bytes_to_hash(toHash, ipPacketTotalLength); }
          calc_sha256_hash_bytes(ipPacketTotalLength, (char *)toHash, hashAsBytes);
          free(toHash);
          if (verbose >= 2) { display_sha256_hash(hashAsBytes); }
          for (int i=0; i<hmacLengthInBytes; i++) {
            *((char *)(((void *)repBuff) + i)) = *((char *)(((void *)hashAsBytes) + i));
          }

          int mangleRetVal = nfq_tcp_mangle_ipv4(pkBuff, payloadLen - choppedLength, choppedLength, repBuff, hmacLengthInBytes);
          if (verbose >= 2) { printf("mangleRetVal = %d\n", mangleRetVal); }

          ip = (struct iphdr *)((unsigned long)nfq_ip_get_hdr(pkBuff));
          totLen = ip->tot_len;
          ipPacketTotalLength = ((totLen & 0xFF00) >> 8) | ((totLen & 0x00FF) << 8);
          if (verbose >= 2) { printf("modified tcp/ip payloadLen = %d\n", payloadLen + hmacLengthInBytes - choppedLength); }
          if (verbose >= 2) { printf("modified tcp/ip tot_len    = %d\n", ipPacketTotalLength); }

          if (verbose >= 2) {
            hex_dump_ip_packet(ip, ipPacketTotalLength, ihlOffset, dataOffset, "MODIFIED TCP/IP");
          }

          acceptPacket = 1;
        }
        else {
          printf("WARNING: Problem encountered while processing the TCP/IP packet: hook = %d, indev = %d, outdev = %d, tcp->syn = %d, tcp->ack = %d\n",
            hook, indev, outdev, tcp->syn, tcp->ack);
        }
      }
      else {
        if (indev > 0) {
          printf("WARNING: Processing the TCP/IP packet: There is no payload.  hook = %d, indev = %d, outdev = %d, tcp->syn = %d, tcp->ack = %d, tcp->fin = %d\n",
            hook, indev, outdev, tcp->syn, tcp->ack, tcp->fin);
        }
        else if ((indev == 0) && (outdev > 0)) { // we are sending a packet out
          char repBuff[SHA256_DIGEST_LENGTH + 1];
          memset(repBuff, '\0', SHA256_DIGEST_LENGTH + 1);

          char *toHash = buildToHash(ipPacketTotalLength, ip, ihlOffset, 0, 1, 0);
          unsigned short ipPacketTotalLength2 = ipPacketTotalLength + hmacLengthInBytes;
          unsigned short totLen2 = ((ipPacketTotalLength2 & 0xFF00) >> 8) | ((ipPacketTotalLength2 & 0x00FF) << 8);
          toHash[2] =  totLen2 & 0x00FF;
          toHash[3] = (totLen2 & 0xFF00) >> 8;
          if (verbose >= 2) { hex_dump_bytes_to_hash(toHash, ipPacketTotalLength); }
          calc_sha256_hash_bytes(ipPacketTotalLength, (char *)toHash, hashAsBytes);
          free(toHash);
          if (verbose >= 2) { display_sha256_hash(hashAsBytes); }
          for (int i=0; i<hmacLengthInBytes; i++) {
            *((char *)(((void *)repBuff) + i)) = *((char *)(((void *)hashAsBytes) + i));
          }

          int mangleRetVal = nfq_tcp_mangle_ipv4(pkBuff, 0, 0, repBuff, hmacLengthInBytes);
          if (verbose >= 2) { printf("mangleRetVal = %d\n", mangleRetVal); }

          ip = (struct iphdr *)((unsigned long)nfq_ip_get_hdr(pkBuff));
          totLen = ip->tot_len;
          ipPacketTotalLength = ((totLen & 0xFF00) >> 8) | ((totLen & 0x00FF) << 8);
          if (verbose >= 2) { printf("modified tcp/ip tot_len = %d\n", ipPacketTotalLength); }

          if (verbose >= 2) {
            hex_dump_ip_packet(ip, ipPacketTotalLength, ihlOffset, dataOffset, "MODIFIED TCP/IP");
          }

          acceptPacket = 1;
        }
        else {
          printf("WARNING: Problem encountered while processing the TCP/IP packet: hook = %d, indev = %d, outdev = %d, tcp->syn = %d, tcp->ack = %d, tcp->fin = %d\n",
            hook, indev, outdev, tcp->syn, tcp->ack, tcp->fin);
        }
      }
    }
    else {
      printf("WARNING: tcp (struct tcphdr) is NULL!\n");
    }
  }
  else if (ip->protocol == IPPROTO_UDP) {
    if (udp != NULL) {
      unsigned short udpLen = ((udp->len & 0xFF00) >> 8) | ((udp->len & 0x00FF) << 8);

      if (verbose >= 2) {
        printf("UDP Header: source  = %d\n", ((udp->source & 0xFF00) >> 8) | ((udp->source & 0x00FF) << 8));
        printf("UDP Header: dest    = %d\n", ((udp->dest   & 0xFF00) >> 8) | ((udp->dest   & 0x00FF) << 8));
        printf("UDP Header: len     = %d\n", udpLen);
        printf("UDP Header: check   = %d\n", udp->check);
        printf("UDP Header: checkES = %d\n", ((udp->check  & 0xFF00) >> 8) | ((udp->check  & 0x00FF) << 8));
      }

      void *payload = nfq_udp_get_payload(udp, pkBuff);
      unsigned int payloadLen = nfq_udp_get_payload_len(udp, pkBuff);
      payloadLen -= 4 * dataOffset;  // 8 bytes
      if (verbose >= 2) { printf("payloadLen = %d\n", payloadLen); }

      if ((outdev == 0) && (indev > 0)) {
        unsigned short udpLen2           = udpLen           - hmacLengthInBytes;
        unsigned short ipPacketTotalLength2 = ipPacketTotalLength - hmacLengthInBytes;
        udp->len    = ((udpLen2           & 0xFF00) >> 8) | ((udpLen2           & 0x00FF) << 8);
        ip->tot_len = ((ipPacketTotalLength2 & 0xFF00) >> 8) | ((ipPacketTotalLength2 & 0x00FF) << 8);

        unsigned short myChecksum = compute_udp_checksum(ip, udp, ipPacketTotalLength2);
        if (verbose >= 2) { printf("udp myChecksum           = %d\n", myChecksum); }
        udp->check = myChecksum;

        char *toHash = buildToHash(ipPacketTotalLength - hmacLengthInBytes, ip, ihlOffset, 0, 0, 1);
        toHash[24] = (udpLen2 & 0xFF00) >> 8;
        toHash[25] =  udpLen2 & 0x00FF;
        toHash[2]  = (ipPacketTotalLength & 0xFF00) >> 8;
        toHash[3]  =  ipPacketTotalLength & 0x00FF;
        if (verbose >= 2) { hex_dump_bytes_to_hash((char *)toHash, ipPacketTotalLength - hmacLengthInBytes); }
        calc_sha256_hash_bytes(ipPacketTotalLength - hmacLengthInBytes, (char *)toHash, hashAsBytes);
        free(toHash);
        if (verbose >= 2) { display_sha256_hash(hashAsBytes); }

        int hashMatchCount = 0;
        if (payloadLen >= hmacLengthInBytes) {
          int j = 0;
          for (int i=payloadLen-hmacLengthInBytes; i<payloadLen; i++) {
            unsigned char plChar = *((unsigned char *)(((void *)udp) + 8 + i));
            unsigned char hbChar = *((unsigned char *)(((void *)hashAsBytes) + j));
            if (verbose >= 2) { printf("j = %2d   plChar = %02x   hbChar = %02x\n", j, plChar, hbChar); }
            if (plChar == hbChar) {
              hashMatchCount++;
            }
            j++;
          }
        }
        if (hashMatchCount == hmacLengthInBytes) {
          if (verbose >= 2) { printf("hashMatchCount = %d (good)\n", hmacLengthInBytes); }
          acceptPacket = 1;
          if (verbose >= 2) { printf("Setting acceptPacket = 1\n"); }
        }
        else {
          printf("hashMatchCount = %d (bad)\n", hashMatchCount);
          acceptPacket = 0;
          printf("Setting acceptPacket = 0\n");
        }
      }
      else if ((indev == 0) && (outdev > 0)) {
        pktb_free(pkBuff);
        pkBuff = (struct pkt_buff *)((unsigned long)pktb_alloc(AF_INET, rawData, len + hmacLengthInBytes, 0x1000));
        ip = (struct iphdr *)((unsigned long)nfq_ip_get_hdr(pkBuff));
        nfq_ip_set_transport_header(pkBuff, ip);
        udp = (struct udphdr *)((unsigned long)nfq_udp_get_hdr(pkBuff));
        unsigned short udpLen2 = udpLen + hmacLengthInBytes;

        char *toHash = buildToHash(ipPacketTotalLength, ip, ihlOffset, 0, 0, 1);
        unsigned short ipPacketTotalLength2 = ipPacketTotalLength + hmacLengthInBytes;
        unsigned short totLen2 = ((ipPacketTotalLength2 & 0xFF00) >> 8) | ((ipPacketTotalLength2 & 0x00FF) << 8);
        toHash[2] =  totLen2 & 0x00FF;
        toHash[3] = (totLen2 & 0xFF00) >> 8;
        if (verbose >= 2) { hex_dump_bytes_to_hash(toHash, ipPacketTotalLength); }
        calc_sha256_hash_bytes(ipPacketTotalLength, (char *)toHash, hashAsBytes);
        free(toHash);
        if (verbose >= 2) { display_sha256_hash(hashAsBytes); }
        int j = 0;
        for (int i=ipPacketTotalLength; i<ipPacketTotalLength2; i++) {
          *((unsigned char *)(((void *)ip) + i)) = hashAsBytes[j];
          j++;
        }
        udp->len = ((udpLen2 & 0xFF00) >> 8) | ((udpLen2 & 0x00FF) << 8);

        if (verbose >= 2) {
          hex_dump_ip_packet(ip, ipPacketTotalLength2, ihlOffset, dataOffset, "MODIFIED UDP/IP");
        }

        unsigned short myChecksum = compute_udp_checksum(ip, udp, ipPacketTotalLength2);
        if (verbose >= 2) { printf("udp myChecksum           = %d\n", myChecksum); }
        udp->check = myChecksum;

        ip->tot_len = ((ipPacketTotalLength2 & 0xFF00) >> 8) | ((ipPacketTotalLength2 & 0x00FF) << 8);

        acceptPacket = 1;
      }
      else {
        printf("WARNING: Problem encountered while processing the UDP/IP packet: hook = %d, indev = %d, outdev = %d\n", hook, indev, outdev);
      }
    }
    else {
      printf("WARNING: udp (struct udphdr) is NULL\n");
    }
  }

  if (verbose >= 2) {
    hex_dump_ip_packet(ip, ipPacketTotalLength, ihlOffset, dataOffset, "IP");
  }

  nfq_ip_set_checksum(ip);
  if (verbose >= 2) { printf("checksum = %d\n", ip->check); }

  int retVal = 0;
  if (acceptPacket == 1) {
    if (verbose >= 1) { printf("Verdict = NF_ACCEPT\n"); }
    retVal = nfq_set_verdict(qh, id, NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    pktb_free(pkBuff);
  }
  else {
    if (verbose >= 1) { printf("Verdict = NF_DROP\n"); }
    retVal = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    pktb_free(pkBuff);
  }

  return retVal;
}

void parse_command_line_args(int argc, char** argv) {
  int c;

  while (1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    static struct option long_options[] = {
      {"wanmode",              no_argument,       0, 'w'},
      {"verbose",              required_argument, 0, 'v'},
      {"queuenumber",          required_argument, 0, 'q'},
      {"queue-number",         required_argument, 0, 'q'},
      {"hmacsecretfilename",   required_argument, 0, 'h'},
      {"hmac-secret-filename", required_argument, 0, 'h'},
      {"hmacbytes",            required_argument, 0, 'b'},
      {"hmac-bytes",           required_argument, 0, 'b'},
      {"hmaclengthinbytes",    required_argument, 0, 'b'},
      {"hmac-length-in-bytes", required_argument, 0, 'b'},
      {0,                      0,                 0,  0 }
    };

    c = getopt_long(argc, argv, "wv:q:h:b:", long_options, &option_index);

    if (c == -1) {
      break;
    }

    switch (c) {
      case 'w':
        wanMode = 1;
        break;

      case 'v':
        sscanf(optarg, "%u", &verbose);
        break;

      case 'q':
        sscanf(optarg, "%u", &queueNumber);
        break;

      case 'h':
        strncpy(hmacSecretFilename, optarg, 255);
        break;

      case 'b':
        sscanf(optarg, "%u", &hmacLengthInBytes);
        break;

      case '?':
        break;

      default:
        printf("?? getopt returned character code 0%o ??\n", c);
    }
  }

  if (optind < argc) {
    printf("non-option ARGV-elements: ");
    while (optind < argc) {
      printf("%s ", argv[optind++]);
    }
    printf("\n");
  }
}

int main(int argc, char **argv) {
  struct nfq_handle    *handle;
  struct nfq_q_handle  *queueHandle;
  int fileDescriptor;
  int retVal;
  char buf[4096] __attribute__ ((aligned));

  verbose            = 0;
  wanMode            = 0;
  queueNumber        = 0;
  hmacLengthInBytes  = 16;
  strcpy(hmacSecretFilename, "hmac_secret.txt");

  parse_command_line_args(argc, argv);

  if (verbose >= 1) {
    printf("########## BEGIN Command-Line Configuration ##########\n");
    printf("verbose            = %d\n", verbose);
    printf("wanMode            = %d\n", wanMode);
    printf("queueNumber        = %d\n", queueNumber);
    printf("hmacLengthInBytes  = %d\n", hmacLengthInBytes);
    printf("hmacSecretFilename = %s\n", hmacSecretFilename);
    printf("########## END   Command-Line Configuration ##########\n");
  }

  readHmacSecretFromFile();

  if (verbose >= 2) { printf("before nfq_open()\n"); }
  handle = nfq_open();
  if (verbose >= 2) { printf("after  nfq_open()\n"); }
  if (!handle) {
    fprintf(stderr, "failed nfq_open()\n");
    exit(1);
  }

  if (verbose >= 2) { printf("before nfq_unbind_pf(handle, AF_INET)\n"); }
  if (nfq_unbind_pf(handle, AF_INET) < 0) {
    fprintf(stderr, "failed nfq_unbind_pf(handle, AF_INET)\n");
    exit(1);
  }
  if (verbose >= 2) { printf("after  nfq_unbind_pf(handle, AF_INET)\n"); }

  if (verbose >= 2) { printf("before nfq_bind_pf(handle, AF_INET)\n"); }
  if (nfq_bind_pf(handle, AF_INET) < 0) {
    fprintf(stderr, "failed nfq_bind_pf(handle, AF_INET)\n");
    exit(1);
  }
  if (verbose >= 2) { printf("after  nfq_bind_pf(handle, AF_INET)\n"); }

  if (verbose >= 2) { printf("before nfq_create_queue(handle, 0, &processPacketCallback, NULL)\n"); }
  queueHandle = nfq_create_queue(handle, queueNumber, &processPacketCallback, NULL);
  if (verbose >= 2) { printf("after  nfq_create_queue(handle, 0, &processPacketCallback, NULL)\n"); }
  if (!queueHandle) {
    fprintf(stderr, "failed nfq_create_queue(handle, 0, &processPacketCallback, NULL)\n");
    exit(1);
  }

  if (verbose >= 2) { printf("before nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0xffff)\n"); }
  if (nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "failed nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0xffff)\n");
    exit(1);
  }
  if (verbose >= 2) { printf("after  nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0xffff)\n"); }

  if (verbose >= 2) { printf("before fileDescriptor = nfq_fd(handle)\n"); }
  fileDescriptor = nfq_fd(handle);
  if (verbose >= 2) { printf("after  fileDescriptor = nfq_fd(handle)\n"); }

  if (verbose >= 2) { printf("before while loop\n"); }
  while ((retVal = recv(fileDescriptor, buf, sizeof(buf), 0)) && retVal >= 0) {
    nfq_handle_packet(handle, buf, retVal);
  }
  if (verbose >= 2) { printf("after  while loop\n"); }

  if (verbose >= 2) { printf("before nfq_destroy_queue(queueHandle)\n"); }
  nfq_destroy_queue(queueHandle);
  if (verbose >= 2) { printf("after  nfq_destroy_queue(queueHandle)\n"); }

  if (verbose >= 2) { printf("before nfq_close(handle)\n"); }
  nfq_close(handle);
  if (verbose >= 2) { printf("after  nfq_close(handle)\n"); }

  exit(0);
}
